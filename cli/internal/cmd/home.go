package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode"
)

// DirName is amctl's state root, relative to the user's home: `~/.agent-manager`.
const DirName = ".agent-manager"

// LockFileName is per home, not per hub: two hubs can name the same package,
// and two syncs racing on one skills directory interleave regardless.
const LockFileName = "sync.lock"

// maxDirNameLen is our own budget for a per-hub directory name (not the
// filesystem's 255-byte limit): prefix + "-" + 16 hex, with room to spare
// for a `.amctl-tmp-*` sibling.
const maxDirNameLen = 64

const readablePrefixLen = 32

// hubDigestLen (64 bits of hex) is what makes hubDirName injective in
// practice; the readable prefix carries no identity and is lossy on purpose.
const hubDigestLen = 16

// ErrHomeUnset marks a home directory the OS could not tell us about.
var ErrHomeUnset = errors.New("home directory is not set")

// ErrHomeUnwritable marks a home directory that exists but can't hold amctl's state.
var ErrHomeUnwritable = errors.New("home directory is not writable")

// ErrHubURL marks a hub URL amctl refuses to turn into an identity.
var ErrHubURL = errors.New("invalid hub URL")

// Home is a validated per-user state root; the only way to obtain one is
// ResolveHome, so every downstream consumer (internal/cache, internal/record,
// lock.go) can take a path and skip the question.
type Home struct {
	UserHome string
	Var      string // env var actually consulted, so a refusal names something the user can act on
	Root     string // <UserHome>/.agent-manager; exists and is writable
}

// Hub is a hub's identity, kept as URL+Dir together: internal/record compares
// URL by exact string equality and never canonicalises.
type Hub struct {
	URL string // canonical form; see ParseHub
	Dir string // readable prefix + truncated SHA-256(URL); see validatePathComponent
}

// homeEnvVar names the variable os.UserHomeDir consults, so a refusal names
// something the user can actually set.
func homeEnvVar() string { return homeEnvVarFor(runtime.GOOS) }

func homeEnvVarFor(goos string) string {
	switch goos {
	case "windows":
		return "USERPROFILE"
	case "plan9":
		return "home"
	default:
		return "HOME"
	}
}

// ResolveHome resolves and validates amctl's state root by a REAL WRITE, not
// a mode-bit check: an NFS root-squash, an ACL or SELinux denial all present
// as an 0700 directory, so this creates the root and then a probe file
// inside it. It never creates the user's home itself (an absent home is a
// broken environment, not ours to repair), and it refuses `.agent-manager`
// being an absolute symlink — os.Root's openat resolution won't follow one.
func ResolveHome() (Home, error) {
	v := homeEnvVar()

	userHome, err := os.UserHomeDir()
	if err != nil {
		// Said here, not from os.UserHomeDir's own error, which always spells it "$HOME".
		return Home{}, Refusef("%w: %s is unset or empty; set it to the directory amctl should keep its state in", ErrHomeUnset, v)
	}
	if !filepath.IsAbs(userHome) {
		return Home{}, Refusef("%w: %s is %q, which is not an absolute path", ErrHomeUnset, v, userHome)
	}

	info, err := os.Stat(userHome)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Home{}, Refusef("%w: %s points at %s, which does not exist", ErrHomeUnset, v, userHome)
	case err != nil:
		return Home{}, Refusef("%w: %s points at %s, which could not be read: %w", ErrHomeUnwritable, v, userHome, err)
	case !info.IsDir():
		return Home{}, Refusef("%w: %s points at %s, which is not a directory", ErrHomeUnset, v, userHome)
	}

	home := Home{UserHome: userHome, Var: v, Root: filepath.Join(userHome, DirName)}
	if err := home.probe(); err != nil {
		return Home{}, err
	}
	return home, nil
}

func (h Home) probe() error { // creates the state root, proves it accepts a write
	root, err := os.OpenRoot(h.UserHome)
	if err != nil {
		return Refusef("%w: %s points at %s, which could not be opened: %w", ErrHomeUnwritable, h.Var, h.UserHome, err)
	}
	defer func() { _ = root.Close() }()

	// 0700: neither the record nor the cache is another user's business, and
	// a group-writable cache is a way to hand amctl bytes it will then extract.
	if mkErr := root.Mkdir(DirName, 0o700); mkErr != nil && !errors.Is(mkErr, fs.ErrExist) {
		return Refusef("%w: cannot create %s (%s=%s): %w%s",
			ErrHomeUnwritable, h.Root, h.Var, h.UserHome, mkErr, symlinkHint(mkErr))
	}

	// Fixed name, not random: two racing amctl runs want the same answer, and
	// a fixed name overwrites crash litter instead of accumulating it.
	probe := DirName + "/.amctl-write-probe"
	f, err := root.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return Refusef("%w: cannot write inside %s (%s=%s): %w%s",
			ErrHomeUnwritable, h.Root, h.Var, h.UserHome, err, symlinkHint(err))
	}
	closeErr := f.Close()
	_ = root.Remove(probe)
	if closeErr != nil {
		return Refusef("%w: cannot write inside %s (%s=%s): %w",
			ErrHomeUnwritable, h.Root, h.Var, h.UserHome, closeErr)
	}
	return nil
}

// symlinkHint turns os.Root's opaque "path escapes from parent" into the one
// fix that works, because nothing about that message suggests a symlink.
func symlinkHint(err error) string {
	if err == nil || !strings.Contains(err.Error(), "escapes from parent") {
		return ""
	}
	return fmt.Sprintf("; %s is reached through an absolute symlink, which amctl refuses"+
		" — make the link relative to the home directory, or point %s at the real location",
		DirName, homeEnvVar())
}

// HubDir creates nothing; internal/record creates it on first save, so a
// never-synced machine has no empty directories claiming otherwise.
func (h Home) HubDir(hub Hub) string { return filepath.Join(h.Root, hub.Dir) }

// LockPath: see lock.go.
func (h Home) LockPath() string { return filepath.Join(h.Root, LockFileName) }

// Prepare validates the state root and the hub's identity before running
// work, structurally rather than by convention: work is the network half,
// and there's no path through this function that reaches it with an invalid
// home or an unparseable hub. Every verb that touches the network must go
// through here.
func Prepare(hubURL string, work func(Home, Hub) error) error {
	home, err := ResolveHome()
	if err != nil {
		return err
	}
	hub, err := ParseHub(hubURL)
	if err != nil {
		return err
	}
	return work(home, hub)
}

// ParseHub turns a user-supplied hub URL into a canonical URL and directory
// name. Missing scheme means https, host is case-folded, default port and a
// trailing slash are dropped — but scheme, a non-default port and a
// non-empty path all stay part of identity: two hubs differing only in
// those are NOT merged. Userinfo, a query/fragment, non-http(s) schemes and
// any control char or non-[a-z0-9._-] host byte are refused, not normalised.
func ParseHub(raw string) (Hub, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Hub{}, Refusef("%w: --hub is empty", ErrHubURL)
	}
	if i := strings.IndexFunc(s, func(r rune) bool { return r == 0 || unicode.IsControl(r) }); i >= 0 {
		return Hub{}, Refusef("%w: %q contains a control character at byte %d", ErrHubURL, s, i)
	}
	if !hasScheme(s) {
		s = "https://" + s // a bare `hub.example.com[:port]` means https
	}

	u, err := url.Parse(s)
	if err != nil {
		return Hub{}, Refusef("%w: %q: %w", ErrHubURL, raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return Hub{}, Refusef("%w: %q has scheme %q; amctl speaks http and https", ErrHubURL, raw, u.Scheme)
	}
	if u.Opaque != "" {
		return Hub{}, Refusef("%w: %q is not a hierarchical URL; write it as https://host[:port][/path]", ErrHubURL, raw)
	}
	if u.User != nil {
		return Hub{}, Refusef("%w: %q carries credentials in the URL; amctl authenticates with `amctl login`", ErrHubURL, raw)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return Hub{}, Refusef("%w: %q has a query string; a hub base URL has none", ErrHubURL, raw)
	}
	if u.Fragment != "" {
		return Hub{}, Refusef("%w: %q has a fragment; a hub base URL has none", ErrHubURL, raw)
	}

	host, err := canonicalHost(u, raw)
	if err != nil {
		return Hub{}, err
	}
	port, err := canonicalPort(u, scheme, raw)
	if err != nil {
		return Hub{}, err
	}
	p, err := canonicalPath(u, raw)
	if err != nil {
		return Hub{}, err
	}

	canonical := scheme + "://" + host + port + p
	dir := hubDirName(canonical)
	// A backstop, not a formality: this function has a blast radius, so the
	// invariant is asserted rather than argued. Firing means amctl's own bug.
	if err := validatePathComponent(dir); err != nil {
		return Hub{}, fmt.Errorf("internal: derived an unusable directory name for %q: %w", canonical, err)
	}
	return Hub{URL: canonical, Dir: dir}, nil
}

// hasScheme reports whether s already carries a URL scheme. Not a search for
// "://" (an opaque URL like `https:hub.example.com` has none) and not "a
// scheme token before the first colon" either, since RFC 3986 lets a scheme
// contain dots and `hub.example.com:8443` would parse as one. The
// disambiguator: a colon followed by a digit is a port on a bare host,
// anything else after a valid scheme token is a real scheme.
func hasScheme(s string) bool {
	if strings.Contains(s, "://") {
		return true
	}
	i := strings.Index(s, ":")
	if i <= 0 || i == len(s)-1 {
		return false
	}
	for j := 0; j < i; j++ {
		c := s[j]
		alpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if j == 0 && !alpha {
			return false
		}
		if !alpha && (c < '0' || c > '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return s[i+1] < '0' || s[i+1] > '9'
}

func canonicalHost(u *url.URL, raw string) (string, error) {
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", Refusef("%w: %q has no host", ErrHubURL, raw)
	}
	if strings.HasPrefix(host, "[") || strings.Contains(host, ":") {
		host = strings.Trim(host, "[]") // url.Hostname stripped these; put back so it re-parses
		if !validIPv6Host(host) {
			return "", Refusef("%w: %q has an unusable IPv6 host %q", ErrHubURL, raw, host)
		}
		return "[" + host + "]", nil
	}
	host = strings.TrimSuffix(host, ".") // one trailing dot is the root-anchored form
	if host == "" || strings.HasSuffix(host, ".") {
		return "", Refusef("%w: %q has an unusable host", ErrHubURL, raw)
	}
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return "", Refusef("%w: %q has %q in its host, which amctl refuses", ErrHubURL, raw, r)
	}
	if strings.Contains(host, "..") {
		return "", Refusef("%w: %q has an empty label in its host", ErrHubURL, raw)
	}
	return host, nil
}

func validIPv6Host(host string) bool {
	if host == "" {
		return false
	}
	for _, r := range host {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || r == ':' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func canonicalPort(u *url.URL, scheme, raw string) (string, error) {
	p := u.Port()
	if p == "" {
		return "", nil
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", Refusef("%w: %q has port %q, which is not a port number", ErrHubURL, raw, p)
	}
	if (scheme == "https" && n == 443) || (scheme == "http" && n == 80) {
		return "", nil
	}
	return ":" + strconv.Itoa(n), nil
}

func canonicalPath(u *url.URL, raw string) (string, error) {
	// u.Path is already percent-decoded, so a `%2e%2e` in the raw URL is a
	// `..` here and gets refused below rather than arriving intact.
	if strings.ContainsRune(u.Path, '\\') {
		return "", Refusef("%w: %q has a backslash in its path", ErrHubURL, raw)
	}
	// Walk decoded segments before path.Clean sees them: Clean would silently
	// turn a malformed `/../..` into `/` instead of refusing it.
	depth := 0
	for _, seg := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		switch seg {
		case "", ".":
		case "..":
			depth--
			if depth < 0 {
				return "", Refusef("%w: %q escapes its own base path", ErrHubURL, raw)
			}
		default:
			depth++
		}
	}
	p := path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	if p == "/" {
		return "", nil
	}
	return p, nil
}

// hubDirName is `<readable prefix>-<16 hex of SHA-256(canonical)>`: the hash
// makes it injective and traversal-proof, and the prefix carries no
// identity — it's lossy on purpose, and nothing may ever compare or parse
// it. validatePathComponent still asserts the result can't collide with
// `.`, `..`, a reserved device name, or a trailing dot/space.
func hubDirName(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	suffix := hex.EncodeToString(sum[:])[:hubDigestLen]
	prefix := readablePrefix(canonical)
	if prefix == "" {
		prefix = "hub"
	}
	return prefix + "-" + suffix
}

// readablePrefix maps a canonical URL to at most readablePrefixLen characters
// of [a-z0-9-]; everything else collapses to a single dash.
func readablePrefix(canonical string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(canonical, "https://"), "http://")
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if !ok {
			dash = b.Len() > 0
			continue
		}
		if dash {
			b.WriteByte('-')
			dash = false
		}
		if b.Len() >= readablePrefixLen {
			break
		}
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), "-")
}

// reservedDeviceNames are the DOS device names, refused even off Windows
// since a home directory is routinely synced across machines. Deliberately a
// superset of the documented list: over-rejecting a name amctl never
// generates costs nothing.
var reservedDeviceNames = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"conin$": true, "conout$": true,
	"com0": true, "com1": true, "com2": true, "com3": true, "com4": true,
	"com5": true, "com6": true, "com7": true, "com8": true, "com9": true,
	"lpt0": true, "lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true,
	"lpt5": true, "lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// validatePathComponent refuses anything that is not a single, boring,
// portable directory name, checked unconditionally (no runtime.GOOS switch)
// since a state root is routinely synced between machines.
func validatePathComponent(name string) error {
	switch {
	case name == "":
		return errors.New("empty")
	case name == "." || name == "..":
		return fmt.Errorf("%q is a relative directory reference", name)
	case len(name) > maxDirNameLen:
		return fmt.Errorf("%d bytes long, over the %d-byte budget", len(name), maxDirNameLen)
	}
	for _, r := range name {
		switch {
		case r == 0:
			return errors.New("contains a NUL")
		case unicode.IsControl(r):
			return fmt.Errorf("contains control character %q", r)
		// `:` is legal on darwin but a separator elsewhere — the trap.
		case strings.ContainsRune(`/\:*?"<>|`, r):
			return fmt.Errorf("contains %q, which is not portable in a filename", r)
		case r >= utf8Max:
			return fmt.Errorf("contains non-ASCII %q", r)
		}
	}
	// Some filesystems silently strip a trailing dot/space, colliding `hub-a.`
	// with `hub-a` — the exact collision this function exists to prevent.
	if last := name[len(name)-1]; last == '.' || last == ' ' {
		return fmt.Errorf("ends in %q, which some filesystems strip", last)
	}
	base, _, _ := strings.Cut(name, ".")
	if reservedDeviceNames[strings.ToLower(base)] {
		return fmt.Errorf("%q is a reserved device name", base)
	}
	return nil
}

const utf8Max = 0x80 // first non-ASCII rune
