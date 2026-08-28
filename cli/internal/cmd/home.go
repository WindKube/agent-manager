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

// DirName is amctl's state root, relative to the invoking user's home:
// `~/.agent-manager`. plan.md's storage table puts both the per-hub
// installation record and the shared bundle cache under it.
const DirName = ".agent-manager"

// LockFileName is the per-home sync lock inside the state root. It is per HOME
// and not per hub because FR-038 refuses "concurrent syncs against the same
// home": two hubs can name the same package, and two syncs racing on one
// skills directory interleave whichever hubs they came from. See lock.go.
const LockFileName = "sync.lock"

// maxDirNameLen bounds a per-hub directory name. It is our own budget rather
// than a filesystem limit (255 bytes on ext4/APFS/NTFS): the name is
// prefix + "-" + 16 hex, so this is the readable prefix's ceiling plus the
// suffix, and it leaves room for a `.amctl-tmp-*` sibling of the record inside.
const maxDirNameLen = 64

// readablePrefixLen bounds the human-readable half of a per-hub directory name.
const readablePrefixLen = 32

// hubDigestLen is the number of hex characters of SHA-256 that carry hub
// identity in a directory name. 16 hex is 64 bits, which is what makes
// HubDirName injective in practice (see Hub and TestHubDirNamesAreInjective);
// the readable prefix carries no identity at all, because it is lossy by
// construction and two different hubs can and do share one.
const hubDigestLen = 16

// ErrHomeUnset marks a home directory the OS could not tell us about: the
// platform's home variable is unset or empty. FR-039 requires the refusal to
// name the variable, which is why homeEnvVar exists.
var ErrHomeUnset = errors.New("home directory is not set")

// ErrHomeUnwritable marks a home directory that exists but cannot hold amctl's
// state root.
var ErrHomeUnwritable = errors.New("home directory is not writable")

// ErrHubURL marks a hub URL amctl refuses to turn into an identity.
var ErrHubURL = errors.New("invalid hub URL")

// Home is a VALIDATED per-user state root. The only way to obtain one is
// ResolveHome, which has already proved the directory exists and accepts a
// write, so every consumer downstream of it — internal/cache, internal/record,
// lock.go — can take a path and skip the question.
//
// Consumers wire up like this, and this is the whole seam:
//
//	cache.Dir(home.Root)                 // ~/.agent-manager/cache
//	record.Path(home.HubDir(hub))        // ~/.agent-manager/<hub>/state.json
//	record.Load(recordPath, hub.URL)     // canonical URL, compared verbatim
type Home struct {
	// UserHome is the resolved OS home directory.
	UserHome string
	// Var is the environment variable that was actually consulted to find it.
	// On darwin and linux that is HOME; on Windows there is no HOME and
	// os.UserHomeDir reads USERPROFILE; on plan9 it is lowercase `home`. A
	// refusal naming HOME on Windows is a refusal nobody can act on, which is
	// why this is a field and not a constant.
	Var string
	// Root is <UserHome>/.agent-manager. It exists and is writable.
	Root string
}

// Hub is a hub's identity: the canonical URL string and the single path
// component derived from it. Both halves live here, in one type, because they
// are one decision — internal/record compares a stored hub URL to Hub.URL by
// exact string equality and deliberately never canonicalises, so a second
// opinion on either half would eventually produce two directories for one hub,
// or one directory for two.
type Hub struct {
	// URL is the canonical form. See ParseHub for what is normalised away.
	URL string
	// Dir is the directory name under Home.Root: a readable prefix plus a
	// truncated SHA-256 of URL. Never `..`, never absolute, never a Windows
	// device name; see validatePathComponent for the full refusal list.
	Dir string
}

// homeEnvVar names the environment variable os.UserHomeDir consults on this
// platform, so FR-039's refusal names something the user can actually set.
// Hand-derived from $GOROOT/src/os/file.go, which switches on runtime.GOOS
// exactly this way; it is a switch rather than a lookup of every variable
// because naming the wrong one is worse than naming none.
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

// ResolveHome resolves and validates amctl's state root.
//
// Validation is a REAL WRITE, not a mode-bit check. Mode bits lie: a read-only
// mount, an NFS export with root squashed, a POSIX ACL, an SELinux denial and a
// full filesystem all present as a directory whose owner has 0700, and a CLI
// that trusted the bits would discover the truth several network calls later.
// So this creates the state root and then creates and removes a probe file
// inside it.
//
// What it deliberately does NOT do:
//
//   - It does not create the user's home directory. An absent home is a broken
//     environment, not a state to repair; MkdirAll'ing one produces a home
//     nothing else on the machine agrees with. Only the single
//     `.agent-manager` component is created.
//   - It does not accept `~/.agent-manager` being an ABSOLUTE symlink, even one
//     pointing back inside the home. Everything here goes through os.Root,
//     whose openat-based resolution refuses any absolute symlink in the path
//     (measured on go1.26: "path escapes from parent"); a relative symlink that
//     stays inside the home is fine and works. This is the safe direction for
//     FR-020 and it is a genuine usability cost, so the refusal says so. Note
//     the asymmetry with the AGENT directories, which are frequently symlinks
//     into a dotfiles repo and are resolved rather than refused — that is
//     internal/apply's containment check on the resolved path, and this is
//     amctl's own state root, which has no such convention behind it.
//   - It does not consult XDG_CONFIG_HOME. R2 measured that Claude Code does
//     not read it for skills, and a state root that disagreed with the target
//     root about where "home" is would be worse than either choice alone.
func ResolveHome() (Home, error) {
	v := homeEnvVar()

	userHome, err := os.UserHomeDir()
	if err != nil {
		// os.UserHomeDir's own error text already names the variable, but it
		// names it as "$HOME" on every platform's message shape and we would
		// rather say it once, ourselves, in the sentence the user reads.
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

// probe creates the state root and proves it accepts a write.
func (h Home) probe() error {
	root, err := os.OpenRoot(h.UserHome)
	if err != nil {
		return Refusef("%w: %s points at %s, which could not be opened: %w", ErrHomeUnwritable, h.Var, h.UserHome, err)
	}
	defer func() { _ = root.Close() }()

	// 0700: the record names every path amctl may ever delete and the cache
	// holds bytes a later run trusts after re-hashing. Neither is another
	// user's business, and a group-writable cache is a way to hand amctl bytes
	// it will then extract.
	if mkErr := root.Mkdir(DirName, 0o700); mkErr != nil && !errors.Is(mkErr, fs.ErrExist) {
		return Refusef("%w: cannot create %s (%s=%s): %w%s",
			ErrHomeUnwritable, h.Root, h.Var, h.UserHome, mkErr, symlinkHint(mkErr))
	}

	// A fixed probe name rather than a random one: two amctl runs racing here
	// both want the same answer, and O_EXCL failing with EEXIST because the
	// other one is mid-probe is not evidence of an unwritable home. A random
	// name would also leave litter behind on a crash that a fixed name
	// overwrites next run.
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

// HubDir is the per-hub directory under the state root:
// `~/.agent-manager/<hub>`. It creates nothing — internal/record creates it on
// its first save, so a machine that has never synced has no empty directories
// claiming otherwise.
func (h Home) HubDir(hub Hub) string { return filepath.Join(h.Root, hub.Dir) }

// LockPath is the per-home sync lock's path. See lock.go.
func (h Home) LockPath() string { return filepath.Join(h.Root, LockFileName) }

// Prepare validates the state root and the hub's identity and ONLY THEN runs
// work. FR-039 requires both refusals before any network request, and this is
// how that ordering is made structural instead of remembered: work is the
// network half, it is an argument, and there is no path through this function
// that reaches it with an invalid home or an unparseable hub.
//
// Every verb that touches the network goes through here. A verb that needs no
// hub (`logout`, `status --offline` against a single hub) may call ResolveHome
// directly — it makes no request, so there is no ordering to get wrong — but a
// verb that dials must not, because then the ordering is back to being a thing
// somebody has to remember while editing.
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

// ParseHub turns a user-supplied hub URL into a canonical URL and a directory
// name.
//
// What counts as the SAME hub, decided here and nowhere else:
//
//   - A missing scheme means https. `hub.example.com` == `https://hub.example.com`,
//     because a bare host is what people type and the alternative is refusing
//     it. TLS is FR-041's business (internal/hub), not this function's; the
//     default being https rather than http is the same decision seen from here.
//   - The host is case-folded and a single trailing dot is dropped.
//     `HUB.example.com.` == `hub.example.com`: DNS is case-insensitive and the
//     root-anchored form names the same host.
//   - The scheme's default port is dropped, and any OTHER port is kept and is
//     part of identity. So `https://hub.example.com:8443/` is NOT the same hub
//     as `https://hub.example.com` — 8443 is a different listener, quite
//     possibly a different deployment, and merging them would apply one's
//     installation record to the other.
//   - The path is cleaned and a trailing slash dropped, so
//     `https://h/am/` == `https://h/am`. A non-empty path is KEPT and is part
//     of identity: a self-hosted hub behind a reverse proxy path prefix is a
//     hub, and two prefixes on one host are two hubs.
//   - The SCHEME is part of identity. `http://h` != `https://h`. They are
//     different security contexts, and quietly sharing a state root would let
//     a plaintext hub (reachable only with FR-041's explicit flag) inherit the
//     record of packages installed from the TLS one, which is a list of paths
//     amctl will delete on request.
//
// What is refused rather than normalised: userinfo (credentials do not belong
// in a directory name or in a string that gets logged), a query or fragment (a
// hub base URL has neither, and accepting them means two canonical forms for
// one hub), any scheme other than http/https, an opaque URL, a NUL or control
// character anywhere, and a host outside [a-z0-9._-] or a bracketed IPv6
// literal. The host charset check is what stops a percent-encoded `..`, a
// backslash and a stray `/` from ever reaching the directory name.
func ParseHub(raw string) (Hub, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Hub{}, Refusef("%w: --hub is empty", ErrHubURL)
	}
	if i := strings.IndexFunc(s, func(r rune) bool { return r == 0 || unicode.IsControl(r) }); i >= 0 {
		return Hub{}, Refusef("%w: %q contains a control character at byte %d", ErrHubURL, s, i)
	}
	if !hasScheme(s) {
		// A bare `hub.example.com` or `hub.example.com:8443` means https. See
		// hasScheme for why this is not a plain search for "://".
		s = "https://" + s
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
	// A backstop, not a formality. hubDirName is written so that its output
	// cannot be hostile — the prefix is whitelisted and the last character is
	// always hex — but the whole point of T023 is that this one function has a
	// blast radius, so the invariant is asserted rather than argued. If this
	// ever fires it is amctl's bug, not the user's, so it is NOT a refusal.
	if err := validatePathComponent(dir); err != nil {
		return Hub{}, fmt.Errorf("internal: derived an unusable directory name for %q: %w", canonical, err)
	}
	return Hub{URL: canonical, Dir: dir}, nil
}

// hasScheme reports whether s already carries a URL scheme.
//
// It is not a search for "://", because an OPAQUE URL (`https:hub.example.com`)
// has a scheme and no slashes, and prepending https to it produces
// `https://https:hub.example.com` — which fails with "invalid port" and reports
// a wrong reason for a real mistake.
//
// It is not a plain "is there a scheme token before the first colon" either:
// RFC 3986 lets a scheme contain dots, so `hub.example.com:8443` parses as
// scheme `hub.example.com` with opaque part `8443`, and the one form people
// actually type would be refused. The disambiguator is that a port is digits:
// a colon followed by a digit is a port on a bare host, anything else after a
// valid scheme token is a scheme.
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
		// url.Hostname strips the brackets from an IPv6 literal; put them back
		// so the canonical form re-parses, and validate the charset.
		host = strings.Trim(host, "[]")
		if !validIPv6Host(host) {
			return "", Refusef("%w: %q has an unusable IPv6 host %q", ErrHubURL, raw, host)
		}
		return "[" + host + "]", nil
	}
	// A single trailing dot is the root-anchored form of the same name; two is
	// not a name at all.
	host = strings.TrimSuffix(host, ".")
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
	// u.Path is already percent-decoded, which is exactly the point: a
	// `%2e%2e` in the raw URL is a `..` here, and gets refused below instead of
	// arriving intact.
	if strings.ContainsRune(u.Path, '\\') {
		return "", Refusef("%w: %q has a backslash in its path", ErrHubURL, raw)
	}
	// Walk the DECODED segments before path.Clean sees them. Clean turns
	// `/../..` into `/`, which is safe but silently reinterprets a malformed
	// hub URL as the root; refusing says what was wrong. depth going negative
	// is the escape, and it is the only thing `%2e%2e` can be trying to do.
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

// hubDirName derives the per-hub directory name from a canonical hub URL.
//
// It is `<readable prefix>-<16 hex of SHA-256(canonical)>`. The hash is what
// makes it injective and traversal-proof; the prefix is what makes
// `~/.agent-manager` readable, which is a real cost to give up when the
// directory holds the file a user may need to inspect or delete by hand. The
// prefix carries NO identity: it is lossy on purpose, two hubs may share one,
// and nothing may ever compare or parse it.
//
// Because the name always ends in a hex digit and the prefix is built from a
// whitelist, the result cannot be `.`, `..`, a Windows reserved device name, or
// a name ending in a dot or a space — the four collisions that are silent
// rather than loud. validatePathComponent asserts that rather than trusting it.
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
// of [a-z0-9-]. Everything else — including the scheme's punctuation, a colon
// (illegal in a filename on Windows and legal but awkward on darwin, where it
// is what the Finder shows as a path separator), a slash, a backslash and any
// non-ASCII rune — collapses to a single dash.
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

// windowsReservedNames are the DOS device names Windows still resolves in every
// directory. Creating `CON` there does not fail with a clear error; the open
// succeeds against the console device, which is why this is a real bug on a
// real platform rather than a curiosity. The set is deliberately a SUPERSET of
// the documented one (COM0/LPT0 and the CONIN$/CONOUT$ pair are included) —
// over-rejecting a name amctl never generates costs nothing, and the list is
// checked on every platform so a Linux test suite catches a Windows bug.
var windowsReservedNames = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"conin$": true, "conout$": true,
	"com0": true, "com1": true, "com2": true, "com3": true, "com4": true,
	"com5": true, "com6": true, "com7": true, "com8": true, "com9": true,
	"lpt0": true, "lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true,
	"lpt5": true, "lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// validatePathComponent refuses anything that is not a single, boring,
// portable directory name. It is exported to the package as the one place the
// refusal list lives, and it is checked on EVERY platform rather than behind a
// runtime.GOOS switch: a state root created on Linux gets read on Windows via
// a mounted home or a synced dotfiles repo, and a name that is only invalid
// over there is still a name amctl must not produce.
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
		// `/` is the separator everywhere; `\` and `:` are separators on
		// Windows, and `:` is legal on darwin, which is the trap — a name with
		// a colon works on the developer's Mac and produces an unopenable path
		// on a user's Windows box.
		case strings.ContainsRune(`/\:*?"<>|`, r):
			return fmt.Errorf("contains %q, which is not portable in a filename", r)
		case r >= utf8Max:
			return fmt.Errorf("contains non-ASCII %q", r)
		}
	}
	// Windows silently STRIPS a trailing dot or space when creating a file, so
	// `hub-a.` and `hub-a` become one directory over there. That is a
	// collision, not an error, and it is the collision this whole function
	// exists to make impossible: two hubs sharing a directory means one
	// machine's record applies to the other.
	if last := name[len(name)-1]; last == '.' || last == ' ' {
		return fmt.Errorf("ends in %q, which Windows strips", last)
	}
	base, _, _ := strings.Cut(name, ".")
	if windowsReservedNames[strings.ToLower(base)] {
		return fmt.Errorf("%q is a Windows device name", base)
	}
	return nil
}

// utf8Max is the first non-ASCII rune. Named so the check above reads as a
// statement about ASCII rather than as a magic number.
const utf8Max = 0x80
