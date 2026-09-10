// Package repourl parses a user-supplied repository reference into its
// parts. Nothing here touches the network: whether a host is reachable,
// public or a disguised loopback address is internal/fetch's problem; this
// package only decides whether a string names a repository at all.
package repourl

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// DefaultHost is assumed for a bare owner/repo reference.
const DefaultHost = "github.com"

// maxRawLen bounds the input before any parsing. A reference is echoed into
// provenance strings, audit rows and log lines, so an unbounded one is a
// log-flooding primitive rather than a paste.
const maxRawLen = 2048

// maxRefLen and maxSubdirLen bound the two values that can also arrive out of
// band through With, where maxRawLen never saw them.
const (
	maxRefLen    = 256
	maxSubdirLen = 1024
)

// ErrInvalid is the sentinel behind every rejection; the wrapped text names the
// rule that failed.
var ErrInvalid = errors.New("invalid repository reference")

var (
	// nameOK is the charset for an owner or a repository name. It is deliberately
	// wider than a GitHub login (self-hosted forges allow dots and underscores) and
	// still narrow enough that no segment can carry a path or a shell metacharacter.
	nameOK = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

	hostOK = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

	// portish tells `host:owner/repo` (scp-style) from `host:8443/owner/repo`.
	portish = regexp.MustCompile(`^\d+(/|$)`)
)

var allowedSchemes = map[string]bool{"http": true, "https": true, "ssh": true, "git": true}

// Repository is a parsed reference. The zero value is not a valid repository.
type Repository struct {
	// Host is the lowercased authority, including the port when one was given.
	Host string

	// Owner and Repo are lowercased. Forges treat them case-insensitively while this
	// hub keys package identity off them, so Owner/Repo and owner/repo must not be
	// able to become two catalog entries for the same source.
	Owner string
	Repo  string

	// Ref is a branch, tag or commit, empty when the reference named none. Case is
	// preserved: git refs are case-sensitive.
	Ref string

	// Subdir is a slash-separated path inside the repository, empty for the root.
	// Case is preserved: git tree paths are case-sensitive.
	Subdir string
}

// CloneURL renders the https clone target. Ref and Subdir are absent on purpose:
// they are arguments to a fetch, not part of the address.
func (r Repository) CloneURL() string {
	return "https://" + r.Host + "/" + r.Owner + "/" + r.Repo + ".git"
}

// String renders the reference the way provenance reads it back.
func (r Repository) String() string {
	s := r.Host + "/" + r.Owner + "/" + r.Repo
	if r.Ref != "" {
		s += "@" + r.Ref
	}
	if r.Subdir != "" {
		s += " (" + r.Subdir + ")"
	}
	return s
}

// Parse turns a user-supplied reference into a Repository.
//
// Accepted: a bare owner/repo, a bare host/owner/repo, an http, https, ssh or
// git URL, and the scp-style git@host:owner/repo, with a ref and a
// subdirectory riding along in the forge's own web path or in a ?ref= query.
// Nothing is silently repaired: a traversal component is rejected, never
// cleaned, since a cleaned value fetches something the user did not ask for.
func Parse(raw string) (Repository, error) {
	s := strings.TrimSpace(raw)
	switch {
	case s == "":
		return Repository{}, fmt.Errorf("%w: reference is empty", ErrInvalid)
	case len(s) > maxRawLen:
		return Repository{}, fmt.Errorf("%w: reference is %d bytes, over the %d byte limit", ErrInvalid, len(s), maxRawLen)
	case !utf8.ValidString(s):
		return Repository{}, fmt.Errorf("%w: reference is not valid utf-8", ErrInvalid)
	}
	// A control character in a reference reaches a log line, a header and a
	// provenance string before a human ever reads it. No legitimate shape has one.
	if i := strings.IndexFunc(s, isControl); i >= 0 {
		return Repository{}, fmt.Errorf("%w: reference contains a control character at byte %d", ErrInvalid, i)
	}

	u, err := parseURL(s)
	if err != nil {
		return Repository{}, err
	}

	host, err := hostOf(u)
	if err != nil {
		return Repository{}, err
	}

	segments := splitPath(u.Path)
	r, err := identity(u.Path, segments)
	if err != nil {
		return Repository{}, err
	}
	r.Host = host

	ref, subdir, err := parseTrailer(segments[2:])
	if err != nil {
		return Repository{}, err
	}

	// u.Query() silently drops pairs it cannot read, one of which may be the
	// ref, so an unreadable query is refused rather than half believed.
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Repository{}, fmt.Errorf("%w: query %q cannot be read: %w", ErrInvalid, u.RawQuery, err)
	}
	refs := query["ref"]
	for _, other := range refs {
		// Get would silently take the first of "?ref=a&ref=v2" — the same
		// contradiction the path-versus-query rule below refuses.
		if other != refs[0] {
			return Repository{}, fmt.Errorf("%w: query names both ref %q and %q", ErrInvalid, refs[0], other)
		}
	}
	if q := query.Get("ref"); q != "" {
		// Two refs in one reference is a contradiction, and quietly preferring one
		// would publish bytes from a version the user did not paste.
		if ref != "" && ref != q {
			return Repository{}, fmt.Errorf("%w: path names ref %q but the query names %q", ErrInvalid, ref, q)
		}
		ref = q
	}

	if refErr := validateRef(ref); refErr != nil {
		return Repository{}, refErr
	}
	subdir, err = validateSubdir(subdir)
	if err != nil {
		return Repository{}, err
	}
	r.Ref, r.Subdir = ref, subdir
	return r, nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// controlFree rejects what Parse's raw-input guard cannot see: that guard
// runs before percent-decoding, so "%0a" only becomes a newline once it is a
// query value or path segment, and a value supplied through With never
// passed that guard at all.
func controlFree(kind, v string) error {
	if !utf8.ValidString(v) {
		return fmt.Errorf("%w: %s is not valid utf-8", ErrInvalid, kind)
	}
	if i := strings.IndexFunc(v, isControl); i >= 0 {
		return fmt.Errorf("%w: %s %q contains a control character at byte %d", ErrInvalid, kind, v, i)
	}
	return nil
}

// identity reads the two segments that carry package identity. They are checked
// before the optional trailer because a traversal component here is the more
// specific failure.
func identity(path string, segments []string) (Repository, error) {
	if len(segments) < 2 {
		return Repository{}, fmt.Errorf("%w: %q names no owner and repository", ErrInvalid, path)
	}
	r := Repository{
		Owner: strings.ToLower(segments[0]),
		// The .git suffix is trimmed after lowering: no repository is named ".GIT",
		// so a case-sensitive trim would only leave the suffix in the identity.
		Repo: strings.TrimSuffix(strings.ToLower(segments[1]), ".git"),
	}
	if err := validateName("owner", r.Owner); err != nil {
		return Repository{}, err
	}
	if err := validateName("repository", r.Repo); err != nil {
		return Repository{}, err
	}
	return r, nil
}

// With overlays a ref and a subdirectory supplied out of band — the form
// fields next to the URL box. Precedence is explicit-wins: a caller who
// typed a ref meant it, whatever the pasted URL happened to carry. An empty
// argument means "not supplied" and leaves the parsed value alone.
func (r Repository) With(ref, subdir string) (Repository, error) {
	if ref != "" {
		if err := validateRef(ref); err != nil {
			return Repository{}, err
		}
		r.Ref = ref
	}
	if subdir != "" {
		clean, err := validateSubdir(subdir)
		if err != nil {
			return Repository{}, err
		}
		r.Subdir = clean
	}
	return r, nil
}

// ParseWith is Parse followed by With, for the common registration path where the
// URL and the two fields arrive together.
func ParseWith(raw, ref, subdir string) (Repository, error) {
	r, err := Parse(raw)
	if err != nil {
		return Repository{}, err
	}
	return r.With(ref, subdir)
}

// parseURL normalises the shapes url.Parse cannot read on its own, then enforces
// the scheme allowlist.
func parseURL(s string) (*url.URL, error) {
	switch scp := scpTarget(s); {
	case scp != "":
		s = scp
	case strings.Contains(s, "://"):
		// already a URL
	case hasScheme(s):
		// something like file:/etc/passwd — leave it for the allowlist to refuse.
	default:
		s = "https://" + withHost(s)
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if !allowedSchemes[u.Scheme] {
		return nil, fmt.Errorf("%w: scheme %q is not one of http, https, ssh, git", ErrInvalid, u.Scheme)
	}
	if u.User != nil {
		// A username is normal (git@host). A password is a credential, and this
		// reference is persisted in provenance and audit rows, so we refuse to
		// store the secret rather than log a redacted copy of it.
		if _, set := u.User.Password(); set {
			return nil, fmt.Errorf("%w: reference embeds a credential", ErrInvalid)
		}
	}
	return u, nil
}

// scpTarget rewrites git@host:owner/repo into an ssh URL, returning "" when s is
// not that shape.
func scpTarget(s string) string {
	if strings.Contains(s, "://") {
		return ""
	}
	colon := strings.IndexByte(s, ':')
	if colon <= 0 {
		return ""
	}
	if slash := strings.IndexByte(s, '/'); slash >= 0 && slash < colon {
		return ""
	}
	authority, path := s[:colon], s[colon+1:]
	if path == "" || strings.HasPrefix(path, "/") || portish.MatchString(path) {
		return ""
	}
	// Require evidence that the left side really is a host: an explicit user@, or a
	// dotted name. Without this, "file:etc/passwd" would parse as a host named file.
	if !strings.Contains(authority, "@") && !strings.Contains(authority, ".") {
		return ""
	}
	return "ssh://" + authority + "/" + path
}

func hasScheme(s string) bool {
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return false
	}
	for j, c := range s[:i] {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case j > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// withHost prefixes DefaultHost when a bare reference starts with an owner rather
// than a host. A first segment carrying a dot or a port is a host; no forge allows
// a dot in an owner, so the two shapes never collide.
func withHost(s string) string {
	s = strings.TrimLeft(s, "/")
	first, _, _ := strings.Cut(s, "/")
	if strings.ContainsAny(first, ".:") {
		return s
	}
	return DefaultHost + "/" + s
}

func hostOf(u *url.URL) (string, error) {
	host := strings.ToLower(u.Hostname())
	// www.github.com and github.com are the same forge; keeping both labels would
	// key two identities off one repository.
	host = strings.TrimPrefix(host, "www.")
	if host == "" {
		return "", fmt.Errorf("%w: reference names no host", ErrInvalid)
	}
	if !hostOK.MatchString(host) {
		return "", fmt.Errorf("%w: %q is not a hostname", ErrInvalid, host)
	}
	if port := u.Port(); port != "" {
		host += ":" + port
	}
	return host, nil
}

func splitPath(p string) []string {
	out := make([]string, 0, 4)
	for _, seg := range strings.Split(p, "/") {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// parseTrailer reads what a forge's web UI puts after owner/repo:
// [-/]{tree,blob,raw,src}/<ref>[/<subdir>...]. Anything else is refused rather
// than guessed at.
func parseTrailer(rest []string) (ref, subdir string, err error) {
	if len(rest) == 0 {
		return "", "", nil
	}
	if rest[0] == "-" { // gitlab's /-/tree/... separator
		rest = rest[1:]
	}
	kind := ""
	if len(rest) > 0 {
		kind = rest[0]
	}
	switch kind {
	case "tree", "blob", "raw", "src":
	default:
		return "", "", fmt.Errorf("%w: unexpected path %q after owner/repo, want tree/<ref>[/<subdir>]",
			ErrInvalid, strings.Join(rest, "/"))
	}
	if len(rest) < 2 {
		return "", "", fmt.Errorf("%w: %q names no ref", ErrInvalid, strings.Join(rest, "/"))
	}
	// A ref containing a slash (release/1.2) is indistinguishable from a ref plus a
	// subdirectory without asking the remote, so the first segment is the ref.
	return rest[1], strings.Join(rest[2:], "/"), nil
}

func validateName(kind, v string) error {
	if v == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalid, kind)
	}
	// ".", ".." and any name embedding "..": rejecting the whole class is cheaper than
	// arguing about which of them a later path join would survive.
	if strings.Trim(v, ".") == "" || strings.Contains(v, "..") {
		return fmt.Errorf("%w: %s %q contains a path traversal component", ErrInvalid, kind, v)
	}
	if !nameOK.MatchString(v) {
		return fmt.Errorf("%w: %s %q contains a character outside [A-Za-z0-9._-]", ErrInvalid, kind, v)
	}
	return nil
}

// validateRef applies git check-ref-format's rules that matter to us.
func validateRef(ref string) error {
	if ref == "" {
		return nil
	}
	if len(ref) > maxRefLen {
		return fmt.Errorf("%w: ref is %d bytes, over the %d byte limit", ErrInvalid, len(ref), maxRefLen)
	}
	if err := controlFree("ref", ref); err != nil {
		return err
	}
	// A ref beginning with "-" is swallowed as an option by any argv-based git the
	// reference is later handed to; rejecting it here costs nothing.
	if strings.HasPrefix(ref, "-") || strings.HasPrefix(ref, "/") {
		return fmt.Errorf("%w: ref %q starts with %q", ErrInvalid, ref, ref[:1])
	}
	if strings.Contains(ref, "..") {
		return fmt.Errorf("%w: ref %q contains %q", ErrInvalid, ref, "..")
	}
	if strings.ContainsAny(ref, " ~^:?*[\\") || strings.Contains(ref, "@{") {
		return fmt.Errorf("%w: ref %q contains a character git forbids", ErrInvalid, ref)
	}
	if strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".") || strings.HasSuffix(ref, ".lock") {
		return fmt.Errorf("%w: ref %q ends with a sequence git forbids", ErrInvalid, ref)
	}
	return nil
}

// validateSubdir returns the subdirectory with its separators normalised. A
// segment that would climb out of the repository is an error: the alternative,
// path.Clean, resolves "a/../../etc" to a location the user never named.
func validateSubdir(subdir string) (string, error) {
	if subdir == "" {
		return "", nil
	}
	if len(subdir) > maxSubdirLen {
		return "", fmt.Errorf("%w: subdirectory is %d bytes, over the %d byte limit", ErrInvalid, len(subdir), maxSubdirLen)
	}
	if err := controlFree("subdirectory", subdir); err != nil {
		return "", err
	}
	if strings.HasPrefix(subdir, "/") {
		return "", fmt.Errorf("%w: subdirectory %q is absolute", ErrInvalid, subdir)
	}
	if strings.Contains(subdir, "..") {
		return "", fmt.Errorf("%w: subdirectory %q escapes the repository", ErrInvalid, subdir)
	}
	segments := splitPath(subdir)
	for _, seg := range segments {
		if strings.Trim(seg, ".") == "" {
			return "", fmt.Errorf("%w: subdirectory %q contains a relative component %q", ErrInvalid, subdir, seg)
		}
	}
	if len(segments) == 0 {
		return "", fmt.Errorf("%w: subdirectory %q names no path", ErrInvalid, subdir)
	}
	return strings.Join(segments, "/"), nil
}
