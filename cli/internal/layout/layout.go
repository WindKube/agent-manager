// Package layout turns a lockfile entry into the paths one agent reads. It is
// pure: strings in, paths out, so a destination's containment check can run
// before anything is opened.
//
// It does not read the environment: CLAUDE_CONFIG_DIR arrives as a Config
// field, since internal/cmd owns home and environment resolution. It does not
// check that a destination is inside the user's home; that check must run on
// the resolved path at the moment of writing, in internal/apply, because
// agent directories are frequently symlinks and a path inside the home as a
// string may not be as an inode. It does not sanitise: every unusable name is
// refused, naming the id and the reason, since a name amctl quietly rewrote
// would not match the record it later prunes against. It does not install
// plugins for any target (see Request.Kind), and it does not resolve or
// compare versions; Version is carried verbatim into the marker.
package layout

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// ErrPackageID marks a lockfile entry id that cannot become a directory name.
// Refusing here is the early gate, before any bytes reach disk.
var ErrPackageID = errors.New("unusable package id")

// ErrDirName marks a skill directory name that must never be written.
var ErrDirName = errors.New("unusable skill directory name")

// ErrKindUnsupported marks a lockfile entry kind amctl cannot install.
var ErrKindUnsupported = errors.New("entry kind not installable")

const (
	// DirSeparator joins the namespace and the name in a skill directory
	// name: `acme/code-review` installs to `acme--code-review`. claude-code
	// keys a skill by its directory name, not the `name:` in its frontmatter,
	// so the directory name is the user-visible identity and namespacing it
	// always (not only on collision) avoids renaming an already-installed
	// directory when an unrelated package appears. A single-character
	// separator cannot work: both segments may contain `-`, `.`, `_` and `+`,
	// so `acme-code/review` and `acme/code-review` would collide on one
	// directory. `--` is refused inside a segment (see validateIDSegment),
	// making the first occurrence unambiguously the separator. It stays
	// inside the lowercase-alphanumeric-and-hyphen alphabet the Agent Skills
	// format expects, unlike `@` (claude-code's own plugin syntax) or `:` (a
	// path separator to too many tools).
	DirSeparator = "--"

	// StagingDirName is the extraction staging directory, a sibling of the
	// destination: agent directories are often symlinks onto another mount,
	// and same-filesystem staging is what makes install a rename at all.
	StagingDirName = ".amctl-staging"

	// MaxDirNameBytes is the strictest limit among the supported filesystems
	// (ext4 255 bytes, APFS 255 characters), applied everywhere so one record
	// stays readable on every platform.
	MaxDirNameBytes = 255

	// MarkerSchemaVersion is the version of the marker format this build writes
	// and the only one it reads.
	MarkerSchemaVersion = 1
)

// Package is a lockfile entry id split into its two segments. The first
// segment is the namespace, not the publisher slug: a publisher slug is
// itself two segments (`example/platform`) whose first is the namespace. An
// id built from the slug would produce a three-segment bundle URL where the
// contract expects two.
type Package struct {
	Namespace string
	Name      string
}

// ID is the lockfile spelling, `namespace/name`.
func (p Package) ID() string { return p.Namespace + "/" + p.Name }

// ParsePackageID splits a lockfile entry id and refuses everything that
// cannot safely become one directory name. An id that is not exactly two
// non-empty segments is an error, never repaired: a repaired id would
// address a different package than the one the lockfile named.
func ParsePackageID(id string) (Package, error) {
	ns, name, ok := strings.Cut(id, "/")
	switch {
	case !ok:
		return Package{}, fmt.Errorf("%w: %q has one segment, want exactly two (namespace/name)", ErrPackageID, id)
	case ns == "" || name == "":
		return Package{}, fmt.Errorf("%w: %q has an empty segment, want exactly two non-empty segments (namespace/name)", ErrPackageID, id)
	case strings.Contains(name, "/"):
		return Package{}, fmt.Errorf("%w: %q has more than two segments, want exactly two (namespace/name)", ErrPackageID, id)
	}
	if err := validateIDSegment(id, "namespace", ns); err != nil {
		return Package{}, err
	}
	if err := validateIDSegment(id, "name", name); err != nil {
		return Package{}, err
	}
	return Package{Namespace: ns, Name: name}, nil
}

// DirName is the directory this package installs to under any target's skills
// root — the user-visible identity of the skill. It is only meaningful for a
// Package that came from ParsePackageID.
func (p Package) DirName() string { return p.Namespace + DirSeparator + p.Name }

// idSegmentAllowed reports whether r may appear after the first character of
// an id segment. Hand-derived from the hub's own object-key segment pattern,
// `^[A-Za-z0-9][A-Za-z0-9._+-]*$`, restated rather than imported since the hub
// is a separate module. Refusing every filename-awkward character everywhere,
// not only where a given filesystem requires it, keeps a profile's install
// behaviour the same across platforms.
func idSegmentAllowed(r rune) bool {
	return isAlnum(r) || r == '.' || r == '_' || r == '+' || r == '-'
}

func isAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func validateIDSegment(id, what, seg string) error {
	for i, r := range seg {
		// This leading-character rule alone rules out "", ".", ".." and a
		// leading separator.
		if i == 0 && !isAlnum(r) {
			return fmt.Errorf("%w: %s %q of id %q must start with a letter or digit",
				ErrPackageID, what, seg, id)
		}
		if !idSegmentAllowed(r) {
			return fmt.Errorf("%w: %s %q of id %q contains %q, which is not usable in a filename on every "+
				"supported platform (allowed: letters, digits, and . _ + -)", ErrPackageID, what, seg, id, r)
		}
	}
	if strings.Contains(seg, "..") {
		return fmt.Errorf("%w: %s %q of id %q contains a parent-directory reference", ErrPackageID, what, seg, id)
	}
	if strings.Contains(seg, DirSeparator) {
		return fmt.Errorf("%w: %s %q of id %q contains %q, which separates the namespace from the name in a "+
			"directory name and cannot appear inside either", ErrPackageID, what, seg, id, DirSeparator)
	}
	return nil
}

// reservedDeviceNames are the DOS device names, refused as a path component
// with or without an extension. amctl does not run on Windows, but the names
// come out of a hub lockfile authored elsewhere, and ValidateDirName is
// called on names this package did not compose, so the refusal must not
// depend on DirSeparator being present.
var reservedDeviceNames = map[string]struct{}{
	"con": {}, "prn": {}, "aux": {}, "nul": {},
	"com0": {}, "com1": {}, "com2": {}, "com3": {}, "com4": {},
	"com5": {}, "com6": {}, "com7": {}, "com8": {}, "com9": {},
	"lpt0": {}, "lpt1": {}, "lpt2": {}, "lpt3": {}, "lpt4": {},
	"lpt5": {}, "lpt6": {}, "lpt7": {}, "lpt8": {}, "lpt9": {},
}

// ValidateDirName is the portable floor every target's directory name must
// clear, checked identically on every platform. A target may be stricter —
// claude-code is, see ValidateClaudeCodeSkillDirName — but nothing may be
// laxer. It refuses a name ending in record.AsideSuffix (the atomic swap's
// rename target for a replaced destination, which would otherwise sit inside
// another package's removable set), StagingDirName (a sibling directory a
// later run clears), a dot-prefixed name, a trailing dot or space (some
// filesystems strip these, so the recorded path would not exist on disk), a
// DOS device name, a path traversal, a separator, and anything over
// MaxDirNameBytes.
func ValidateDirName(dirName string) error {
	switch {
	case dirName == "":
		return fmt.Errorf("%w: name is empty", ErrDirName)
	case dirName == "." || dirName == "..":
		return fmt.Errorf("%w: %q is a path traversal", ErrDirName, dirName)
	case strings.ContainsAny(dirName, `/\`), dirName != filepath.Base(dirName):
		return fmt.Errorf("%w: %q is a path, not a single directory name", ErrDirName, dirName)
	case len(dirName) > MaxDirNameBytes:
		return fmt.Errorf("%w: %q is %d bytes, over the %d-byte limit of the strictest supported filesystem",
			ErrDirName, dirName, len(dirName), MaxDirNameBytes)
	case strings.HasPrefix(dirName, "."):
		return fmt.Errorf("%w: %q is dot-prefixed, which is how an agent hides its own internals", ErrDirName, dirName)
	case strings.HasSuffix(dirName, "."), strings.HasSuffix(dirName, " "):
		return fmt.Errorf("%w: %q ends in a dot or a space, which some filesystems strip from a path component, so the "+
			"recorded path would not be the path on disk", ErrDirName, dirName)
	case strings.HasSuffix(dirName, record.AsideSuffix):
		return fmt.Errorf("%w: %q ends in %s, the name the atomic swap renames a replaced destination to, so "+
			"installing here would put this package inside another package's removable set",
			ErrDirName, dirName, record.AsideSuffix)
	case dirName == StagingDirName:
		return fmt.Errorf("%w: %q is the extraction staging directory", ErrDirName, dirName)
	}
	for _, r := range dirName {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`:*?"<>|`, r) {
			return fmt.Errorf("%w: %q contains %q, which is not usable in a filename on every supported platform",
				ErrDirName, dirName, r)
		}
		if unicode.IsSpace(r) && r != ' ' {
			return fmt.Errorf("%w: %q contains whitespace %q", ErrDirName, dirName, r)
		}
	}
	stem, _, _ := strings.Cut(dirName, ".")
	if _, reserved := reservedDeviceNames[strings.ToLower(stem)]; reserved {
		return fmt.Errorf("%w: %q is a reserved device name", ErrDirName, dirName)
	}
	return nil
}

// StagingRoot is the staging directory for a destination: a sibling of it, so
// the swap's rollback rename stays on one filesystem.
func StagingRoot(dest string) string {
	return filepath.Join(filepath.Dir(dest), StagingDirName)
}

// DestCollisionKey is the key under which two destinations are the same
// directory on a case-insensitive filesystem (APFS by default). Lowercasing
// the directory name itself would "fix" this by colliding on every platform,
// which is the sanitising this package refuses; the check instead belongs
// where the whole set of destinations is visible, in internal/plan.
func DestCollisionKey(dest string) string { return strings.ToLower(dest) }

// Request is one lockfile entry, reduced to what a destination depends on.
type Request struct {
	// ID is the lockfile entry id, `namespace/name`.
	ID string

	// Version is the version the hub resolved, verbatim, carried into the
	// marker and never parsed or compared. The destination deliberately does
	// not depend on it: a version in the path would turn an upgrade into a
	// write-then-remove with a window where both or neither exist, instead
	// of one rename.
	Version string

	// Kind is the lockfile entry kind. Only record.KindSkill is installable.
	// KindPlugin is refused structurally, not as pending work: a claude-code
	// plugin is registered in an agent-owned JSON file and a Codex MCP
	// server is a table in a shared TOML file, neither of which can be
	// swapped by rename or pruned without touching keys amctl did not write.
	Kind record.Kind
}

// Placement is every path one entry needs, derived and validated. Dest is
// absolute and clean, so it satisfies record.Entry's own validation, and it
// never ends in record.AsideSuffix.
type Placement struct {
	Target  record.Target
	Package Package
	Version string
	Kind    record.Kind

	// Root is the absolute directory the agent scans for skills.
	Root string

	// DirName is Root's child that holds this entry — the name the agent
	// advertises the skill under.
	DirName string

	// Dest is the entry root: the single path the record stores and the
	// only path prune consults (with its aside sibling).
	Dest string

	// EntryFilePath is the SKILL.md every skill directory must contain,
	// derived for verification and reporting; its bytes come from the
	// bundle and are never edited.
	EntryFilePath string

	// MarkerPath is the marker, a dotfile beside SKILL.md.
	MarkerPath string
}

// AsidePath is the name the atomic swap renames an existing Dest to.
func (p Placement) AsidePath() string { return p.Dest + record.AsideSuffix }

// StagingRoot is the staging directory for this placement.
func (p Placement) StagingRoot() string { return StagingRoot(p.Dest) }

// Marker is the on-disk answer to which package and version a directory
// holds, readable with no hub and no network. It is provenance, not
// authority: state.json remains the only thing pruning consults, since a
// marker sits inside a directory a user can edit. It carries no timestamp,
// so re-extracting the same version produces a byte-identical tree, and no
// profile slug, since two profiles may claim one destination.
type Marker struct {
	SchemaVersion int           `json:"schemaVersion"`
	ID            string        `json:"id"`
	Version       string        `json:"version"`
	Kind          record.Kind   `json:"kind"`
	Target        record.Target `json:"target"`
	Digest        record.Digest `json:"digest"`
}

// Marker builds the marker for this placement. The digest is the bundle
// digest verified before any byte reached the tree.
func (p Placement) Marker(digest record.Digest) Marker {
	return Marker{
		SchemaVersion: MarkerSchemaVersion,
		ID:            p.Package.ID(),
		Version:       p.Version,
		Kind:          p.Kind,
		Target:        p.Target,
		Digest:        digest,
	}
}

// Bytes is the marker's on-disk form: indented JSON with a trailing newline,
// deterministic for a given marker.
func (m Marker) Bytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode marker: %w", err)
	}
	return append(b, '\n'), nil
}

// ParseMarker reads a marker written by this build and refuses anything
// else. Unknown fields and an unrecognised schema version are errors rather
// than warnings, since a build that guessed at an unknown format would give
// a confident wrong answer.
func ParseMarker(b []byte) (Marker, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var m Marker
	if err := dec.Decode(&m); err != nil {
		return Marker{}, fmt.Errorf("decode marker: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Marker{}, err
	}
	return m, nil
}

// Validate checks the marker's shape. It does not check that the directory
// around it actually holds that package; that is a separate fingerprint check.
func (m Marker) Validate() error {
	if m.SchemaVersion != MarkerSchemaVersion {
		return fmt.Errorf("marker schema version %d is not %d", m.SchemaVersion, MarkerSchemaVersion)
	}
	if _, err := ParsePackageID(m.ID); err != nil {
		return fmt.Errorf("marker id: %w", err)
	}
	if m.Version == "" {
		return errors.New("marker has no version")
	}
	if !m.Kind.IsValid() {
		return fmt.Errorf("marker kind %q is not a contract kind", m.Kind)
	}
	if !m.Target.IsValid() {
		return fmt.Errorf("marker target %q is not a contract target", m.Target)
	}
	if m.Digest.IsZero() {
		return errors.New("marker has no digest")
	}
	return nil
}
