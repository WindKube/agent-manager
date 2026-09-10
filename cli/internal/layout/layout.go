// Package layout turns a lockfile entry into the paths one agent reads,
// purely: no I/O, no home-containment check, no sanitising — an unusable name is refused, not rewritten.
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

// ErrPackageID is the early gate, before any bytes reach disk.
var ErrPackageID = errors.New("unusable package id")

// ErrDirName marks a skill directory name that must never be written.
var ErrDirName = errors.New("unusable skill directory name")

// ErrKindUnsupported marks a lockfile entry kind amctl cannot install.
var ErrKindUnsupported = errors.New("entry kind not installable")

const (
	// DirSeparator joins namespace and name; a single char can't work since
	// both may contain `-.-_+`, and `--` is refused inside a segment.
	DirSeparator = "--"

	StagingDirName = ".amctl-staging" // sibling of the destination for a same-filesystem rename

	MaxDirNameBytes     = 255 // strictest limit among supported filesystems
	MarkerSchemaVersion = 1   // the marker format this build writes and reads
)

// Package is a lockfile entry id split into namespace and name (not the
// publisher slug, itself two segments, or the bundle URL gets three).
type Package struct {
	Namespace string
	Name      string
}

func (p Package) ID() string { return p.Namespace + "/" + p.Name }

// ParsePackageID refuses anything but two non-empty segments; never repairs.
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

// DirName is the user-visible skill identity under any target's skills root.
func (p Package) DirName() string { return p.Namespace + DirSeparator + p.Name }

// idSegmentAllowed mirrors the hub's object-key pattern (restated: hub is a separate module).
func idSegmentAllowed(r rune) bool {
	return isAlnum(r) || r == '.' || r == '_' || r == '+' || r == '-'
}

func isAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func validateIDSegment(id, what, seg string) error {
	for i, r := range seg {
		if i == 0 && !isAlnum(r) { // rules out "", ".", ".." and a leading separator
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

// reservedDeviceNames: DOS names, refused even off Windows since ids come from an external lockfile.
var reservedDeviceNames = map[string]struct{}{
	"con": {}, "prn": {}, "aux": {}, "nul": {},
	"com0": {}, "com1": {}, "com2": {}, "com3": {}, "com4": {},
	"com5": {}, "com6": {}, "com7": {}, "com8": {}, "com9": {},
	"lpt0": {}, "lpt1": {}, "lpt2": {}, "lpt3": {}, "lpt4": {},
	"lpt5": {}, "lpt6": {}, "lpt7": {}, "lpt8": {}, "lpt9": {},
}

// ValidateDirName is the portable floor every target's directory name must
// clear; a target may be stricter (see ValidateClaudeCodeSkillDirName) but
// never laxer. Refuses record.AsideSuffix, StagingDirName, dot-prefix,
// trailing dot/space, a DOS device name, traversal, a separator, oversize.
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

// StagingRoot is a sibling of dest, so the swap's rollback rename stays on one filesystem.
func StagingRoot(dest string) string {
	return filepath.Join(filepath.Dir(dest), StagingDirName)
}

// DestCollisionKey is where two destinations collide on a case-insensitive
// filesystem; the check itself lives in internal/plan.
func DestCollisionKey(dest string) string { return strings.ToLower(dest) }

// Request is one lockfile entry, reduced to what a destination depends on.
type Request struct {
	ID string // lockfile entry id, `namespace/name`

	Version string // carried into the marker verbatim, never in the path

	Kind record.Kind // only record.KindSkill is installable; KindPlugin refused structurally
}

// Placement is every path one entry needs, derived and validated. Dest is
// absolute, clean, and never ends in record.AsideSuffix.
type Placement struct {
	Target  record.Target
	Package Package
	Version string
	Kind    record.Kind

	Root    string // the absolute directory the agent scans for skills
	DirName string // Root's child holding this entry
	Dest    string // the entry root; the only path prune consults, with its aside sibling

	EntryFilePath string // the SKILL.md every skill directory must contain
	MarkerPath    string // the marker, a dotfile beside SKILL.md
}

func (p Placement) AsidePath() string { return p.Dest + record.AsideSuffix }

func (p Placement) StagingRoot() string { return StagingRoot(p.Dest) }

// Marker is provenance, not authority (state.json is what pruning
// consults); no timestamp, no profile slug (two profiles may share a destination).
type Marker struct {
	SchemaVersion int           `json:"schemaVersion"`
	ID            string        `json:"id"`
	Version       string        `json:"version"`
	Kind          record.Kind   `json:"kind"`
	Target        record.Target `json:"target"`
	Digest        record.Digest `json:"digest"`
}

// Marker builds the marker for this placement; digest is already verified.
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

// Bytes is the marker's on-disk form: deterministic indented JSON.
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

// ParseMarker refuses unknown fields and schema versions rather than
// guessing at an unknown format.
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

// Validate checks the marker's shape only, not that the directory around it
// actually holds that package (a separate fingerprint check).
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
