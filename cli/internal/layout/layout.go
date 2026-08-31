// Package layout turns a lockfile entry into the paths one agent reads.
//
// It is PURE: strings in, paths out. Nothing here stats, opens, creates or
// removes anything, and that is a requirement rather than a preference. A
// layout that touched the disk could only be tested for the paths it managed
// to create, never for the ones it would choose — and FR-020's containment
// check (T042a) has to run on a destination BEFORE anything opens it, which is
// impossible if deriving the destination is itself an open.
//
// # What this package deliberately does NOT do
//
//   - It does not read the environment. CLAUDE_CONFIG_DIR arrives as a Config
//     field. internal/cmd owns home and environment resolution (FR-039), and a
//     package that fell back to os.Getenv or os.UserHomeDir would route around
//     the refusal FR-039 requires before any network call.
//   - It does not check that a destination is inside the user's home (FR-020).
//     That check must run on the RESOLVED path at the moment of writing, in
//     internal/apply: agent directories are frequently symlinks into a dotfiles
//     repo, so a path that is inside the home as a string may not be as an
//     inode. Re-deriving containment from a string here would be a check that
//     passes on the wrong evidence.
//   - It does not sanitise. Every unusable name is refused, naming the id and
//     the reason. A name amctl quietly rewrote would not match the record it
//     later prunes against (FR-028), and two different packages rewritten to
//     one name is FR-023 broken by the very code meant to satisfy it.
//   - It does not install plugins, for any target. See Request.Kind.
//   - It does not resolve or compare versions (FR-009). Version is carried
//     verbatim into the marker and never parsed.
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
// Refusing here is the EARLY gate: record.Validate refuses the same ids when
// the record is written, but by then bytes are already on disk.
var ErrPackageID = errors.New("unusable package id")

// ErrDirName marks a skill directory name that must never be written.
var ErrDirName = errors.New("unusable skill directory name")

// ErrKindUnsupported marks a lockfile entry kind amctl cannot install.
var ErrKindUnsupported = errors.New("entry kind not installable")

const (
	// DirSeparator joins the namespace and the name in a skill directory name:
	// `acme/code-review` installs to `acme--code-review`.
	//
	// WHY TWO HYPHENS, and why the scheme is what it is (FR-023).
	//
	// Gate R2 measured that claude-code keys a skill by its DIRECTORY name and
	// not by the `name:` in its frontmatter — two directories with identical
	// frontmatter both loaded, each advertised under its own directory name. So
	// the directory name is the user-visible identity, and FR-023 ("two packages
	// whose names collide across publishers MUST install to distinct
	// directories") is satisfiable by naming alone, with no bundle rewriting.
	// It also means the name has to READ well: a user sees `acme--code-review`
	// and `globex--code-review` side by side in their skills list and has to be
	// able to tell which is which and invoke one of them.
	//
	// The namespace is ALWAYS present, never only on collision. Disambiguating
	// on demand would make a package's destination depend on the rest of the
	// catalog: an unrelated package appearing under another namespace would
	// rename an already-installed directory, which means an uninstall and a
	// reinstall of something that did not change (FR-025), a stale record
	// destination, and a skill whose name changed under the user for reasons
	// they cannot see.
	//
	// A single separator cannot work. Both segments may legitimately contain
	// `-`, `.`, `_` and `+` (see idSegmentAllowed), so with any single-character
	// separator `acme-code/review` and `acme/code-review` produce the SAME
	// directory name — two different packages, one directory, one overwriting
	// the other and prune deleting the survivor. That is FR-023 violated by the
	// disambiguator. `--` is refused INSIDE a segment (see validateIDSegment),
	// which makes the first `--` unambiguously the separator and the mapping
	// injective. The cost is refusing a package whose namespace or name contains
	// a double hyphen; the refusal is loud and names the reason, which is the
	// direction to fail in.
	//
	// It stays inside the lowercase-alphanumeric-and-hyphen alphabet the Agent
	// Skills format expects, which is why it is `--` and not `@`, `:` or `__`.
	// R2's consequence is explicit that the separator must be conservative
	// because Codex may enforce naming rules claude-code ignores; `:` is a path
	// separator to enough tools to be unusable, `@` already means `<skill>@<source>` in
	// claude-code's own plugin vocabulary, and `_` is not in the hub's
	// object-key charset at all so it buys nothing the hyphen does not.
	//
	// REJECTED: nesting, `skills/<namespace>/<name>/SKILL.md`. It is the obvious
	// answer and it is unmeasured in the direction that fails silently — R2
	// observed loading only at one level, and two independent accounts of Codex
	// state its skills root is scanned exactly one level deep, non-recursively.
	// A nested skill that does not load reports success and does nothing, which
	// is the worst failure this tool has.
	//
	// NOT ESTABLISHED: no `--` name was planted and observed loading. R2's
	// probes were single-segment names (`amctl-probe`). The scheme is the most
	// conservative disambiguation available — same charset, one extra hyphen —
	// but confirming that claude-code lists `acme--code-review` is owed on the
	// release-matrix runners (T063) alongside the darwin roots.
	DirSeparator = "--"

	// StagingDirName is the extraction staging directory, a sibling of the
	// destination as gate R3 requires: an agent directory is often a symlink
	// into a dotfiles repo on another mount, and same-filesystem staging is the
	// only thing that makes the install a rename at all. It is named here
	// because it is a path this package must refuse to install a package to,
	// and a second literal in internal/apply is how the two drift apart.
	StagingDirName = ".amctl-staging"

	// MaxDirNameBytes is the longest directory name any target accepts. 255
	// bytes is the strictest of the filesystems in the release matrix (ext4 255
	// bytes, APFS 255 characters), so applying it everywhere keeps one record
	// readable on every platform.
	MaxDirNameBytes = 255

	// MarkerSchemaVersion is the version of the marker format this build writes
	// and the only one it reads.
	MarkerSchemaVersion = 1
)

// Package is a lockfile entry id split into its two segments.
//
// THE TRAP: the first segment is the NAMESPACE, not the publisher slug. A
// publisher slug is itself two segments (`example/platform`) and its namespace
// is the first of them (`example`). The lockfile schema's `"description":
// "publisher/name"` on the entry id, and the bundle path's `{publisher}`
// parameter, are both wrong in the same way; the parameter's own description
// ("the publishing namespace, as it appears in the catalog") is the accurate
// half. An id built from a slug would produce a three-segment bundle URL where
// the contract has two, and the 404 looks exactly like a missing package.
//
// This is also why FR-023 is about `namespace/name` and not about the
// publisher: two publishers may share one namespace, so the publisher is not
// the thing that disambiguates.
type Package struct {
	Namespace string
	Name      string
}

// ID is the lockfile spelling, `namespace/name`.
func (p Package) ID() string { return p.Namespace + "/" + p.Name }

// ParsePackageID splits a lockfile entry id and refuses everything that cannot
// safely become one directory name.
//
// An id that is not exactly two non-empty segments is an error, never joined,
// truncated or padded: either repair addresses a different package than the one
// the lockfile named, and the resulting install would be recorded under an id
// that does not exist.
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

// idSegmentAllowed reports whether r may appear after the first character of an
// id segment.
//
// HAND-DERIVED from the hub's own object-key segment pattern,
// `^[A-Za-z0-9][A-Za-z0-9._+-]*$` in the hub module's internal/blob/keys.go,
// which every namespace, package name and version in the catalog must satisfy
// to have a bundle object at all. A package whose segment falls outside it
// cannot exist in the store, so accepting more here would only widen what this
// package has to defend. The pattern is restated rather than imported because
// the hub is a separate module and importing it would put the server in this
// binary's dependency graph; if the hub ever widens its charset, this is the
// place that has to widen with it.
//
// It also answers the platform question outright: every character that is
// awkward in a filename anywhere is already outside this set — `/ \ : * ? " < >
// |`, every control character, and space. Refusing them EVERYWHERE rather than
// only where the filesystem does is deliberate: R4 made the record
// separator-independent on purpose, and a charset that varied by GOOS would
// mean a profile that installs on one platform and refuses on another, with the
// same lockfile.
func idSegmentAllowed(r rune) bool {
	return isAlnum(r) || r == '.' || r == '_' || r == '+' || r == '-'
}

func isAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func validateIDSegment(id, what, seg string) error {
	for i, r := range seg {
		// The leading-character rule is the hub's too, and it alone rules out
		// "", ".", ".." and a leading separator.
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
	// Without this the namespace/name split of a directory name is ambiguous
	// and two distinct packages can land in one directory. See DirSeparator.
	if strings.Contains(seg, DirSeparator) {
		return fmt.Errorf("%w: %s %q of id %q contains %q, which separates the namespace from the name in a "+
			"directory name and cannot appear inside either", ErrPackageID, what, seg, id, DirSeparator)
	}
	return nil
}

// reservedDeviceNames are the DOS device names, refused as a path component
// with or without an extension. amctl does not run on Windows; the names come
// out of a HUB LOCKFILE, which is data authored elsewhere and read on machines
// amctl does not control, so the refusal is about what the hub may serve rather
// than about what this binary runs on. A composed DirName always contains
// DirSeparator and so can never be one of these, but the guarantee must not
// depend on the separator: ValidateDirName is the last check before a path is
// built, and it is called on names this package did not compose.
var reservedDeviceNames = map[string]struct{}{
	"con": {}, "prn": {}, "aux": {}, "nul": {},
	"com0": {}, "com1": {}, "com2": {}, "com3": {}, "com4": {},
	"com5": {}, "com6": {}, "com7": {}, "com8": {}, "com9": {},
	"lpt0": {}, "lpt1": {}, "lpt2": {}, "lpt3": {}, "lpt4": {},
	"lpt5": {}, "lpt6": {}, "lpt7": {}, "lpt8": {}, "lpt9": {},
}

// ValidateDirName is the portable floor every target's directory name must
// clear, checked identically on every platform for the reason given on
// idSegmentAllowed. A target may be stricter — claude-code is, see
// ValidateClaudeCodeSkillDirName — but nothing may be laxer.
//
// What it refuses, and why each refusal is not tidiness:
//
//   - A name ending in record.AsideSuffix. R3's atomic swap renames an existing
//     destination to dest+".amctl-old" before renaming the new tree in, so the
//     complete set of paths amctl may ever remove for an entry is {dest,
//     dest+".amctl-old"} — Entry.RemovablePaths, two literal names, no glob. A
//     package legitimately installed at `x.amctl-old` would sit INSIDE the
//     removable set of the package at `x`, so pruning one would delete a live
//     install of the other. R3 makes refusing this internal/layout's
//     guarantee, which is why it is here and not only in record.validateDest.
//   - StagingDirName. Extraction stages into a sibling of the destination; a
//     package installed there would be inside the directory a later run
//     clears.
//   - A dot-prefixed name, a trailing dot or a trailing space. Some filesystems
//     strip trailing dots and spaces from a path component, so a directory
//     recorded as `foo.` is `foo` on disk: the record then names a path that
//     does not exist, prune finds nothing to remove, and the files stay
//     forever.
//   - A DOS device name, a path traversal, a name containing a separator, and
//     anything over MaxDirNameBytes.
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

// StagingRoot is the staging directory for a destination: a SIBLING of it, per
// gate R3. A central staging directory would make the swap's rollback fail with
// EXDEV exactly when it is needed, and an EXDEV recursive-copy fallback is not
// atomic, which inverts the one requirement FR-024 exists for.
func StagingRoot(dest string) string {
	return filepath.Join(filepath.Dir(dest), StagingDirName)
}

// DestCollisionKey is the key under which two destinations are the SAME
// directory on a case-insensitive filesystem — APFS by default.
//
// This is the one FR-023 hazard a per-entry function cannot close. `Acme/x` and
// `acme/x` are two packages with two distinct destinations on ext4 and one
// shared directory on a Mac, where the record holds two entries pointing at one
// tree and pruning either deletes the other's install. Lowercasing the
// directory name instead would close it by making the two collide on EVERY
// platform, which is worse and is also the sanitising this package refuses.
//
// So the check belongs where the whole set is visible — internal/plan, which
// already has to refuse two profiles resolving one package to two versions
// (FR-012) — and this function is what it compares. Nothing here can use it,
// because nothing here sees more than one entry.
func DestCollisionKey(dest string) string { return strings.ToLower(dest) }

// Request is one lockfile entry, reduced to what a destination depends on.
type Request struct {
	// ID is the lockfile entry id, `namespace/name`.
	ID string

	// Version is the version the hub resolved, verbatim. It is carried into the
	// marker and is never parsed or compared (FR-009).
	//
	// THE DESTINATION DOES NOT DEPEND ON IT, and that is load-bearing rather
	// than an omission: a version in the path would make an upgrade a write to
	// a new directory plus a removal of the old one, two operations with a
	// window where both or neither exist, instead of R3's single rename of one
	// directory (FR-024). It also means Place needs no version — it routes on
	// id and kind alone — so the version is required only where it is actually
	// used, by Marker.Validate.
	Version string

	// Kind is the lockfile entry kind. Only record.KindSkill is installable.
	//
	// KindPlugin is refused for every target, and structurally rather than
	// pending work: a claude-code plugin is registered in agent-owned
	// $CLAUDE_CONFIG_DIR/plugins/installed_plugins.json and a Codex MCP server
	// is a table in user-owned ~/.codex/config.toml. Installing either means
	// rewriting a shared file, which cannot be made atomic by rename (FR-024)
	// and cannot be pruned without removing keys amctl did not write (FR-028).
	// There is no plugin destination to derive, so Place refuses rather than
	// returning a path nothing can safely use.
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

	// Dest is the entry root: the single path the record stores and the only
	// path prune consults (with its aside sibling).
	Dest string

	// EntryFilePath is the SKILL.md every skill directory must contain. It is
	// derived for verification and reporting; the bytes come from the bundle
	// and are never edited — stamping provenance into SKILL.md would rewrite
	// bytes just verified by digest and break R4's install fingerprint.
	EntryFilePath string

	// MarkerPath is the FR-022 marker, a dotfile beside SKILL.md. R2 confirmed
	// by observation that a skill directory carrying it loads normally.
	MarkerPath string
}

// AsidePath is the name R3's swap renames an existing Dest to. It is here so no
// caller retypes the suffix; record.AsideSuffix is the single definition.
func (p Placement) AsidePath() string { return p.Dest + record.AsideSuffix }

// StagingRoot is the staging directory for this placement.
func (p Placement) StagingRoot() string { return StagingRoot(p.Dest) }

// Marker is the on-disk answer to FR-022: which package and version a directory
// holds, readable with no hub and no network.
//
// It is PROVENANCE, NOT AUTHORITY. state.json remains the only thing pruning
// consults (FR-026, FR-028); nothing may decide a removal from a marker,
// because a marker is a file inside a directory a user can edit and prune must
// not be steerable by its own target.
//
// It carries no timestamp and no profile slug, and both omissions are
// deliberate. No timestamp, so the marker's bytes are a function of the entry
// alone: a re-extraction of the same version produces a byte-identical tree,
// which keeps R4's fingerprint comparison and idempotence (FR-025) about the
// package rather than about when it was installed. No profile, because two
// profiles may claim one destination — record.ClaimantsOf exists for exactly
// that — so a marker naming one of them would be wrong as soon as the second
// arrived.
type Marker struct {
	SchemaVersion int           `json:"schemaVersion"`
	ID            string        `json:"id"`
	Version       string        `json:"version"`
	Kind          record.Kind   `json:"kind"`
	Target        record.Target `json:"target"`
	Digest        record.Digest `json:"digest"`
}

// Marker builds the marker for this placement. The digest is the bundle digest
// that was verified before any byte reached the tree (FR-014).
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

// ParseMarker reads a marker written by this build and refuses anything else.
// Unknown fields and an unrecognised schema version are errors rather than
// warnings: a marker is only useful if "what is this directory" has one answer,
// and a build that guessed at a format it does not know would give a confident
// wrong one.
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
// around it actually holds that package: that is R4's fingerprint, and the
// record is its source.
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
