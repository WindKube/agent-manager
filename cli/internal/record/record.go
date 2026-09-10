// Package record is amctl's per-hub account of what it wrote and may remove.
package record

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/WindKube/agent-manager/cli/internal/cache"
)

const SchemaVersion = 1 // this build's format version; a mismatch refuses rather than migrates

const FileName = "state.json" // `~/.agent-manager/<hub>/state.json`

const AsideSuffix = ".amctl-old" // atomic-swap sibling name; internal/apply's swap must match

// Kind is a lockfile entry's kind (`plugin|skill`); only skill is installable today.
type Kind string

// The contract's kind values.
const (
	KindSkill  Kind = "skill"
	KindPlugin Kind = "plugin"
)

// IsValid reports whether k is one of the contract's kinds.
func (k Kind) IsValid() bool { return k == KindSkill || k == KindPlugin }

// Target is one agent's directory convention (`claude-code|codex`); `agents-md` was removed.
type Target string

// The contract's target values.
const (
	TargetClaudeCode Target = "claude-code"
	TargetCodex      Target = "codex"
)

// IsValid reports whether t is one of the contract's targets.
func (t Target) IsValid() bool {
	return t == TargetClaudeCode || t == TargetCodex
}

// Digest is cache.Digest with the record's JSON encoding, `sha256:<64 hex>`.
type Digest struct {
	cache.Digest
}

// ParseDigest reads the record encoding, which is the lockfile encoding.
func ParseDigest(s string) (Digest, error) {
	d, err := cache.ParseLockfileDigest(s)
	if err != nil {
		return Digest{}, err
	}
	return Digest{Digest: d}, nil
}

// MarshalJSON writes the lockfile encoding.
func (d Digest) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.Lockfile() + `"`), nil
}

// UnmarshalJSON reads only the lockfile encoding; anything else is corruption.
func (d *Digest) UnmarshalJSON(b []byte) error {
	s := string(b)
	if !strings.HasPrefix(s, `"`) || !strings.HasSuffix(s, `"`) || len(s) < 2 {
		return fmt.Errorf("%w: %s is not a JSON string", cache.ErrDigest, s)
	}
	parsed, err := ParseDigest(s[1 : len(s)-1])
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// FileMark is one installed file's account. No mtime (a same-size edit within
// a millisecond of install is byte-identical in mtime here), no ctime
// (darwin's Stat_t has none), no inode (the swap's rename changes it on every install).
type FileMark struct {
	SHA256 string `json:"h"` // the detector; everything else here is secondary
	Size   int64  `json:"s"` // cheap short-circuit: a differing size is sufficient for `modified`, never for `unmodified`

	// Mode is permission bits (masked 0o777), read via lstat, never the
	// archive header: under umask 0027 a requested 0755 lands as 0750.
	Mode uint32 `json:"m"`

	Kind string `json:"k"` // from lstat; a kind change is reported rather than opened (unsafe through a symlink)
}

// The lstat kinds a FileMark may carry; only FileKindRegular is written at install.
const (
	FileKindRegular = "f"
	FileKindSymlink = "l"
	FileKindOther   = "o"
)

const FingerprintAlgo = "sha256-tree-v1" // this build's fingerprint algorithm name

// Fingerprint is the record's account of one installed entry's tree at
// install time. Files and Dirs form a closed set over the entry root — a path
// on disk and absent here is `added`, a path here and absent on disk is
// `missing` — valid only for a root amctl created for this entry. Algo fails
// closed: an absent or unrecognised value refuses rather than assumes unmodified.
type Fingerprint struct {
	Algo  string              `json:"algo"`
	Files map[string]FileMark `json:"files,omitempty"` // keyed by entry-root-relative, slash-separated path
	Dirs  map[string]uint32   `json:"dirs,omitempty"`  // keyed the same way; value is permission bits only
}

// IsZero reports whether f was never taken (encoding/json's omitzero uses this).
func (f Fingerprint) IsZero() bool {
	return f.Algo == "" && len(f.Files) == 0 && len(f.Dirs) == 0
}

// Entry is one installed package, for one target, in one profile.
type Entry struct {
	// ID is `namespace/name`, exactly two segments — not `publisher/name`,
	// which would build a bundle URL with three where the contract has two.
	ID string `json:"id"`

	Version string `json:"version"` // verbatim, as the hub resolved and amctl installed it
	Digest  Digest `json:"digest"`

	Kind   Kind   `json:"kind"`
	Target Target `json:"target"` // per entry too: removing a disabled target's files needs to know which files those were

	Dest string `json:"dest"` // absolute path amctl wrote; the entry's root

	Fingerprint Fingerprint `json:"fingerprint,omitzero"` // absent means unverifiable: refuse and name --force, never assume unmodified
}

// RemovablePaths is Dest and Dest+AsideSuffix (what an interrupted swap
// leaves behind) — candidates, not obligations; the caller removes only what
// exists and only after ClaimantsOf reports no other profile claims Dest.
func (e Entry) RemovablePaths() []string {
	return []string{e.Dest, e.Dest + AsideSuffix}
}

// Profile is one synced profile's installation, as of the revision named here.
type Profile struct {
	Slug string `json:"slug"`

	Revision int `json:"revision"` // resolved to a number; `head` is never stored, or drift couldn't be told from change

	InstalledAt time.Time `json:"installedAt"` // provenance for `status` only; set only when Revision/Entries actually change

	Targets []Target `json:"targets"` // the intersection the CLI actually wrote, not the lockfile's advisory list

	Entries []Entry `json:"entries"`
}

// Record is one hub's installation record: the contents of one state.json.
type Record struct {
	SchemaVersion int    `json:"schemaVersion"`
	Hub           string `json:"hub"` // canonical URL this record belongs to; Load refuses a mismatch

	Profiles []Profile `json:"profiles"`
}

// New returns an empty record for hub; also what Load returns for an absent file.
func New(hub string) *Record {
	return &Record{SchemaVersion: SchemaVersion, Hub: hub}
}

// IsEmpty means "prune nothing, install everything" — correct for a
// never-synced machine, WRONG for a corrupt file; see Load.
func (r *Record) IsEmpty() bool { return len(r.Profiles) == 0 }

// Ref locates one entry by the profile slug it was installed for.
type Ref struct {
	Profile string
	Entry   Entry
}

// Refs is every entry in the record, in profile-then-entry order.
func (r *Record) Refs() []Ref {
	refs := make([]Ref, 0, r.entryCount())
	for i := range r.Profiles {
		p := &r.Profiles[i]
		for j := range p.Entries {
			refs = append(refs, Ref{Profile: p.Slug, Entry: p.Entries[j]})
		}
	}
	return refs
}

func (r *Record) entryCount() int {
	n := 0
	for _, p := range r.Profiles {
		n += len(p.Entries)
	}
	return n
}

// ByID is every entry for a package id, across profiles — for reporting, not
// deciding: the two-profiles-one-package refusal is internal/plan's.
func (r *Record) ByID(id string) []Ref {
	var out []Ref
	refs := r.Refs()
	for i := range refs {
		if refs[i].Entry.ID == id {
			out = append(out, refs[i])
		}
	}
	return out
}

// ClaimantsOf is every entry installed to dest; more than one is legitimate
// (shared destination at the same version). Prune must check this first.
func (r *Record) ClaimantsOf(dest string) []Ref {
	var out []Ref
	refs := r.Refs()
	for i := range refs {
		if refs[i].Entry.Dest == dest {
			out = append(out, refs[i])
		}
	}
	return out
}

// ProfileBySlug returns the profile with the given slug.
func (r *Record) ProfileBySlug(slug string) (Profile, bool) {
	for _, p := range r.Profiles {
		if p.Slug == slug {
			return p, true
		}
	}
	return Profile{}, false
}

// SetProfile replaces the profile with p.Slug, or appends it.
func (r *Record) SetProfile(p Profile) {
	for i := range r.Profiles {
		if r.Profiles[i].Slug == p.Slug {
			r.Profiles[i] = p
			return
		}
	}
	r.Profiles = append(r.Profiles, p)
}

// RemoveProfile drops a profile and reports whether it was there. Touches
// nothing on disk — prune first, then call this, or the tree becomes unremovable.
func (r *Record) RemoveProfile(slug string) bool {
	for i := range r.Profiles {
		if r.Profiles[i].Slug == slug {
			r.Profiles = append(r.Profiles[:i], r.Profiles[i+1:]...)
			return true
		}
	}
	return false
}

// normalize sorts the record into one canonical order so an unchanged sync
// encodes to byte-identical output and Save can decline to write at all.
func (r *Record) normalize() {
	r.SchemaVersion = SchemaVersion
	sort.Slice(r.Profiles, func(i, j int) bool { return r.Profiles[i].Slug < r.Profiles[j].Slug })
	for i := range r.Profiles {
		p := &r.Profiles[i]
		sort.Slice(p.Targets, func(a, b int) bool { return p.Targets[a] < p.Targets[b] })
		sort.Slice(p.Entries, func(a, b int) bool {
			if p.Entries[a].ID != p.Entries[b].ID {
				return p.Entries[a].ID < p.Entries[b].ID
			}
			return p.Entries[a].Target < p.Entries[b].Target
		})
	}
}

// ErrInvalid marks a record that decoded cleanly but says something amctl
// could not have written, meaning the file was edited or corrupted.
var ErrInvalid = errors.New("invalid installation record")

// Validate refuses a record this build will not act on; called by both Load and Save.
func (r *Record) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schema version %d, want %d", ErrInvalid, r.SchemaVersion, SchemaVersion)
	}
	if r.Hub == "" {
		return fmt.Errorf("%w: no hub URL", ErrInvalid)
	}
	seenProfile := make(map[string]struct{}, len(r.Profiles))
	for i := range r.Profiles {
		p := &r.Profiles[i]
		if p.Slug == "" {
			return fmt.Errorf("%w: a profile has no slug", ErrInvalid)
		}
		if _, dup := seenProfile[p.Slug]; dup {
			return fmt.Errorf("%w: profile %q appears twice", ErrInvalid, p.Slug)
		}
		seenProfile[p.Slug] = struct{}{}
		if err := p.validate(); err != nil {
			return fmt.Errorf("profile %s: %w", p.Slug, err)
		}
	}
	return nil
}

func (p *Profile) validate() error {
	// A revision of 0 is not a small revision, it is `head` never resolved.
	if p.Revision < 1 {
		return fmt.Errorf("%w: revision %d is not a resolved revision (>= 1)", ErrInvalid, p.Revision)
	}
	for _, t := range p.Targets {
		if !t.IsValid() {
			return fmt.Errorf("%w: target %q is not one of the contract's targets", ErrInvalid, t)
		}
	}
	seenSlot := make(map[string]struct{}, len(p.Entries))
	seenDest := make(map[string]struct{}, len(p.Entries))
	for i := range p.Entries {
		e := &p.Entries[i]
		if err := e.validate(); err != nil {
			return err
		}
		// (id, target): the same package may legitimately install for two targets.
		slot := e.ID + "\x00" + string(e.Target)
		if _, dup := seenSlot[slot]; dup {
			return fmt.Errorf("%w: entry %s appears twice for target %s", ErrInvalid, e.ID, e.Target)
		}
		seenSlot[slot] = struct{}{}
		// Sharing a destination within a profile is a bug; across profiles
		// it's legitimate, see ClaimantsOf.
		if _, dup := seenDest[e.Dest]; dup {
			return fmt.Errorf("%w: entries %s and another claim the same destination %s", ErrInvalid, e.ID, e.Dest)
		}
		seenDest[e.Dest] = struct{}{}
	}
	return nil
}

func (e *Entry) validate() error {
	if err := validateID(e.ID); err != nil {
		return err
	}
	if err := validateVersion(e.Version); err != nil {
		return fmt.Errorf("entry %s: %w", e.ID, err)
	}
	if e.Digest.IsZero() {
		return fmt.Errorf("%w: entry %s has no digest", ErrInvalid, e.ID)
	}
	if !e.Kind.IsValid() {
		return fmt.Errorf("%w: entry %s has kind %q, not one of the contract's kinds", ErrInvalid, e.ID, e.Kind)
	}
	if !e.Target.IsValid() {
		return fmt.Errorf("%w: entry %s has target %q, not one of the contract's targets", ErrInvalid, e.ID, e.Target)
	}
	if err := validateDest(e.ID, e.Dest); err != nil {
		return err
	}
	return e.Fingerprint.validate(e.ID)
}

// validateID enforces `namespace/name`, two non-empty segments, never repaired.
func validateID(id string) error {
	ns, name, ok := strings.Cut(id, "/")
	if !ok || ns == "" || name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("%w: entry id %q is not exactly two non-empty segments", ErrInvalid, id)
	}
	for _, seg := range []string{ns, name} {
		if seg == "." || seg == ".." || strings.ContainsAny(seg, "\\\x00") {
			return fmt.Errorf("%w: entry id %q has an unusable segment %q", ErrInvalid, id, seg)
		}
	}
	return nil
}

// validateVersion guards a value that becomes a URL path segment, not version ordering.
func validateVersion(v string) error {
	if v == "" {
		return fmt.Errorf("%w: no version", ErrInvalid)
	}
	if strings.ContainsAny(v, "/\\\x00") || strings.TrimSpace(v) != v {
		return fmt.Errorf("%w: version %q is not usable as a path segment", ErrInvalid, v)
	}
	return nil
}

func validateDest(id, dest string) error {
	if dest == "" {
		return fmt.Errorf("%w: entry %s has no destination", ErrInvalid, id)
	}
	if !filepath.IsAbs(dest) {
		return fmt.Errorf("%w: entry %s destination %s is not absolute", ErrInvalid, id, dest)
	}
	if filepath.Clean(dest) != dest {
		return fmt.Errorf("%w: entry %s destination %s is not a clean path", ErrInvalid, id, dest)
	}
	// Ending in AsideSuffix is refused: it would sit inside another entry's removable set.
	if strings.HasSuffix(dest, AsideSuffix) {
		return fmt.Errorf("%w: entry %s destination %s ends in %s, which is the swap's aside name",
			ErrInvalid, id, dest, AsideSuffix)
	}
	return nil
}

// validate checks the fingerprint's shape only; a hand-edited key could
// otherwise send --force outside the entry root.
func (f Fingerprint) validate(id string) error {
	if f.IsZero() {
		// Absent is allowed and means unverifiable, not silently unmodified.
		return nil
	}
	if f.Algo == "" {
		return fmt.Errorf("%w: entry %s has a fingerprint with no algorithm", ErrInvalid, id)
	}
	for key, mark := range f.Files {
		if err := validateFingerprintKey(id, key); err != nil {
			return err
		}
		if len(mark.SHA256) != 64 || strings.ToLower(mark.SHA256) != mark.SHA256 ||
			strings.TrimLeft(mark.SHA256, "0123456789abcdef") != "" {
			return fmt.Errorf("%w: entry %s file %s has hash %q, want 64 lowercase hex characters",
				ErrInvalid, id, key, mark.SHA256)
		}
		if mark.Size < 0 {
			return fmt.Errorf("%w: entry %s file %s has size %d", ErrInvalid, id, key, mark.Size)
		}
		if mark.Mode > 0o777 {
			return fmt.Errorf("%w: entry %s file %s has mode %#o outside the permission bits",
				ErrInvalid, id, key, mark.Mode)
		}
		switch mark.Kind {
		case FileKindRegular, FileKindSymlink, FileKindOther:
		default:
			return fmt.Errorf("%w: entry %s file %s has kind %q", ErrInvalid, id, key, mark.Kind)
		}
	}
	for key, mode := range f.Dirs {
		if err := validateFingerprintKey(id, key); err != nil {
			return err
		}
		if mode > 0o777 {
			return fmt.Errorf("%w: entry %s directory %s has mode %#o outside the permission bits",
				ErrInvalid, id, key, mode)
		}
	}
	return nil
}

// validateFingerprintKey enforces a clean, entry-root-relative, slash-separated key.
func validateFingerprintKey(id, key string) error {
	if key == "" {
		return fmt.Errorf("%w: entry %s has an empty fingerprint key", ErrInvalid, id)
	}
	if strings.ContainsAny(key, "\\\x00") {
		return fmt.Errorf("%w: entry %s fingerprint key %q must be slash-separated and NUL-free", ErrInvalid, id, key)
	}
	if strings.HasPrefix(key, "/") {
		return fmt.Errorf("%w: entry %s fingerprint key %q is absolute; keys are relative to the entry root",
			ErrInvalid, id, key)
	}
	// path.Clean leaves a leading `..` in place, so this check isn't redundant.
	if key == "." || key == ".." || strings.HasPrefix(key, "../") || path.Clean(key) != key {
		return fmt.Errorf("%w: entry %s fingerprint key %q is not a clean relative path", ErrInvalid, id, key)
	}
	return nil
}
