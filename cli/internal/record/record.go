// Package record is amctl's installation record: the CLI's own account, per
// hub, of what it wrote to this machine, and the authority for what may
// later be removed.
//
// It records paths, not patterns: pruning walks a list of things the CLI
// wrote, never a glob over a directory it does not own, so the complete set
// of paths amctl may ever remove for an entry is Entry.RemovablePaths(), two
// literal names derived from one recorded destination. It is written after
// the swap, not before: a record claiming an entry that is not on disk
// causes a spurious removal attempt, while an entry on disk without a
// record is merely re-installed next run, and only the first is unsafe.
//
// It does not resolve the home directory or derive a hub's directory name;
// Load and Save are given a path, and internal/cmd owns hub identity, so
// this package compares the recorded hub URL by exact string equality and
// never canonicalises. It does not check that a destination is inside the
// user's home; that containment check must run on the resolved path at the
// moment of writing, by internal/apply, since an agent directory is
// frequently a symlink. It does not resolve, compare or order versions, and
// it does not implement the refusal of two profiles resolving one package
// to two versions (that is internal/plan's). It does not compute or verify
// a Fingerprint; this file only defines the shape.
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

// SchemaVersion is the version of the on-disk format this build writes and is
// the only version it reads. A record stamped with anything else is refused
// with a message rather than migrated in place, because a migration that has
// not been written yet is indistinguishable from one that has.
const SchemaVersion = 1

// FileName is the record's name inside a hub's directory:
// `~/.agent-manager/<hub>/state.json` (plan.md's storage table).
const FileName = "state.json"

// AsideSuffix is the name the atomic swap renames an existing destination to
// before renaming the new tree into place. It lives here rather than in
// internal/apply because the record needs the aside to be a deterministic
// sibling, which is what keeps Entry.RemovablePaths a closed two-element set
// instead of a glob; internal/apply's swap must use this same constant. The
// leading dot keeps an interrupted swap's leftovers out of an agent's scan
// of its own skills directory.
const AsideSuffix = ".amctl-old"

// Kind is a lockfile entry's kind, the frozen contract's enum (`plugin|skill`).
// Only `skill` is installable today, since claude-code plugins live in
// agent-owned state that cannot be swapped by rename or pruned without
// touching keys amctl did not write, but the record carries the full enum
// so a record written by a later build stays readable.
type Kind string

// The contract's kind values.
const (
	KindSkill  Kind = "skill"
	KindPlugin Kind = "plugin"
)

// IsValid reports whether k is one of the contract's kinds.
func (k Kind) IsValid() bool { return k == KindSkill || k == KindPlugin }

// Target is one agent's directory convention, the frozen contract's enum
// (`claude-code|codex`). Which of them amctl can actually write is a
// separate, client-side decision; this type is the contract's vocabulary,
// not the shipped set, so a record written by a later build stays readable.
// `agents-md` was a third value and is gone from the contract; IsValid
// rejects a record from a build that predates the removal.
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
// A typed digest rather than a string, since the same value reaches this
// CLI in two encodings and a field that could hold either would compare
// unequal for two spellings of one value.
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

// UnmarshalJSON reads the lockfile encoding and nothing else. A spelling
// amctl does not emit means the file was edited or corrupted, and guessing
// at it is how a digest check stops being a check.
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

// FileMark is one installed file's account in a Fingerprint. Nothing
// time-based is stored: no mtime, since a same-size edit within a
// millisecond of the install write is byte-identical in mtime on this
// kernel and any mtime-preserving restore has no detection window at all;
// no ctime, since `syscall.Stat_t` has no Ctim on darwin; no inode number,
// since the atomic swap's rename changes the inode on every install by design.
type FileMark struct {
	// SHA256 is 64 lowercase hex characters of the file's bytes, the
	// detector; everything else here is a lesser job.
	SHA256 string `json:"h"`

	// Size is for diagnostics and a cheap short-circuit: a differing size is
	// sufficient for `modified`, a matching size is never sufficient for
	// `unmodified`.
	Size int64 `json:"s"`

	// Mode is permission bits only, masked 0o777, read with lstat from the
	// file as actually written, never from the archive header: under umask
	// 0027 a requested 0755 lands as 0750, and recording the header's mode
	// would report a false conflict on every executable file. setuid, setgid
	// and sticky are refused by the extractor, so any of those bits present
	// at check time is itself a modification.
	Mode uint32 `json:"m"`

	// Kind comes from lstat, so a symlink reports as a symlink. A kind
	// change is reported instead of opening the path, since hashing through
	// a link or overwriting through it are both unsafe.
	Kind string `json:"k"`
}

// The lstat kinds a FileMark may carry. Only FileKindRegular is ever written
// at install; the other two give a check-time verdict a name.
const (
	FileKindRegular = "f"
	FileKindSymlink = "l"
	FileKindOther   = "o"
)

// FingerprintAlgo is the algorithm string this build's fingerprint is
// written with, fixing its name so the migration seam below is real.
const FingerprintAlgo = "sha256-tree-v1"

// Fingerprint is the record's account of one installed entry's tree, taken
// at install, answering by content whether anything under the entry's root
// has changed since amctl wrote it.
//
// Files and Dirs together are a closed set over the entry root: a path on
// disk and absent here is `added`, a path here and absent on disk is
// `missing`, and both are modifications. This closure only holds for a root
// amctl created for this entry, since prune removes an entry by removing
// that root recursively.
//
// Algo is the migration seam and fails closed: a known older algorithm is
// verified with its own verifier, and an absent or unrecognised one refuses
// rather than assumes unmodified, since that is the direction that deletes
// somebody's work.
//
// There is deliberately no root hash alongside Files: it is derivable, saves
// nothing to compute, and introduces a second value that can disagree with
// the first.
type Fingerprint struct {
	Algo string `json:"algo"`

	// Files is keyed by entry-root-relative, slash-separated path, never
	// absolute, since the entry already carries its absolute destination.
	Files map[string]FileMark `json:"files,omitempty"`

	// Dirs is keyed the same way; the value is permission bits only.
	Dirs map[string]uint32 `json:"dirs,omitempty"`
}

// IsZero reports whether f was never taken. Used by encoding/json's omitzero
// so an entry recorded before T049 lands does not serialise an empty object.
func (f Fingerprint) IsZero() bool {
	return f.Algo == "" && len(f.Files) == 0 && len(f.Dirs) == 0
}

// Entry is one installed package, for one target, in one profile.
type Entry struct {
	// ID is `namespace/name`, exactly two non-empty segments — not
	// `publisher/name`: a publisher slug is itself two segments and would
	// build a bundle URL with three where the contract has two.
	ID string `json:"id"`

	// Version is the version the hub resolved and amctl installed, verbatim.
	Version string `json:"version"`

	// Digest is the bundle digest verified before any byte reached the tree.
	Digest Digest `json:"digest"`

	// Kind and Target say what was installed and under whose convention.
	// Target is per entry as well as per profile since removing what a
	// now-disabled target wrote needs to know which files those were.
	Kind   Kind   `json:"kind"`
	Target Target `json:"target"`

	// Dest is the absolute path amctl wrote, the entry's root, and the only
	// thing prune consults.
	Dest string `json:"dest"`

	// Fingerprint is the install-time account of Dest's contents. Absent
	// means unverifiable, which means a refusal naming --force, never an
	// assumption of unmodified.
	Fingerprint Fingerprint `json:"fingerprint,omitzero"`
}

// RemovablePaths is the complete set of paths amctl may remove for this
// entry. Dest+AsideSuffix is what an interrupted swap leaves behind, fixed
// as a deterministic sibling so it is a name this function can compute
// rather than one only a directory listing could find. The two paths are
// candidates, not obligations: a caller removes only what exists, and only
// after ClaimantsOf reports no other profile still claims Dest.
func (e Entry) RemovablePaths() []string {
	return []string{e.Dest, e.Dest + AsideSuffix}
}

// Profile is one synced profile's installation, as of the revision named here.
type Profile struct {
	// Slug is the profile's slug.
	Slug string `json:"slug"`

	// Revision is the exact revision installed, resolved to a number.
	// `head` is never stored, since a record saying `head` cannot tell
	// drift from change on the next run.
	Revision int `json:"revision"`

	// InstalledAt is when this revision was installed, provenance for
	// `status`, never consulted by modification detection. Set this only
	// when Revision or Entries actually change, never on every save, or an
	// unchanged sync would make the record's bytes differ on every run.
	InstalledAt time.Time `json:"installedAt"`

	// Targets is the set of targets in force when this profile was
	// installed, the intersection the CLI actually wrote rather than the
	// lockfile's advisory list.
	Targets []Target `json:"targets"`

	// Entries is what was installed for this profile.
	Entries []Entry `json:"entries"`
}

// Record is one hub's installation record: the contents of one state.json.
type Record struct {
	// SchemaVersion is stamped on write and checked on read.
	SchemaVersion int `json:"schemaVersion"`

	// Hub is the canonical hub URL this record belongs to. Load refuses a
	// record against a different hub, since applying one hub's account of
	// what may be removed to another hub's tree is a deletion with no
	// evidence behind it.
	Hub string `json:"hub"`

	// Profiles is every profile installed from this hub.
	Profiles []Profile `json:"profiles"`
}

// New returns an empty record for hub. This is also what Load returns for an
// absent file, so the two paths cannot diverge.
func New(hub string) *Record {
	return &Record{SchemaVersion: SchemaVersion, Hub: hub}
}

// IsEmpty reports whether the record claims nothing. An empty record means
// "prune nothing, install everything", which is the correct reading of a
// machine that has never synced and the WRONG reading of a corrupt file —
// see Load.
func (r *Record) IsEmpty() bool { return len(r.Profiles) == 0 }

// Ref locates one entry: the slug of the profile it was installed for, and
// the entry itself. Entries are compared and reported per profile, so a bare
// Entry is never enough to say anything to a user.
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

// ByID is every entry for a package id, across profiles. This exists for
// reporting, not for deciding: the refusal of two profiles resolving one
// package to two versions is internal/plan's, since at the moment it fires
// neither version has been installed yet.
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

// ClaimantsOf is every entry that installed to dest. More than one is
// legitimate: two profiles may include the same package at the same
// version, resolving to one destination with only one directory on disk.
// Prune must consult this before removing anything, since removing dest
// because one profile no longer claims it would delete a package another
// profile still wants.
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

// RemoveProfile drops a profile and reports whether it was there. It
// removes nothing from the filesystem: dropping the record before pruning
// the files it accounts for is how an installed tree becomes unremovable.
// Prune first, then call this.
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

// Validate refuses a record this build will not act on. Called by both Load
// and Save, so a record cannot be written in a shape that would be refused on
// the way back in.
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
		// (id, target) rather than id: the same package may legitimately be
		// installed for two targets, into two different roots.
		slot := e.ID + "\x00" + string(e.Target)
		if _, dup := seenSlot[slot]; dup {
			return fmt.Errorf("%w: entry %s appears twice for target %s", ErrInvalid, e.ID, e.Target)
		}
		seenSlot[slot] = struct{}{}
		// Two entries in one profile sharing a destination is a bug; across
		// profiles it is legitimate, see ClaimantsOf.
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

// validateID enforces `namespace/name`, exactly two non-empty segments,
// never silently joined or truncated: either repair would build a URL for a
// different package than the one recorded.
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

// validateVersion guards a value that becomes a URL path segment. It is not
// version parsing: this CLI has no opinion on which of two versions is newer.
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
	// A destination ending in the aside suffix is refused: entry A at
	// /x/foo has removable set {/x/foo, /x/foo.amctl-old}, so an entry B
	// installed at /x/foo.amctl-old would sit inside A's removable set.
	if strings.HasSuffix(dest, AsideSuffix) {
		return fmt.Errorf("%w: entry %s destination %s ends in %s, which is the swap's aside name",
			ErrInvalid, id, dest, AsideSuffix)
	}
	return nil
}

// validate checks the fingerprint's shape, not its contents: whether the
// recorded hashes still match the tree is the verifier's job, but whether
// the keys are safe to join onto an absolute destination is this package's,
// since a hand-edited record could otherwise send `--force` outside the
// entry root.
func (f Fingerprint) validate(id string) error {
	if f.IsZero() {
		// Absent is allowed and means unverifiable, not silently unmodified;
		// an entry recorded before the fingerprint existed must still be prunable.
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

// validateFingerprintKey enforces that keys are entry-root-relative,
// slash-separated and clean, since every key is eventually joined onto
// Entry.Dest.
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
	// path.Clean leaves a leading `..` in place, so the explicit test is not
	// redundant with the Clean comparison: Clean("../x") is "../x".
	if key == "." || key == ".." || strings.HasPrefix(key, "../") || path.Clean(key) != key {
		return fmt.Errorf("%w: entry %s fingerprint key %q is not a clean relative path", ErrInvalid, id, key)
	}
	return nil
}
