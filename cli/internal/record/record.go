// Package record is amctl's installation record: the CLI's own account, per
// hub, of what it wrote to this machine. It is the authority for what may
// later be removed (FR-026) and the whole reason pruning can be safe in a
// directory the CLI does not own (FR-028).
//
// Two properties matter more than the field list. Both are quoted from
// plan.md's on-disk state model, and both are written down here because both
// look arbitrary and will otherwise be "tidied":
//
//   - "It records paths, not patterns." Pruning walks a list of things the
//     CLI wrote, never a glob over a directory it does not own. That is what
//     makes FR-028 true by construction rather than by care: the complete set
//     of paths amctl may ever remove for an entry is Entry.RemovablePaths(),
//     two literal names derived from one recorded destination. There is no
//     pattern anywhere in this package, and adding one — a `*.amctl-old`
//     sweep, a "clean up anything we don't recognise" pass over a skills
//     directory — deletes somebody's hand-written skill the first time it
//     runs.
//   - "It is written after the swap, not before." A record claiming an entry
//     that is not on disk causes a spurious removal attempt; an entry on disk
//     without a record is merely re-installed next run. Both orderings can be
//     wrong; this one is wrong in the recoverable direction. Do not "fix" the
//     ordering by saving first so that a crash mid-swap leaves a consistent
//     file — the file would be consistent about a tree that does not exist.
//
// # What this package deliberately does NOT do
//
//   - It does not resolve the home directory or derive a hub's directory name.
//     Load and Save are given a path. FR-039 requires the refusal for an unset
//     or unwritable home to name the variable, before any network call, and
//     that check belongs to internal/cmd; a record that quietly fell back to
//     os.UserHomeDir would route around it. internal/cmd is also the single
//     owner of hub identity — the URL-to-directory-name function and the
//     canonical URL form are one decision — so this package compares the
//     recorded hub URL to the expected one by exact string equality and never
//     canonicalises, folds case or strips a port. A second canonicalisation
//     here would eventually disagree with the directory naming, and the
//     failure mode of disagreement is two records for one hub, one of which
//     stops being consulted while its files stay on disk forever.
//   - It does not check that a destination is inside the user's home (FR-020).
//     It checks that a destination is absolute, and that it does not collide
//     with the swap's aside name, but containment must be checked on the
//     RESOLVED path at the moment of writing, by internal/apply — an agent
//     directory is frequently a symlink into a dotfiles repo, so a path that
//     was inside the home when it was recorded may not be now. Re-deriving
//     containment from a stored string would be a check that passes on the
//     wrong evidence.
//   - It does not resolve, compare or order versions (FR-009). Entry.Version
//     is validated as a string that is safe to put in a URL path segment,
//     which is not the same thing as having an opinion about which of two
//     versions is newer. The hub resolves; the CLI applies.
//   - It does not implement FR-012's refusal of two profiles resolving one
//     package to two versions. That is internal/plan's, and see ByID for why.
//   - It does not compute or verify a Fingerprint. That is T049's
//     fingerprint.go. This file defines the shape so that arriving is an
//     implementation and not a schema change.
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
// before renaming the new tree into place (gate R3). It lives here, in the
// record, rather than in internal/apply, because it is a property of the
// RECORD that the aside is deterministic and a sibling: it is what makes
// Entry.RemovablePaths a closed two-element set instead of a glob, and
// therefore what makes FR-028 provable. internal/apply's swap must use this
// constant; a second literal in that package is how the two drift apart and
// leave an orphaned `.amctl-old` tree nothing will ever remove.
//
// The leading dot keeps an interrupted swap's leftovers out of an agent's
// scan of its own skills directory.
const AsideSuffix = ".amctl-old"

// Kind is a lockfile entry's kind. The values are the frozen contract's enum
// (`plugin|skill`). Only `skill` is installable today — gate R2 found that
// claude-code plugins live in agent-owned state that cannot be swapped by
// rename or pruned without touching keys amctl did not write — but the record
// carries the full enum so a record written by a later build stays readable.
type Kind string

// The contract's kind values.
const (
	KindSkill  Kind = "skill"
	KindPlugin Kind = "plugin"
)

// IsValid reports whether k is one of the contract's kinds.
func (k Kind) IsValid() bool { return k == KindSkill || k == KindPlugin }

// Target is one agent's directory convention. The values are the frozen
// contract's enum (`claude-code|codex`); which of them amctl can actually WRITE
// is a separate, client-side decision — R2 ships claude-code only, and
// layout.NewCodex refuses with ErrR2Unresolved until it is measured. This type
// is the contract's vocabulary, not the shipped set, because a record written by
// a later build must still be readable by this one.
//
// `agents-md` was a third value and is gone from the contract: one shared
// repository-root markdown file cannot be installed per package, marked with a
// package and version, given a distinct directory per publisher, swapped
// atomically or pruned by path. A record that still names it is a record from a
// build that predates the removal, which is what IsValid's rejection is for.
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
//
// The record stores a typed digest rather than a string on the argument
// cache.Digest's own doc comment makes: the same value reaches this CLI in two
// encodings, and a field that can hold "either of those" compares unequal for
// two spellings of one value. FR-014's check is the last line of defence, and
// a check that silently never matches looks exactly like one that silently
// always matches. So the encoding lives at the JSON boundary — here — and
// nothing in between holds a string.
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

// UnmarshalJSON reads the lockfile encoding and nothing else. An uppercase,
// base64 or bare-hex spelling is refused rather than folded: every byte of
// this file was written by amctl, so a spelling amctl does not emit means the
// file was edited or corrupted, and guessing at it is how a digest check stops
// being a check.
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

// FileMark is one installed file's account in a Fingerprint. Shaped by gate
// R4, which measured every candidate against a fifteen-mutation matrix; this
// is the only one with zero work-destroying misses.
//
// Nothing time-based is stored, and this is the rule most likely to be
// "optimised" back in. No mtime: measured on this kernel, a real same-size
// edit made within a millisecond of the install write is byte-identical in
// mtime, and reported unmodified, 99% of the time — which is exactly the
// window a post-sync hook or a `sed -i` one-liner lands in — and any
// mtime-preserving restore (`tar -x`, `rsync -a`, `cp -p`) has no window at
// all. No ctime: `syscall.Stat_t` has no Ctim on darwin, so it is not merely
// inadvisable but does not compile. No inode
// number: the atomic swap replaces the destination by rename, so the inode
// changes on every install by design and would report every re-install as a
// modification.
type FileMark struct {
	// SHA256 is 64 lowercase hex characters of the file's bytes. This is the
	// detector; everything else in this struct is a lesser job.
	SHA256 string `json:"h"`

	// Size is for diagnostics ("grew by N bytes" without re-reading) and as a
	// cheap short-circuit. A differing size is sufficient for `modified`; a
	// matching size is NEVER sufficient for `unmodified`.
	Size int64 `json:"s"`

	// Mode is permission bits only, masked 0o777, read with lstat from the
	// file AS ACTUALLY WRITTEN — never from the archive header. Measured:
	// under umask 0027 a requested 0755 lands as 0750, so recording the
	// header's mode reports a mode conflict on every executable file for
	// anyone whose umask is not 022, on the very next sync. setuid, setgid and
	// sticky are refused by the extractor, so any of those bits present at
	// check time is a modification and not a mode to be matched.
	Mode uint32 `json:"m"`

	// Kind comes from lstat, so a symlink reports as a symlink. The extractor
	// refuses symlink members, so this is FileKindRegular for everything amctl
	// installs and any other value at check time is by construction a
	// post-install change. A kind change is reported INSTEAD of opening the
	// path: hashing through the link is R4's missed mutation, and overwriting
	// through it is the FR-020 violation FR-020 exists to prevent.
	Kind string `json:"k"`
}

// The lstat kinds a FileMark may carry. Only FileKindRegular is ever written
// at install; the other two exist so that a check-time verdict has a name and
// so that a hand-edited record naming one is refused rather than misread.
const (
	FileKindRegular = "f"
	FileKindSymlink = "l"
	FileKindOther   = "o"
)

// FingerprintAlgo is the algorithm string this build's fingerprint is written
// with. T049 owns producing and verifying it; this constant fixes its name so
// that the seam below is real rather than aspirational.
const FingerprintAlgo = "sha256-tree-v1"

// Fingerprint is the record's account of one installed entry's tree, taken at
// install. It answers exactly one question — has anything under this entry's
// root changed since amctl wrote it (FR-029) — and it answers it by content,
// never by timestamp.
//
// Files and Dirs together are a CLOSED SET over the entry root: a path on disk
// and absent here is `added`, a path here and absent on disk is `missing`, and
// both are modifications. That closure holds only for a root amctl created for
// this entry, because prune removes an entry by removing that root
// recursively, so an unrecorded file inside it is work a legitimate prune will
// delete. For a single-file target the root IS the file, Dirs is empty, and
// the parent's other contents are none of amctl's business. Getting that scope
// backwards turns SC-004 into a false-conflict generator.
//
// Algo is the migration seam, and it fails closed. A KNOWN OLDER algorithm
// must be verified with that algorithm's own verifier — keep the old one when
// the format changes, or a CLI upgrade turns every installed entry into a
// conflict. An ABSENT or UNRECOGNISED algorithm must refuse: report the entry
// as unverifiable, name `--force`, and exit with FR-036's "refusal the user
// can fix" code. Assuming unmodified on a fingerprint that cannot be verified
// is the direction that deletes somebody's work, so it is not available.
//
// There is deliberately no root hash alongside Files. It is derivable from
// Files, it saves nothing (computing the current value still means hashing
// every file), and it introduces a second value that can disagree with the
// first. Conflicts are reported per file, naming what changed about each,
// because `--force` has to name what it is about to destroy.
type Fingerprint struct {
	// Algo names the algorithm. See the migration-seam paragraph above.
	Algo string `json:"algo"`

	// Files is keyed by entry-root-relative, slash-separated path. Never
	// absolute: the entry already carries its absolute destination, and
	// duplicating it here gives two things that can disagree. Slashes so the
	// key is separator-independent.
	Files map[string]FileMark `json:"files,omitempty"`

	// Dirs is keyed the same way; the value is permission bits only.
	// Directories are in the closed set because R4 measured two mutations —
	// an added empty directory and a directory chmod — that every
	// files-only candidate missed.
	Dirs map[string]uint32 `json:"dirs,omitempty"`
}

// IsZero reports whether f was never taken. Used by encoding/json's omitzero
// so an entry recorded before T049 lands does not serialise an empty object.
func (f Fingerprint) IsZero() bool {
	return f.Algo == "" && len(f.Files) == 0 && len(f.Dirs) == 0
}

// Entry is one installed package, for one target, in one profile.
type Entry struct {
	// ID is `namespace/name`, exactly two non-empty segments. NOT
	// `publisher/name`, despite what the frozen schema's description says: a
	// publisher slug is itself two segments and cannot fit in one path
	// segment, so an id joined from one would build a bundle URL with three
	// segments where the contract has two.
	ID string `json:"id"`

	// Version is the version the hub resolved and amctl installed, verbatim.
	Version string `json:"version"`

	// Digest is the bundle digest that was verified before any byte reached
	// the tree (FR-014).
	Digest Digest `json:"digest"`

	// Kind and Target say what was installed and under whose convention.
	// Target is per entry as well as per profile because FR-030 has to remove
	// what a now-disabled target's entries wrote, and the profile's target
	// list alone cannot say which files those were.
	Kind   Kind   `json:"kind"`
	Target Target `json:"target"`

	// Dest is the absolute path amctl wrote — the entry's root. This is the
	// "paths, not patterns" field: it, and it alone, is what prune consults.
	Dest string `json:"dest"`

	// Fingerprint is the install-time account of Dest's contents (FR-029).
	// Absent means unverifiable, which means a refusal naming --force, never
	// an assumption of unmodified.
	Fingerprint Fingerprint `json:"fingerprint,omitzero"`
}

// RemovablePaths is the COMPLETE set of paths amctl may remove for this entry,
// and the reason FR-028 needs no glob and no second field.
//
// Dest is what was installed. Dest+AsideSuffix is what an interrupted swap
// leaves behind: gate R3 fixed the aside as a deterministic sibling for
// exactly this reason, so the leftover of a crash is a name this function can
// compute rather than a name only a directory listing could find. A random
// aside token (`dest.old-a1b2c3`) would force a glob over a directory shared
// with the user's own files, and a glob is how amctl would delete a
// hand-written skill.
//
// The two paths are candidates, not obligations: a caller removes only what
// exists, and only after ClaimantsOf reports no other profile still claims
// Dest.
func (e Entry) RemovablePaths() []string {
	return []string{e.Dest, e.Dest + AsideSuffix}
}

// Profile is one synced profile's installation, as of the revision named here.
type Profile struct {
	// Slug is the profile's slug.
	Slug string `json:"slug"`

	// Revision is the exact revision installed, resolved to a number
	// (FR-013). `head` is never stored: it is a request, not a state, and a
	// record saying `head` cannot tell drift from change on the next run.
	Revision int `json:"revision"`

	// InstalledAt is when this revision was installed. It is provenance for
	// `status` and it is never consulted by modification detection — the
	// no-timestamps rule on FileMark is about the DETECTOR, and this is not
	// it.
	//
	// Set this only when Revision or Entries actually change, never on every
	// save. Refreshing it on an unchanged sync would make the record's bytes
	// differ on every run, which is a filesystem modification FR-025 forbids
	// and which would defeat Save's identical-bytes short circuit.
	InstalledAt time.Time `json:"installedAt"`

	// Targets is the set of targets in force when this profile was installed,
	// which is what lets a later run notice one was disabled (FR-030). It is
	// the intersection the CLI actually wrote, not the lockfile's advisory
	// list.
	Targets []Target `json:"targets"`

	// Entries is what was installed for this profile.
	Entries []Entry `json:"entries"`
}

// Record is one hub's installation record: the contents of one state.json.
type Record struct {
	// SchemaVersion is stamped on write and checked on read.
	SchemaVersion int `json:"schemaVersion"`

	// Hub is the canonical hub URL this record belongs to, in the exact form
	// internal/cmd produced. A record is refused against a different hub
	// (Load), because applying one hub's account of what may be removed to
	// another hub's tree is a deletion with no evidence behind it.
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

// ByID is every entry for a package id, across profiles.
//
// This exists for reporting, not for deciding. FR-012 — refuse a set of
// profiles that resolve one package to two versions, before writing anything,
// naming both profiles and both versions — is internal/plan's, because at the
// moment it must fire there is nothing in the record to consult: neither
// version has been installed. The record's contribution is only that it can
// name what IS installed, per profile, when the conflict is reported.
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

// ClaimantsOf is every entry that installed to dest.
//
// More than one is LEGITIMATE and prune must consult this before removing
// anything: two profiles may both include the same package at the same
// version, in which case both resolve to one destination and only one
// directory exists. Removing dest because the profile being pruned no longer
// claims it would delete a package another profile still wants — the record
// would then be wrong in the unrecoverable direction, since the next sync
// re-installs it but anything the user changed inside it is gone.
//
// FR-012 is what keeps the two versions from differing; this is what keeps the
// one version from being removed twice over.
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

// RemoveProfile drops a profile and reports whether it was there. It removes
// nothing from the filesystem: dropping the record before pruning the files it
// accounts for is how an installed tree becomes unremovable, since FR-028
// forbids the directory listing that would be the only way to find it again.
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

// normalize sorts the record into one canonical order so that an unchanged
// sync encodes to byte-identical output and Save can decline to write at all
// (FR-025). It is not cosmetic: without it, map iteration or lockfile ordering
// would rewrite the file on every run and "no filesystem modification" would
// be false of the record while being true of the tree.
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

// ErrInvalid marks a record whose contents this build refuses to act on. It is
// returned for a record that decoded cleanly but says something amctl could
// not have written, which — since amctl wrote every byte of this file — means
// the file was edited or corrupted. Refusing is the recoverable direction:
// treating it as empty means "prune nothing, reinstall everything", and
// treating it as valid means removing paths on the strength of a string
// somebody else chose.
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
	// A revision of 0 is not a small revision, it is `head` never resolved:
	// the contract's revision is an integer >= 1. Storing 0 would make
	// FR-013's "tell drift from change" answer "I don't know".
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
		// Two entries in ONE profile sharing a destination is a bug — FR-023
		// gives distinct directories per namespace/name — and it would make
		// the removable set ambiguous. Across profiles it is legitimate; see
		// ClaimantsOf.
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

// validateID enforces `namespace/name`, exactly two non-empty segments.
// CLI-CONTRACT.md: the bundle path's `{publisher}` parameter is the namespace,
// and an id that is not two segments must be an error rather than silently
// joined or truncated, because either repair builds a URL for a different
// package than the one recorded.
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

// validateVersion guards a value that becomes a URL path segment. It is NOT
// version parsing: FR-009 forbids this CLI having an opinion on which of two
// versions is newer, and nothing here forms one.
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
	// A destination ending in the aside suffix is refused, and the reason is
	// not tidiness. Entry A at /x/foo has removable set {/x/foo,
	// /x/foo.amctl-old}; an entry B installed at /x/foo.amctl-old would be
	// inside A's removable set, so pruning A would delete a live install of B.
	// R3 makes this internal/layout's guarantee; it is cheap enough to also
	// make it impossible to record.
	if strings.HasSuffix(dest, AsideSuffix) {
		return fmt.Errorf("%w: entry %s destination %s ends in %s, which is the swap's aside name",
			ErrInvalid, id, dest, AsideSuffix)
	}
	return nil
}

// validate checks the fingerprint's shape, not its contents. Whether the
// recorded hashes still match the tree is T049's verifier; whether the keys
// are safe to join onto an absolute destination is this package's, because
// getting that wrong would let a hand-edited record send the verifier — and
// then `--force` — outside the entry root.
func (f Fingerprint) validate(id string) error {
	if f.IsZero() {
		// Absent is allowed and means unverifiable. It is not silently
		// unmodified: T049 refuses such an entry naming --force. Allowed
		// because an entry recorded before the fingerprint exists must still
		// be prunable, and a record that cannot be written cannot be pruned
		// from.
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

// validateFingerprintKey enforces R4's rule 1: keys are entry-root-relative,
// slash-separated and clean. `..`, an absolute key, a backslash and a NUL are
// all refused, because every key is eventually joined onto Entry.Dest.
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
