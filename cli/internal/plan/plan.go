package plan

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// DestFunc maps a package id and kind to the absolute destination path for one
// target. It is internal/layout's job, passed in rather than imported so this
// package stays pure: layout's constructors read CLAUDE_CONFIG_DIR and the OS
// home directory, and a plan that could do that would no longer be a function
// of its inputs.
//
// An error means the target refuses to route that entry — a reserved directory
// name, a dot-prefixed name, a plugin where the target supports skills only.
// It is a refusal, never a hint to sanitise: a name amctl quietly rewrote
// would not match the record it later prunes against (FR-028).
type DestFunc func(id string, kind record.Kind) (string, error)

// Target is one agent target as seen by THIS build.
//
// The two failure shapes are deliberately distinct, and conflating them is the
// specific mistake this type exists to prevent. A target the PROFILE turned
// off produces removals (FR-030) and is a normal outcome. A target the CLIENT
// cannot write produces a refusal (research gate R2): `codex`'s constructor
// returns an error wrapping layout.ErrR2Unresolved because its on-disk layout
// is documented but unobserved, and writing to a path the agent does not read
// reports success and does nothing. Telling a user pinned to codex that their
// profile excluded it would send them to fix the wrong thing.
type Target struct {
	// Name is the target's contract spelling, e.g. "claude-code".
	Name record.Target

	// Dest routes an entry. Required when Err is nil.
	Dest DestFunc

	// Err is non-nil when this build cannot write the target. It is carried
	// through to the conflict and joined into [Plan.ConflictError], so a caller
	// can still match errors.Is(err, layout.ErrR2Unresolved) rather than
	// matching on a message.
	Err error

	// Withdrawn is the THIRD outcome, and the split from Err is the decision
	// this field exists to record: a target that is known, deliberately never
	// going to be implemented, and therefore REPORTED rather than refused.
	//
	// Err is a target awaiting a MEASUREMENT — codex has a plausible layout and
	// writing to the wrong one of two candidate directories would report success
	// and do nothing — so it refuses, and the user can fix it by turning codex
	// off. Withdrawn is a target awaiting a DESIGN that will not come, on both
	// sides, and there is nothing the user can do about it: the target list is
	// the hub's, and `agents-md` is the lockfile schema's own example value. A
	// refusal there would make the seeded catalogue unsyncable over a value the
	// hub itself suggests, with no user-side fix. See internal/layout's
	// withdrawnTargets for the full argument.
	//
	// It is NOT a licence to install nothing and exit 0, which is the failure
	// gate R2 exists to prevent: a profile whose targets are ALL withdrawn or
	// unwritable has an empty writable set and is refused with
	// ConflictNoWritableTarget.
	Withdrawn error
}

// Op is what a plan does to one entry. It is finer-grained than the bucket the
// change lands in: see [Plan].
type Op string

// The five operations. Remove is a [Removal], not a [Change], because a
// removal carries the record's removable-path set and its retention list and a
// change does not.
const (
	OpAdd       Op = "add"
	OpUpgrade   Op = "upgrade"
	OpDowngrade Op = "downgrade"

	// OpReplace is a write whose version did not move: the hub republished the
	// same version with different bytes, or the two versions order equal but
	// differ textually (build metadata, `1.0` against `1.0.0`), or the comparer
	// could form no opinion. The digest differs, so the entry must be written;
	// "upgrade" and "downgrade" would both be claims about a direction nobody
	// established.
	OpReplace Op = "replace"

	OpUnchanged Op = "unchanged"
)

// Installed is what the record says is on disk for an entry, as the `from`
// side of a change or the subject of a removal.
type Installed struct {
	Version string
	Digest  record.Digest

	// Fingerprinted reports whether the recorded entry carries an R4
	// fingerprint, i.e. whether internal/apply can tell a modified path from
	// an untouched one for it. False means unverifiable — which is NOT the same
	// as unmodified, and must be refused naming --force rather than overwritten.
	Fingerprinted bool
}

// Change is one entry a sync would write, or would leave exactly as it is.
type Change struct {
	Op      Op
	Profile string
	Target  record.Target
	ID      string
	Kind    record.Kind

	// Dest is the absolute destination the target routed this entry to. The
	// paths a later prune may remove for it are record.Entry.RemovablePaths(),
	// derived from this one value and nothing else.
	Dest string

	// Version and Digest are the hub's resolved answer for this revision. The
	// digest is 32 bytes, not a string, because comparing formatted digests is
	// how a digest check silently stops being one.
	Version string
	Digest  record.Digest

	// Resolution is the hub's account of HOW it resolved: latest, pinned or
	// range. Reporting only — FR-009 forbids re-deriving a version from it.
	Resolution string

	// Verdict is the scan verdict the hub recorded: clean or flagged. A flagged
	// entry present in `entries` rather than `skipped` resolved under an
	// override or a warn-with-override gate; the hub decided that, not this CLI.
	Verdict string

	// Signature is the source's signature provenance, absent when it carried
	// none. Verified is false until Sigstore verification ships, so a false
	// value MUST NOT be rendered as a pass, as a tick, or as "unsigned" — none
	// of those is a fact that has been checked.
	Signature *Signature

	// From is what the record claims is installed. Nil exactly when Op is
	// OpAdd.
	From *Installed

	// Direction is the reporting-side label produced by direction.go. It is
	// DirectionNone for an add.
	Direction Direction
}

// Signature mirrors the lockfile's optional signature block. The lockfile's
// `verified` is itself optional, and absent and false mean the same thing here:
// nothing has been checked. Sigstore verification has not shipped, so
// Verified is false for every entry today, and the schema's instruction is
// explicit — never render a false value as a pass. Not a tick, and not the word
// "unsigned" either: neither is a fact anyone established.
type Signature struct {
	Ref      string
	Verified bool
}

// RemoveReason says why an installed entry is going away. The two reasons are
// reported differently and must not be merged: one is the profile's content
// changing, the other is a target being switched off (FR-030).
type RemoveReason string

const (
	// RemoveLeftProfile: the profile's lockfile no longer lists the package, or
	// the hub now refuses to serve the version (FR-027).
	RemoveLeftProfile RemoveReason = "no-longer-in-profile"

	// RemoveTargetDisabled: the profile no longer enables the target the entry
	// was installed under (FR-030).
	RemoveTargetDisabled RemoveReason = "target-disabled"

	// RemoveRelocated: the same package under the same target now routes to a
	// different path — a layout change, e.g. disambiguation kicking in once a
	// second publisher takes the same name. Distinct from the other two because
	// nothing left the profile and no target was switched off: the entry is
	// being re-installed elsewhere in this same plan, and the old directory
	// would otherwise be orphaned while the run reported success.
	RemoveRelocated RemoveReason = "relocated"
)

// Claim is one profile's stake in a package: who wants it, at what version,
// under which target. Used both for FR-012's "name both profiles and both
// versions" and for a removal's retention list.
type Claim struct {
	Profile string
	Target  record.Target
	ID      string
	Version string
}

// Removal is one recorded entry a sync would drop.
type Removal struct {
	Profile string
	Target  record.Target
	ID      string
	Kind    record.Kind
	Version string
	Dest    string
	Reason  RemoveReason

	// Paths is exactly record.Entry.RemovablePaths(): the destination and its
	// `.amctl-old` sibling, two literal names. FR-028 holds by construction
	// because this is a list and never a pattern — a glob over a directory the
	// CLI does not own is how you delete somebody's hand-written skill.
	Paths []string

	// RetainedBy names the other stakes in this same destination that survive
	// the plan: another profile's record row that is not itself being removed,
	// or another profile in this very run that installs the same destination.
	// Non-empty means drop the record row and touch NOTHING on disk — the
	// directory is one directory and another profile still wants it.
	RetainedBy []Claim

	// Fingerprinted mirrors [Installed].Fingerprinted for the entry being
	// removed.
	Fingerprinted bool
}

// RemovesFromDisk reports whether this removal may touch the filesystem.
func (r Removal) RemovesFromDisk() bool { return len(r.RetainedBy) == 0 }

// ConflictKind is why a plan refuses. Every kind here is detectable without
// touching the filesystem; the modified-path conflict of FR-029 is not, and
// lives in internal/apply.
type ConflictKind string

const (
	// ConflictVersionSplit is FR-012: two profiles resolve one package to two
	// different versions. They would land in one directory, so the second write
	// would silently define what the first profile got.
	ConflictVersionSplit ConflictKind = "version-split"

	// ConflictDestCollision is two DIFFERENT package ids routed to one
	// destination. FR-023 requires colliding names across publishers to land in
	// distinct directories, so this is a layout defect rather than a user error
	// — but it is refused here because the record keys removals by destination
	// and would otherwise attribute one directory to two packages.
	ConflictDestCollision ConflictKind = "destination-collision"

	// ConflictTargetUnwritable is a target the profile enables and this build
	// cannot write: research gate R2 is open for it. Err wraps
	// layout.ErrR2Unresolved. Warn-and-continue is exactly the failure the gate
	// exists to stop, because a target that installs nothing while the command
	// exits 0 reports success.
	ConflictTargetUnwritable ConflictKind = "target-unwritable"

	// ConflictTargetUnknown is a target this build has never heard of. The
	// contract's enum still carries `agents-md`, which no longer has an
	// implementation, and a newer hub may add more. Unknown is refused rather
	// than ignored for the same reason as unwritable: silence looks like success.
	ConflictTargetUnknown ConflictKind = "target-unknown"

	// ConflictNoWritableTarget is a profile that enabled targets and none of
	// them survived: every one was unknown, gated or withdrawn. It exists
	// because a withdrawn target is reported rather than refused, which without
	// this check would let a profile naming only withdrawn targets install
	// nothing and exit 0 — the exact warn-and-continue outcome gate R2 was
	// opened to stop.
	ConflictNoWritableTarget ConflictKind = "no-writable-target"

	// ConflictUnroutable is an entry the target refused to route, or one whose
	// id, kind or digest is unusable: an id that is not exactly two non-empty
	// segments, a kind outside skill|plugin, a digest that is not
	// sha256:<64 hex>. Refused, never repaired.
	ConflictUnroutable ConflictKind = "unroutable-entry"
)

// Conflict is one reason the plan must be refused before anything is written.
type Conflict struct {
	Kind ConflictKind

	// ID is the package involved, empty for the two target-level kinds.
	ID string

	// Target is set for target-level kinds and for a destination collision.
	Target record.Target

	// Dest is set for a destination collision.
	Dest string

	// Claims is every profile stake involved, sorted. FR-012 requires the
	// report to name both profiles and both versions, so this is the payload
	// and not a convenience.
	Claims []Claim

	// Err is the underlying error where there was one — a target constructor's
	// or a DestFunc's. Preserved so a caller can classify by errors.Is rather
	// than by string match.
	Err error

	// Installed is what the record says is on this machine for the package, per
	// profile, at the moment the conflict is raised. For FR-012 that is the
	// context a user needs and nothing else can supply: neither of the two
	// disagreeing versions has been installed yet, so the record can only say
	// what is there now.
	Installed []Claim

	// Detail is extra human text where no error carried it.
	Detail string
}

// String is the sentence a refusal prints. It names every party, because a
// refusal that does not say which two profiles disagree cannot be acted on.
func (c Conflict) String() string {
	switch c.Kind {
	case ConflictVersionSplit:
		return fmt.Sprintf("%s is resolved to %d different versions by the profiles being synced: %s",
			c.ID, len(distinctVersions(c.Claims)), describeClaims(c.Claims))
	case ConflictDestCollision:
		return fmt.Sprintf("%s would be installed to one directory by %d different packages: %s (%s)",
			c.Dest, len(distinctIDs(c.Claims)), describeClaims(c.Claims), c.Target)
	case ConflictTargetUnwritable:
		return fmt.Sprintf("target %s is enabled by %s but this build cannot write it: %v",
			c.Target, describeProfiles(c.Claims), c.Err)
	case ConflictTargetUnknown:
		return fmt.Sprintf("target %s is enabled by %s and is not a target this build knows; "+
			"refusing rather than skipping, because a target that installs nothing still exits 0",
			c.Target, describeProfiles(c.Claims))
	case ConflictNoWritableTarget:
		return fmt.Sprintf("profile %s enables %s and this build can write none of them, so a sync would "+
			"install nothing and still exit 0", describeProfiles(c.Claims), describeTargets(c.Claims))
	case ConflictUnroutable:
		detail := c.Detail
		if c.Err != nil {
			detail = c.Err.Error()
		}
		return fmt.Sprintf("%s cannot be installed under target %s: %s", c.ID, c.Target, detail)
	default:
		return fmt.Sprintf("%s: %s", c.Kind, c.ID)
	}
}

// Plan is what a sync would do. It is the whole answer: a caller needs no
// second query and must make no second decision.
//
// The buckets are the four FR-031 requires --dry-run to report, plus the three
// that are not actions. Upgrade holds OpUpgrade AND OpReplace: a replacement
// whose direction did not move forward is still a write, and filing it under
// Downgrade would raise a rollback alarm about something that did not roll
// back. [Change.Op] is the precise answer; the bucket is the printed heading.
type Plan struct {
	Add       []Change
	Upgrade   []Change
	Downgrade []Change
	Remove    []Removal
	Conflicts []Conflict
	Skipped   []Skip

	// Unchanged is not one of the six sets the task line names, and it is here
	// because dropping it makes an entry already at the locked version
	// indistinguishable from an entry the lockfile never mentioned. FR-025's
	// idempotence is the claim "the second run's Add, Upgrade, Downgrade and
	// Remove are all empty AND Unchanged accounts for every entry", which
	// cannot be stated without it.
	Unchanged []Change
}

// Refuses reports whether the plan must not be applied. FR-012 requires the
// refusal to happen before anything is written, so a caller checks this before
// it stages a single byte.
func (p Plan) Refuses() bool { return len(p.Conflicts) > 0 }

// ConflictError joins every conflict into one error, preserving the underlying
// errors so errors.Is still matches layout.ErrR2Unresolved through it. Nil
// when there are no conflicts.
func (p Plan) ConflictError() error {
	if len(p.Conflicts) == 0 {
		return nil
	}
	errs := make([]error, 0, len(p.Conflicts))
	for i := range p.Conflicts {
		c := &p.Conflicts[i]
		if c.Err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.String(), c.Err))
			continue
		}
		errs = append(errs, errors.New(c.String()))
	}
	return errors.Join(errs...)
}

// ChangeCount is how many entries the plan would write or remove. It excludes
// Unchanged and Skipped by definition, and is what selects between FR-036's
// two success exit codes.
func (p Plan) ChangeCount() int {
	return len(p.Add) + len(p.Upgrade) + len(p.Downgrade) + len(p.Remove)
}

// IsNoOp reports a plan that would change nothing. A refusing plan is not a
// no-op: it has something to say.
func (p Plan) IsNoOp() bool { return p.ChangeCount() == 0 && !p.Refuses() }

// Writes is every entry a sync would write — Add, Upgrade and Downgrade — for
// a caller that stages them all the same way and does not care which heading an
// entry printed under.
//
// It is re-sorted rather than concatenated, and that is not tidiness. Which
// bucket an entry lands in depends on the version comparer, which is reporting;
// concatenating the buckets would therefore make the ORDER OF WORK depend on
// the comparer, and FR-009's whole claim is that it cannot. The sort key is the
// same one the buckets use: target, then package id, then profile.
func (p Plan) Writes() []Change {
	out := make([]Change, 0, len(p.Add)+len(p.Upgrade)+len(p.Downgrade))
	out = append(out, p.Add...)
	out = append(out, p.Upgrade...)
	out = append(out, p.Downgrade...)
	slices.SortFunc(out, changeOrder)
	return out
}

func describeClaims(claims []Claim) string {
	parts := make([]string, 0, len(claims))
	for _, c := range claims {
		parts = append(parts, fmt.Sprintf("%s wants %s@%s", c.Profile, c.ID, c.Version))
	}
	return strings.Join(parts, "; ")
}

func describeProfiles(claims []Claim) string {
	seen := make(map[string]struct{}, len(claims))
	parts := make([]string, 0, len(claims))
	for _, c := range claims {
		if _, dup := seen[c.Profile]; dup {
			continue
		}
		seen[c.Profile] = struct{}{}
		parts = append(parts, c.Profile)
	}
	if len(parts) == 0 {
		return "the profiles being synced"
	}
	return strings.Join(parts, ", ")
}

func describeTargets(claims []Claim) string {
	seen := make(map[record.Target]struct{}, len(claims))
	parts := make([]string, 0, len(claims))
	for _, c := range claims {
		if _, dup := seen[c.Target]; dup {
			continue
		}
		seen[c.Target] = struct{}{}
		parts = append(parts, string(c.Target))
	}
	if len(parts) == 0 {
		return "no target"
	}
	return strings.Join(parts, ", ")
}

func distinctVersions(claims []Claim) []string {
	return distinct(claims, func(c Claim) string { return c.Version })
}

func distinctIDs(claims []Claim) []string {
	return distinct(claims, func(c Claim) string { return c.ID })
}

func distinct(claims []Claim, key func(Claim) string) []string {
	seen := make(map[string]struct{}, len(claims))
	out := make([]string, 0, len(claims))
	for _, c := range claims {
		k := key(c)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}
