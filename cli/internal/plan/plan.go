package plan

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// DestFunc maps a package id and kind to a destination path. It is
// internal/layout's job passed in rather than imported, so this package
// stays pure and never reads CLAUDE_CONFIG_DIR or the OS home itself. An
// error means the target refuses the entry — a refusal, never a hint to
// sanitise: a rewritten name wouldn't match the record it later prunes against.
type DestFunc func(id string, kind record.Kind) (string, error)

// Target is one agent target as seen by this build. A target the profile
// turned off produces removals (normal); a target the client cannot write
// produces a refusal (e.g. codex, whose layout is documented but unobserved) —
// reporting it as "excluded" instead would send the user to fix the wrong thing.
type Target struct {
	// Name is the target's contract spelling, e.g. "claude-code".
	Name record.Target

	// Dest routes an entry. Required when Err is nil.
	Dest DestFunc

	// Err is non-nil when this build cannot write the target; carried through
	// to the conflict so a caller can errors.Is(err, layout.ErrR2Unresolved).
	Err error

	// Withdrawn: a known target deliberately never implemented (see
	// internal/layout's withdrawnTargets), reported rather than refused. Not
	// a licence to install nothing and exit 0 — an all-withdrawn-or-unwritable
	// profile is refused with ConflictNoWritableTarget.
	Withdrawn error
}

// Op is what a plan does to one entry. It is finer-grained than the bucket the
// change lands in: see [Plan].
type Op string

// The five operations. Remove is a [Removal], not a [Change]: it carries a
// removable-path set and a retention list that a change does not.
const (
	OpAdd       Op = "add"
	OpUpgrade   Op = "upgrade"
	OpDowngrade Op = "downgrade"

	// OpReplace: version didn't move (republish, textually-differing equal
	// versions, or no comparer opinion) but the digest differs, so it must be
	// written — "upgrade"/"downgrade" would claim a direction nobody established.
	OpReplace Op = "replace"

	OpUnchanged Op = "unchanged"
)

// Installed is what the record says is on disk: the `from` side of a change
// or the subject of a removal.
type Installed struct {
	Version string
	Digest  record.Digest

	// Fingerprinted: false means unverifiable (not unmodified) and must be
	// refused naming --force rather than silently overwritten.
	Fingerprinted bool
}

// Change is one entry a sync would write, or would leave exactly as it is.
type Change struct {
	Op      Op
	Profile string
	Target  record.Target
	ID      string
	Kind    record.Kind

	// Dest is the routed destination; a later prune removes
	// record.Entry.RemovablePaths(), derived from this value alone.
	Dest string

	Version string        // the hub's resolved version for this revision
	Digest  record.Digest // 32 bytes, not a string — comparing formatted digests stops being a digest check

	Resolution string // how the hub resolved (latest/pinned/range); reporting only

	// Verdict: clean or flagged. A flagged entry in `entries` rather than
	// `skipped` resolved under an override or warn-with-override gate.
	Verdict string

	// Signature is absent when the source carried none. Verified is false
	// until Sigstore ships — never render false as a pass, tick, or "unsigned".
	Signature *Signature

	From *Installed // what the record claims is installed; nil exactly when Op is OpAdd

	Direction Direction // reporting-side label from direction.go; DirectionNone for an add
}

// Signature mirrors the lockfile's optional signature block; absent and
// false mean the same thing (nothing checked). Sigstore is unshipped, so
// Verified is false for every entry today — never render it as a pass or tick.
type Signature struct {
	Ref      string
	Verified bool
}

// RemoveReason: the two main reasons are reported differently and must not
// be merged — one is the profile's content changing, the other a target off.
type RemoveReason string

const (
	RemoveLeftProfile    RemoveReason = "no-longer-in-profile" // lockfile no longer lists it, or hub refuses the version
	RemoveTargetDisabled RemoveReason = "target-disabled"      // profile no longer enables this target

	// RemoveRelocated: same package/target, new path (e.g. disambiguation on
	// a name clash) — the entry is reinstalled elsewhere in this plan, so the
	// old directory would be orphaned without an explicit removal.
	RemoveRelocated RemoveReason = "relocated"
)

// Claim is one profile's stake in a package, used both for a version-split
// conflict (naming both profiles and versions) and a removal's retention list.
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

	// Paths is exactly record.Entry.RemovablePaths(): two literal names,
	// never a pattern — a glob over a CLI-unowned dir deletes a hand-written skill.
	Paths []string

	// RetainedBy: non-empty means another stake survives, so drop the record
	// row and touch NOTHING on disk.
	RetainedBy []Claim

	Fingerprinted bool // mirrors Installed.Fingerprinted for the entry being removed
}

// RemovesFromDisk reports whether this removal may touch the filesystem.
func (r Removal) RemovesFromDisk() bool { return len(r.RetainedBy) == 0 }

// ConflictKind is why a plan refuses. Every kind here is detectable without
// touching the filesystem; the modified-path conflict is not, and lives in internal/apply.
type ConflictKind string

const (
	// ConflictVersionSplit: two profiles resolve one package to two versions
	// that would land in one directory, so the second write would silently win.
	ConflictVersionSplit ConflictKind = "version-split"

	// ConflictDestCollision: two package ids routed to one destination — a
	// layout defect, refused since the record keys removals by destination.
	ConflictDestCollision ConflictKind = "destination-collision"

	// ConflictTargetUnwritable: profile enables a target this build can't
	// write (Err wraps layout.ErrR2Unresolved) — refused rather than
	// warn-and-continue, since installing nothing while exiting 0 reports success.
	ConflictTargetUnwritable ConflictKind = "target-unwritable"

	// ConflictTargetUnknown: a target this build has never heard of (the
	// contract's enum still carries `agents-md`) — refused, not ignored, for
	// the same reason as unwritable.
	ConflictTargetUnknown ConflictKind = "target-unknown"

	// ConflictNoWritableTarget: every target a profile enabled was unknown,
	// gated or withdrawn — without this, an all-withdrawn profile installs
	// nothing and exits 0.
	ConflictNoWritableTarget ConflictKind = "no-writable-target"

	// ConflictUnroutable: target refused the entry, or its id/kind/digest is
	// unusable. Refused, never repaired.
	ConflictUnroutable ConflictKind = "unroutable-entry"
)

// Conflict is one reason the plan must be refused before anything is written.
type Conflict struct {
	Kind ConflictKind

	ID     string        // the package involved; empty for the two target-level kinds
	Target record.Target // set for target-level kinds and a destination collision
	Dest   string        // set for a destination collision

	Claims []Claim // every profile stake, sorted; the payload, not a convenience

	Err error // underlying error, if any, preserved so a caller can errors.Is rather than string-match

	// Installed: what the record says is on this machine, per profile, at
	// the moment raised — neither disagreeing version is installed yet.
	Installed []Claim

	Detail string // extra human text where no error carried it
}

// String names every party: a refusal that doesn't say who disagrees can't be acted on.
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

// Plan is what a sync would do: the whole answer, needing no second query.
//
// Upgrade holds OpUpgrade and OpReplace: a non-forward-moving replacement is
// still a write, and filing it under Downgrade would raise a false rollback
// alarm. [Change.Op] is the precise answer; the bucket is the printed heading.
type Plan struct {
	Add       []Change
	Upgrade   []Change
	Downgrade []Change
	Remove    []Removal
	Conflicts []Conflict
	Skipped   []Skip

	// Unchanged: without it, an entry at the locked version is
	// indistinguishable from one the lockfile never mentioned — idempotence
	// needs it to state "Add/Upgrade/Downgrade/Remove empty, Unchanged accounts for everything".
	Unchanged []Change
}

// Refuses reports whether the plan must not be applied, before a caller
// stages a single byte.
func (p Plan) Refuses() bool { return len(p.Conflicts) > 0 }

// ConflictError joins every conflict into one error, preserving errors.Is
// matching (e.g. layout.ErrR2Unresolved). Nil when there are no conflicts.
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

// ChangeCount excludes Unchanged and Skipped by definition, and selects
// between the two success exit codes.
func (p Plan) ChangeCount() int {
	return len(p.Add) + len(p.Upgrade) + len(p.Downgrade) + len(p.Remove)
}

// IsNoOp reports a plan that would change nothing. A refusing plan is not a
// no-op: it has something to say.
func (p Plan) IsNoOp() bool { return p.ChangeCount() == 0 && !p.Refuses() }

// Writes is Add+Upgrade+Downgrade for a caller that stages them all the same
// way. Re-sorted rather than concatenated: which bucket an entry lands in
// depends on the reporting-only comparer, and work order must not.
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
