package plan

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// DestFunc maps a package id and kind to a destination path, supplied by the
// caller so this package stays pure; an error refuses rather than sanitises.
type DestFunc func(id string, kind record.Kind) (string, error)

// Target is one agent target as seen by this build. A target the client
// cannot write produces a refusal, not a silent "excluded".
type Target struct {
	// Name is the target's contract spelling, e.g. "claude-code".
	Name record.Target

	// Dest routes an entry. Required when Err is nil.
	Dest DestFunc

	// Err is non-nil when this build cannot write the target; every entry
	// that would route to it becomes a [Skip] rather than a [Conflict].
	Err error

	// Withdrawn: a known target deliberately unimplemented, reported rather
	// than refused (does not license an all-withdrawn profile to exit 0).
	Withdrawn error
}

// Op is what a plan does to one entry, finer-grained than the bucket the change lands in.
type Op string

// The five operations. Remove is a [Removal], not a [Change].
const (
	OpAdd       Op = "add"
	OpUpgrade   Op = "upgrade"
	OpDowngrade Op = "downgrade"

	// OpReplace: version didn't move but the digest differs, so it must be
	// written - "upgrade"/"downgrade" would claim a direction nobody established.
	OpReplace Op = "replace"

	OpUnchanged Op = "unchanged"
)

// Installed is what the record says is on disk: the `from` side of a change or removal.
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

	// Dest is the routed destination; a later prune removes RemovablePaths(), derived from it.
	Dest string

	Version string        // the hub's resolved version for this revision
	Digest  record.Digest // 32 bytes, not a string — comparing formatted digests stops being a digest check

	Resolution string // how the hub resolved (latest/pinned/range); reporting only

	// Verdict: clean or flagged, under an override or warn-with-override gate.
	Verdict string

	// Signature is absent when the source carried none; Verified is false
	// until Sigstore ships - never render false as a pass or tick.
	Signature *Signature

	From *Installed // what the record claims is installed; nil exactly when Op is OpAdd

	Direction Direction // reporting-side label from direction.go; DirectionNone for an add
}

// Signature mirrors the lockfile's optional signature block.
type Signature struct {
	Ref      string
	Verified bool
}

// RemoveReason: the two main reasons are reported differently and must not
// be merged.
type RemoveReason string

const (
	RemoveLeftProfile    RemoveReason = "no-longer-in-profile" // lockfile no longer lists it, or hub refuses the version
	RemoveTargetDisabled RemoveReason = "target-disabled"      // profile no longer enables this target

	// RemoveRelocated: same package/target, new path; an explicit removal
	// avoids orphaning the old directory once it's reinstalled elsewhere.
	RemoveRelocated RemoveReason = "relocated"
)

// Claim is one profile's stake in a package: a version-split conflict, or a removal's retention list.
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
	// never a pattern - a glob over a CLI-unowned dir deletes a hand-written skill.
	Paths []string

	// RetainedBy: non-empty means another stake survives, so drop the row and touch nothing on disk.
	RetainedBy []Claim

	Fingerprinted bool // mirrors Installed.Fingerprinted for the entry being removed
}

// RemovesFromDisk reports whether this removal may touch the filesystem.
func (r Removal) RemovesFromDisk() bool { return len(r.RetainedBy) == 0 }

// ConflictKind is why a plan refuses; every kind here is detectable without touching the filesystem.
type ConflictKind string

const (
	// ConflictVersionSplit: two profiles resolve one package to two versions
	// that would land in one directory, so the second write would silently win.
	ConflictVersionSplit ConflictKind = "version-split"

	// ConflictDestCollision: two package ids routed to one destination.
	ConflictDestCollision ConflictKind = "destination-collision"

	// ConflictTargetUnknown is a target this build has never heard of.
	// Refused rather than ignored - silence would look like success.
	ConflictTargetUnknown ConflictKind = "target-unknown"

	// ConflictNoWritableTarget: every target a profile enabled was unknown,
	// gated or withdrawn.
	ConflictNoWritableTarget ConflictKind = "no-writable-target"

	// ConflictUnroutable is an entry whose id, kind or digest is unusable.
	// A [Skip] (not this) is a target refusing one KIND under it, since the profile's other entries still install.
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

	// Installed: what the record says is on this machine, per profile, at the moment raised.
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
// [Change.Op] is the precise answer; the bucket below is just the heading.
type Plan struct {
	Add       []Change
	Upgrade   []Change
	Downgrade []Change
	Remove    []Removal
	Conflicts []Conflict
	Skipped   []Skip

	// Unchanged: without it, a locked-version entry is indistinguishable
	// from one the lockfile never mentioned.
	Unchanged []Change
}

// Refuses reports whether the plan must not be applied.
func (p Plan) Refuses() bool { return len(p.Conflicts) > 0 }

// ConflictError joins every conflict into one error, preserving errors.Is matching. Nil when there are none.
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

// ChangeCount excludes Unchanged and Skipped, and selects the exit code.
func (p Plan) ChangeCount() int {
	return len(p.Add) + len(p.Upgrade) + len(p.Downgrade) + len(p.Remove)
}

// IsNoOp reports a plan that would change nothing; a refusing plan is not a no-op.
func (p Plan) IsNoOp() bool { return p.ChangeCount() == 0 && !p.Refuses() }

// Writes is Add+Upgrade+Downgrade, re-sorted rather than concatenated since
// bucket placement depends on the reporting-only comparer.
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
