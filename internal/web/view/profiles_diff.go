package view

import (
	"slices"
	"strconv"
)

// The "Show diff" panel's comparison (US5's revision history, extended).
//
// The lockfile is the durable record of what a revision resolved to, so the
// diff is computed from two of them rather than from a stored delta: there is
// no other source of truth to drift from.

// LockfileSnapshot is one revision's lockfile, reduced to what a diff
// compares. Keeping this separate from hub.RevisionLockfile is what makes
// DiffRevisions a pure function over plain data instead of one more consumer
// of the hub's wire shape.
type LockfileSnapshot struct {
	Revision      int
	Gate          string
	DefaultPolicy string
	Targets       []string
	Entries       []LockfileEntrySnapshot
	Skipped       []LockfileSkipSnapshot
}

// LockfileEntrySnapshot is one resolved package.
type LockfileEntrySnapshot struct {
	ID         string
	Version    string
	Resolution string
}

// LockfileSkipSnapshot is one excluded package and why.
type LockfileSkipSnapshot struct {
	ID     string
	Reason string
}

type AddedPackage struct {
	ID, Version, Resolution string
}

type RemovedPackage struct {
	ID, Version, Resolution string
}

// ChangedPackage is a package present in both revisions whose version,
// resolution mode, or both, differ.
type ChangedPackage struct {
	ID                           string
	VersionFrom, VersionTo       string
	ResolutionFrom, ResolutionTo string
}

func (c ChangedPackage) VersionChanged() bool    { return c.VersionFrom != c.VersionTo }
func (c ChangedPackage) ResolutionChanged() bool { return c.ResolutionFrom != c.ResolutionTo }

type SkipAdded struct{ ID, Reason string }

type SkipRemoved struct{ ID, Reason string }

type SkipChanged struct{ ID, ReasonFrom, ReasonTo string }

// RevisionDiff is what changed between one revision and its predecessor.
type RevisionDiff struct {
	Revision int
	// FirstRevision is revision 1's case: there is no predecessor, so
	// everything below is what this revision INTRODUCED rather than a delta.
	FirstRevision bool

	GateFrom, GateTo                   string
	DefaultPolicyFrom, DefaultPolicyTo string
	TargetsFrom, TargetsTo             []string

	Added   []AddedPackage
	Removed []RemovedPackage
	Changed []ChangedPackage

	SkipsAdded   []SkipAdded
	SkipsRemoved []SkipRemoved
	SkipsChanged []SkipChanged
}

func (d RevisionDiff) GateChanged() bool { return !d.FirstRevision && d.GateFrom != d.GateTo }

func (d RevisionDiff) DefaultPolicyChanged() bool {
	return !d.FirstRevision && d.DefaultPolicyFrom != d.DefaultPolicyTo
}

func (d RevisionDiff) TargetsChanged() bool {
	return !d.FirstRevision && !slices.Equal(d.TargetsFrom, d.TargetsTo)
}

// Empty is true when nothing changed: every package, skip, gate, policy and
// target the two revisions carry agree. Never true for FirstRevision, which
// always has something to introduce (or, when the profile started with
// nothing, is rendered as its own state rather than through this check).
func (d RevisionDiff) Empty() bool {
	return !d.FirstRevision &&
		len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0 &&
		len(d.SkipsAdded) == 0 && len(d.SkipsRemoved) == 0 && len(d.SkipsChanged) == 0 &&
		!d.GateChanged() && !d.DefaultPolicyChanged() && !d.TargetsChanged()
}

// DiffRevisions compares newer against older, its immediate predecessor.
// older is nil exactly for revision 1, which has none: everything in newer is
// then reported as introduced rather than as an empty diff, and the two
// revision-scoped fields (gate, default policy, targets) are left blank
// rather than false-reported as "changed from nothing".
func DiffRevisions(newer LockfileSnapshot, older *LockfileSnapshot) RevisionDiff {
	diff := RevisionDiff{Revision: newer.Revision}

	if older == nil {
		diff.FirstRevision = true
		for _, entry := range newer.Entries {
			diff.Added = append(diff.Added, AddedPackage(entry))
		}
		for _, skip := range newer.Skipped {
			diff.SkipsAdded = append(diff.SkipsAdded, SkipAdded(skip))
		}
		return diff
	}

	diff.GateFrom, diff.GateTo = older.Gate, newer.Gate
	diff.DefaultPolicyFrom, diff.DefaultPolicyTo = older.DefaultPolicy, newer.DefaultPolicy
	// Sorted copies, so the panel never reports a reordering as a change: the
	// target list is a set, and the lockfile does not promise an order.
	diff.TargetsFrom, diff.TargetsTo = slices.Sorted(slices.Values(older.Targets)), slices.Sorted(slices.Values(newer.Targets))

	priorEntry := make(map[string]LockfileEntrySnapshot, len(older.Entries))
	for _, entry := range older.Entries {
		priorEntry[entry.ID] = entry
	}
	stillPresent := make(map[string]bool, len(newer.Entries))
	for _, entry := range newer.Entries {
		stillPresent[entry.ID] = true
		prior, existed := priorEntry[entry.ID]
		switch {
		case !existed:
			diff.Added = append(diff.Added, AddedPackage(entry))
		case prior.Version != entry.Version || prior.Resolution != entry.Resolution:
			diff.Changed = append(diff.Changed, ChangedPackage{
				ID:          entry.ID,
				VersionFrom: prior.Version, VersionTo: entry.Version,
				ResolutionFrom: prior.Resolution, ResolutionTo: entry.Resolution,
			})
		}
	}
	for _, entry := range older.Entries {
		if !stillPresent[entry.ID] {
			diff.Removed = append(diff.Removed, RemovedPackage(entry))
		}
	}

	priorSkip := make(map[string]LockfileSkipSnapshot, len(older.Skipped))
	for _, skip := range older.Skipped {
		priorSkip[skip.ID] = skip
	}
	skipStillPresent := make(map[string]bool, len(newer.Skipped))
	for _, skip := range newer.Skipped {
		skipStillPresent[skip.ID] = true
		prior, existed := priorSkip[skip.ID]
		switch {
		case !existed:
			diff.SkipsAdded = append(diff.SkipsAdded, SkipAdded(skip))
		case prior.Reason != skip.Reason:
			diff.SkipsChanged = append(diff.SkipsChanged, SkipChanged{
				ID: skip.ID, ReasonFrom: prior.Reason, ReasonTo: skip.Reason,
			})
		}
	}
	for _, skip := range older.Skipped {
		if !skipStillPresent[skip.ID] {
			diff.SkipsRemoved = append(diff.SkipsRemoved, SkipRemoved(skip))
		}
	}

	return diff
}

// RevisionDiffPanel is what "Show diff" opens: a plain server round trip,
// closed by a link back, like the audit screen's own detail panel.
type RevisionDiffPanel struct {
	Revision int
	// Missing is a revision query naming no revision this profile has, or
	// one this identity may not read — the same answer for a nonexistent
	// thing and one that cannot be read that the rest of this screen gives.
	Missing bool
	// PredecessorUnavailable is Revision itself reading fine while its
	// predecessor did not: a real read failure, said plainly rather than
	// rendered as a silently empty diff.
	PredecessorUnavailable bool
	Diff                   RevisionDiff
}

// RevisionDiffHref opens one revision's diff panel without disturbing the
// rest of the page.
func RevisionDiffHref(slug string, revision int) string {
	return ProfileHref(slug) + "?revision=" + strconv.Itoa(revision)
}
