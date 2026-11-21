package view

import (
	"slices"
	"strconv"
)

// Revision diffs are computed from two lockfiles rather than a stored delta, so there is no second source
// of truth to drift.

// LockfileSnapshot is one revision's lockfile, reduced to what a diff compares.
type LockfileSnapshot struct {
	Revision      int
	Gate          string
	DefaultPolicy string
	Targets       []string
	Entries       []LockfileEntrySnapshot
	Skipped       []LockfileSkipSnapshot
}

type LockfileEntrySnapshot struct {
	ID         string
	Version    string
	Resolution string
}

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

// ChangedPackage is a package present in both revisions whose version or resolution mode differs.
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
	// FirstRevision means there is no predecessor, so everything below was introduced rather than changed.
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

// Empty is true when nothing changed; never for FirstRevision, which renders as its own state.
func (d RevisionDiff) Empty() bool {
	return !d.FirstRevision &&
		len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0 &&
		len(d.SkipsAdded) == 0 && len(d.SkipsRemoved) == 0 && len(d.SkipsChanged) == 0 &&
		!d.GateChanged() && !d.DefaultPolicyChanged() && !d.TargetsChanged()
}

// DiffRevisions compares newer against its immediate predecessor. older is nil for revision 1: everything
// is then reported as introduced, and gate, policy and targets are left blank rather than "changed from nothing".
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
	// Targets are a set with no promised order, so compare sorted copies.
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

// RevisionDiffPanel is what "Show diff" opens.
type RevisionDiffPanel struct {
	Revision int
	// Missing covers both a nonexistent and an unreadable revision.
	Missing bool
	// PredecessorUnavailable is a read failure of the predecessor, shown plainly rather than as an empty diff.
	PredecessorUnavailable bool
	Diff                   RevisionDiff
}

func RevisionDiffHref(slug string, revision int) string {
	return ProfileHref(slug) + "?revision=" + strconv.Itoa(revision)
}
