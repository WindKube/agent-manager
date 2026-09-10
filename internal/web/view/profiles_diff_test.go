package view_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/view"
)

// TestDiffRevisionsReportsWhatChanged covers each shape of change
// DiffRevisions must report, one at a time, against an otherwise identical
// pair of revisions so a test failure names exactly what broke.
func TestDiffRevisionsReportsWhatChanged(t *testing.T) {
	t.Run("a package added", func(t *testing.T) {
		older := view.LockfileSnapshot{Revision: 4, Entries: []view.LockfileEntrySnapshot{
			{ID: "example/adr-writer", Version: "3.0.2", Resolution: "pinned"},
		}}
		newer := view.LockfileSnapshot{Revision: 5, Entries: []view.LockfileEntrySnapshot{
			{ID: "example/adr-writer", Version: "3.0.2", Resolution: "pinned"},
			{ID: "example/security-review-kit", Version: "1.0.0", Resolution: "latest"},
		}}

		diff := view.DiffRevisions(newer, &older)

		require.False(t, diff.FirstRevision)
		require.Equal(t, []view.AddedPackage{
			{ID: "example/security-review-kit", Version: "1.0.0", Resolution: "latest"},
		}, diff.Added)
		require.Empty(t, diff.Removed)
		require.Empty(t, diff.Changed)
		require.False(t, diff.Empty())
	})

	t.Run("a package removed", func(t *testing.T) {
		older := view.LockfileSnapshot{Revision: 4, Entries: []view.LockfileEntrySnapshot{
			{ID: "example/adr-writer", Version: "3.0.2", Resolution: "pinned"},
			{ID: "community/postgres-migration-guard", Version: "0.8.2", Resolution: "latest"},
		}}
		newer := view.LockfileSnapshot{Revision: 5, Entries: []view.LockfileEntrySnapshot{
			{ID: "example/adr-writer", Version: "3.0.2", Resolution: "pinned"},
		}}

		diff := view.DiffRevisions(newer, &older)

		require.Empty(t, diff.Added)
		require.Equal(t, []view.RemovedPackage{
			{ID: "community/postgres-migration-guard", Version: "0.8.2", Resolution: "latest"},
		}, diff.Removed)
		require.Empty(t, diff.Changed)
		require.False(t, diff.Empty())
	})

	t.Run("a version change", func(t *testing.T) {
		older := view.LockfileSnapshot{Revision: 4, Entries: []view.LockfileEntrySnapshot{
			{ID: "community/postgres-migration-guard", Version: "0.8.2", Resolution: "latest"},
		}}
		newer := view.LockfileSnapshot{Revision: 5, Entries: []view.LockfileEntrySnapshot{
			{ID: "community/postgres-migration-guard", Version: "0.8.3", Resolution: "latest"},
		}}

		diff := view.DiffRevisions(newer, &older)

		require.Len(t, diff.Changed, 1)
		changed := diff.Changed[0]
		require.Equal(t, "community/postgres-migration-guard", changed.ID)
		require.True(t, changed.VersionChanged())
		require.Equal(t, "0.8.2", changed.VersionFrom)
		require.Equal(t, "0.8.3", changed.VersionTo)
		require.False(t, changed.ResolutionChanged())
		require.False(t, diff.Empty())
	})

	t.Run("a pin mode change", func(t *testing.T) {
		older := view.LockfileSnapshot{Revision: 4, Entries: []view.LockfileEntrySnapshot{
			{ID: "example/adr-writer", Version: "3.0.2", Resolution: "latest"},
		}}
		newer := view.LockfileSnapshot{Revision: 5, Entries: []view.LockfileEntrySnapshot{
			{ID: "example/adr-writer", Version: "3.0.2", Resolution: "pinned"},
		}}

		diff := view.DiffRevisions(newer, &older)

		require.Len(t, diff.Changed, 1)
		changed := diff.Changed[0]
		require.False(t, changed.VersionChanged())
		require.True(t, changed.ResolutionChanged())
		require.Equal(t, "latest", changed.ResolutionFrom)
		require.Equal(t, "pinned", changed.ResolutionTo)
	})

	t.Run("a skip appearing", func(t *testing.T) {
		older := view.LockfileSnapshot{Revision: 4}
		newer := view.LockfileSnapshot{Revision: 5, Skipped: []view.LockfileSkipSnapshot{
			{ID: "community/release-notes", Reason: "flagged-awaiting-approval"},
		}}

		diff := view.DiffRevisions(newer, &older)

		require.Equal(t, []view.SkipAdded{
			{ID: "community/release-notes", Reason: "flagged-awaiting-approval"},
		}, diff.SkipsAdded)
		require.Empty(t, diff.SkipsRemoved)
		require.Empty(t, diff.SkipsChanged)
		require.False(t, diff.Empty())
	})

	t.Run("a skip disappearing", func(t *testing.T) {
		older := view.LockfileSnapshot{Revision: 4, Skipped: []view.LockfileSkipSnapshot{
			{ID: "community/release-notes", Reason: "flagged-awaiting-approval"},
		}}
		newer := view.LockfileSnapshot{Revision: 5}

		diff := view.DiffRevisions(newer, &older)

		require.Empty(t, diff.SkipsAdded)
		require.Equal(t, []view.SkipRemoved{
			{ID: "community/release-notes", Reason: "flagged-awaiting-approval"},
		}, diff.SkipsRemoved)
		require.Empty(t, diff.SkipsChanged)
		require.False(t, diff.Empty())
	})

	t.Run("a skip's reason changing", func(t *testing.T) {
		older := view.LockfileSnapshot{Revision: 4, Skipped: []view.LockfileSkipSnapshot{
			{ID: "community/release-notes", Reason: "flagged-awaiting-approval"},
		}}
		newer := view.LockfileSnapshot{Revision: 5, Skipped: []view.LockfileSkipSnapshot{
			{ID: "community/release-notes", Reason: "flagged-blocked-by-gate"},
		}}

		diff := view.DiffRevisions(newer, &older)

		require.Empty(t, diff.SkipsAdded)
		require.Empty(t, diff.SkipsRemoved)
		require.Equal(t, []view.SkipChanged{
			{ID: "community/release-notes", ReasonFrom: "flagged-awaiting-approval", ReasonTo: "flagged-blocked-by-gate"},
		}, diff.SkipsChanged)
	})

	t.Run("gate, default policy and targets changing", func(t *testing.T) {
		older := view.LockfileSnapshot{Revision: 4, Gate: "warn-with-override", DefaultPolicy: "floating-latest", Targets: []string{"claude-code"}}
		newer := view.LockfileSnapshot{Revision: 5, Gate: "block", DefaultPolicy: "pinned", Targets: []string{"claude-code", "codex"}}

		diff := view.DiffRevisions(newer, &older)

		require.True(t, diff.GateChanged())
		require.Equal(t, "warn-with-override", diff.GateFrom)
		require.Equal(t, "block", diff.GateTo)
		require.True(t, diff.DefaultPolicyChanged())
		require.True(t, diff.TargetsChanged())
		require.False(t, diff.Empty())
	})

	t.Run("nothing changed", func(t *testing.T) {
		snapshot := view.LockfileSnapshot{
			Revision: 5, Gate: "warn-with-override", DefaultPolicy: "floating-latest",
			Targets: []string{"claude-code"},
			Entries: []view.LockfileEntrySnapshot{
				{ID: "example/adr-writer", Version: "3.0.2", Resolution: "pinned"},
			},
			Skipped: []view.LockfileSkipSnapshot{
				{ID: "community/release-notes", Reason: "flagged-awaiting-approval"},
			},
		}
		older := snapshot
		older.Revision = 4
		newer := snapshot

		diff := view.DiffRevisions(newer, &older)

		require.True(t, diff.Empty())
		require.Empty(t, diff.Added)
		require.Empty(t, diff.Removed)
		require.Empty(t, diff.Changed)
		require.Empty(t, diff.SkipsAdded)
		require.Empty(t, diff.SkipsRemoved)
		require.Empty(t, diff.SkipsChanged)
	})

	// Revision 1 has no predecessor. The panel says that plainly and shows
	// what the revision introduced, rather than rendering an empty diff or
	// treating "no older revision" as an error.
	t.Run("revision 1 has no predecessor", func(t *testing.T) {
		newer := view.LockfileSnapshot{
			Revision: 1, Gate: "warn-with-override", DefaultPolicy: "floating-latest",
			Entries: []view.LockfileEntrySnapshot{
				{ID: "example/adr-writer", Version: "3.0.0", Resolution: "latest"},
			},
			Skipped: []view.LockfileSkipSnapshot{
				{ID: "community/release-notes", Reason: "flagged-awaiting-approval"},
			},
		}

		diff := view.DiffRevisions(newer, nil)

		require.True(t, diff.FirstRevision)
		require.Equal(t, []view.AddedPackage{
			{ID: "example/adr-writer", Version: "3.0.0", Resolution: "latest"},
		}, diff.Added)
		require.Equal(t, []view.SkipAdded{
			{ID: "community/release-notes", Reason: "flagged-awaiting-approval"},
		}, diff.SkipsAdded)
		require.Empty(t, diff.Removed)
		require.Empty(t, diff.Changed)
		// Nothing to compare the gate, policy or targets against.
		require.False(t, diff.GateChanged())
		require.False(t, diff.DefaultPolicyChanged())
		require.False(t, diff.TargetsChanged())
		// Empty() is defined over a delta and revision 1 has none; the panel
		// itself tells first-revision apart from a genuinely unchanged diff.
		require.False(t, diff.Empty())
	})
}

// A target list is a set: the lockfile makes no promise about its order, so a
// reordering is not a change the panel may claim.
func TestDiffRevisionsDoesNotReportAReorderedTargetListAsAChange(t *testing.T) {
	older := view.LockfileSnapshot{Revision: 1, Targets: []string{"claude-code", "codex"}}
	newer := view.LockfileSnapshot{Revision: 2, Targets: []string{"codex", "claude-code"}}

	diff := view.DiffRevisions(newer, &older)
	require.False(t, diff.TargetsChanged(), "the same two targets in a different order is not a change")
	require.True(t, diff.Empty(), "nothing else changed either")
}
