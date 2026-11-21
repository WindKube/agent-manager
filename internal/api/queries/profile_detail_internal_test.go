package queries

import (
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
)

func entry(id, version, mode, verdict string) contract.ProfileEntry {
	return contract.ProfileEntry{ID: id, Version: version, Mode: mode, Verdict: verdict}
}

func frozen(id, version, resolution, verdict string) contract.LockfileEntry {
	return contract.LockfileEntry{ID: id, Version: version, Resolution: resolution, Verdict: verdict}
}

func TestWhetherAProfileHasAnythingToPublishComparesWhatWouldReachAMachine(t *testing.T) {
	clean := entry("acme/review", "2.4.1", "latest", "clean")
	sameAsPublished := frozen("acme/review", "2.4.1", "latest", "clean")

	for _, tc := range []struct {
		name      string
		entries   []contract.ProfileEntry
		targets   []string
		head      contract.Lockfile
		published bool
		want      bool
		wantRows  []bool
	}{
		{
			name:      "a profile with no revisions owes one, whatever it holds",
			entries:   []contract.ProfileEntry{clean},
			published: false,
			want:      true,
			wantRows:  []bool{true},
		},
		{
			name:      "a profile with no revisions and no entries still owes one",
			published: false,
			want:      true,
		},
		{
			name:      "nothing has moved",
			entries:   []contract.ProfileEntry{clean},
			targets:   []string{"claude-code"},
			head:      contract.Lockfile{Entries: []contract.LockfileEntry{sameAsPublished}, Targets: []string{"claude-code"}},
			published: true,
			want:      false,
			wantRows:  []bool{false},
		},
		{
			name: "a floating entry the catalog moved under is unpublished, though nobody edited it",
			entries: []contract.ProfileEntry{
				entry("acme/review", "2.5.0", "latest", "clean"),
			},
			head:      contract.Lockfile{Entries: []contract.LockfileEntry{sameAsPublished}},
			published: true,
			want:      true,
			wantRows:  []bool{true},
		},
		{
			name: "a pin toggled on the same version is unpublished, because the lockfile records the mode",
			entries: []contract.ProfileEntry{
				entry("acme/review", "2.4.1", "pinned", "clean"),
			},
			head:      contract.Lockfile{Entries: []contract.LockfileEntry{sameAsPublished}},
			published: true,
			want:      true,
			wantRows:  []bool{true},
		},
		{
			name: "a version that has been rescanned into a different verdict is unpublished",
			entries: []contract.ProfileEntry{
				entry("acme/review", "2.4.1", "latest", "flagged"),
			},
			head:      contract.Lockfile{Entries: []contract.LockfileEntry{sameAsPublished}},
			published: true,
			want:      true,
			wantRows:  []bool{true},
		},
		{
			name: "an entry that gained an override is unpublished: the lockfile names the reviewer",
			entries: []contract.ProfileEntry{{
				ID: "acme/review", Version: "2.4.1", Mode: "latest", Verdict: "flagged",
				Override: &contract.LockfileOverride{Reviewer: "sec@example.dev"},
			}},
			head: contract.Lockfile{Entries: []contract.LockfileEntry{
				frozen("acme/review", "2.4.1", "latest", "flagged"),
			}},
			published: true,
			want:      true,
			wantRows:  []bool{true},
		},
		{
			name: "an entry the gate has begun excluding is unpublished",
			entries: []contract.ProfileEntry{{
				ID:   "acme/review",
				Skip: &contract.LockfileSkip{ID: "acme/review", Reason: "flagged-awaiting-approval"},
			}},
			head:      contract.Lockfile{Entries: []contract.LockfileEntry{sameAsPublished}},
			published: true,
			want:      true,
			wantRows:  []bool{true},
		},
		{
			name: "an exclusion that is still the same exclusion is not a change",
			entries: []contract.ProfileEntry{{
				ID: "acme/review",
				Skip: &contract.LockfileSkip{
					ID: "acme/review", Reason: "flagged-awaiting-approval",
					// Reworded by the rule pack: not a change anybody owes a revision for.
					Detail: "SH-NET-002 in postinstall.sh, line 41",
				},
			}},
			head: contract.Lockfile{Skipped: []contract.LockfileSkip{{
				ID: "acme/review", Reason: "flagged-awaiting-approval",
				Detail: "SH-NET-002 in postinstall.sh",
			}}},
			published: true,
			want:      false,
			wantRows:  []bool{false},
		},
		{
			name: "an exclusion whose reason changed is a change: the two say different things to a reader",
			entries: []contract.ProfileEntry{{
				ID:   "acme/review",
				Skip: &contract.LockfileSkip{ID: "acme/review", Reason: "flagged-blocked-by-gate"},
			}},
			head: contract.Lockfile{Skipped: []contract.LockfileSkip{{
				ID: "acme/review", Reason: "flagged-awaiting-approval",
			}}},
			published: true,
			want:      true,
			wantRows:  []bool{true},
		},
		{
			name:      "a package added to the profile is unpublished, and only that row",
			entries:   []contract.ProfileEntry{clean, entry("acme/threat", "1.0.0", "latest", "clean")},
			head:      contract.Lockfile{Entries: []contract.LockfileEntry{sameAsPublished}},
			published: true,
			want:      true,
			wantRows:  []bool{false, true},
		},
		{
			name:      "enabling a sync target is unpublished at the profile level and on no row",
			entries:   []contract.ProfileEntry{clean},
			targets:   []string{"claude-code", "codex"},
			head:      contract.Lockfile{Entries: []contract.LockfileEntry{sameAsPublished}, Targets: []string{"claude-code"}},
			published: true,
			want:      true,
			wantRows:  []bool{false},
		},
		{
			// Unreachable while `am_api` holds no DELETE on profile_entry; covered
			// for when that grant widens.
			name:    "a package the head revision holds and the draft does not is unpublished, on no row",
			entries: []contract.ProfileEntry{clean},
			head: contract.Lockfile{Entries: []contract.LockfileEntry{
				sameAsPublished, frozen("acme/threat", "1.0.0", "latest", "clean"),
			}},
			published: true,
			want:      true,
			wantRows:  []bool{false},
		},
		{
			name:    "an exclusion the head revision records and the draft no longer holds is unpublished",
			entries: []contract.ProfileEntry{clean},
			head: contract.Lockfile{
				Entries: []contract.LockfileEntry{sameAsPublished},
				Skipped: []contract.LockfileSkip{{ID: "acme/threat", Reason: "version-rejected"}},
			},
			published: true,
			want:      true,
			wantRows:  []bool{false},
		},
		{
			name:      "a gate flip that changed nothing anybody installs is not an unpublished change",
			entries:   []contract.ProfileEntry{clean},
			head:      contract.Lockfile{Gate: "block", Entries: []contract.LockfileEntry{sameAsPublished}},
			published: true,
			want:      false,
			wantRows:  []bool{false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries := append([]contract.ProfileEntry(nil), tc.entries...)
			got := markUnpublished(entries, tc.targets, tc.head, tc.published)

			require.Equal(t, tc.want, got)
			for i, want := range tc.wantRows {
				require.Equalf(t, want, entries[i].Unpublished,
					"row %d (%s) reported the wrong publication state", i, entries[i].ID)
			}
		})
	}
}
