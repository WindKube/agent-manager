package resolve_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/domain/resolve"
)

// The gate rules, tested with no container. That is the whole reason the resolver
// takes its own input types instead of models.*: the three gates crossed with the
// two entry modes and the four states a version can be in is 24 cases, and 24
// cases that need Postgres is a table nobody writes.

var (
	// resolvedAt is the instant every resolution below happens at. The two
	// acceptance expiries straddle it, which is what makes "an override that has
	// lapsed is not an override" a case rather than a comment.
	resolvedAt = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	stillValid = time.Date(2026, 4, 12, 9, 0, 0, 0, time.UTC)
	ranOut     = time.Date(2025, 12, 1, 9, 0, 0, 0, time.UTC)
)

const (
	reviewer   = "ewojcik@example.com"
	flagDetail = "SH-INJ-011 in SKILL.md"
)

// newest is the candidate every case varies; older is the clean release behind it
// that a fallback can land on.
func older() resolve.Candidate {
	return resolve.Candidate{
		ID: "guard@1.0.0", Semver: "1.0.0", Verdict: resolve.VerdictClean, Visible: true,
		Digest: "sha256:" + zeros(), ObjectKey: "bundles/guard/1.0.0/bundle.tar.zst",
	}
}

func newest(verdict resolve.Verdict, override *resolve.Override) resolve.Candidate {
	candidate := resolve.Candidate{
		ID: "guard@2.0.0", Semver: "2.0.0", Verdict: verdict, Visible: true,
		Digest: "sha256:" + zeros(), ObjectKey: "bundles/guard/2.0.0/bundle.tar.zst",
		Override: override,
	}
	if verdict == resolve.VerdictFlagged {
		candidate.FlagDetail = flagDetail
	}
	return candidate
}

func accepted(expires *time.Time) *resolve.Override {
	return &resolve.Override{Reviewer: reviewer, Note: "the write is the default, not the intent", ExpiresAt: expires}
}

func zeros() string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = '0'
	}
	return string(out)
}

// entry is one package tracking the two candidates above, in the given mode. A
// pinned entry always pins the NEWER one, because a pin at a version the gate
// dislikes is the case US5 asks the screen to state rather than silently fix.
func entry(mode resolve.Mode, newest resolve.Candidate) resolve.Entry {
	built := resolve.Entry{
		ID: "community/postgres-migration-guard", Kind: "skill", Mode: mode,
		Candidates: []resolve.Candidate{older(), newest},
	}
	if mode == resolve.ModePinned {
		built.PinnedID = newest.ID
	}
	return built
}

func resolveOne(t *testing.T, gate resolve.Gate, e resolve.Entry) resolve.Resolution {
	t.Helper()
	result, err := resolve.Resolve(resolve.Input{Gate: gate, At: resolvedAt, Entries: []resolve.Entry{e}})
	require.NoError(t, err)
	require.Len(t, result.Entries, 1)
	require.Equal(t, gate, result.Gate)
	return result.Entries[0]
}

// The four states the newest version can be in.
const (
	stateClean   = "clean"
	stateFlagged = "flagged"
	stateActive  = "flagged, acceptance still valid"
	stateLapsed  = "flagged, acceptance expired"
)

func newestIn(state string) resolve.Candidate {
	switch state {
	case stateClean:
		return newest(resolve.VerdictClean, nil)
	case stateFlagged:
		return newest(resolve.VerdictFlagged, nil)
	case stateActive:
		return newest(resolve.VerdictFlagged, accepted(&stillValid))
	default:
		return newest(resolve.VerdictFlagged, accepted(&ranOut))
	}
}

func TestEachGateDecidesWhatAPinnedAndAFloatingEntryResolveTo(t *testing.T) {
	cases := []struct {
		gate    resolve.Gate
		mode    resolve.Mode
		state   string
		outcome resolve.Outcome
		// version is the semver the entry resolved to, empty when it was excluded.
		version string
		reason  resolve.Reason
		// would is Skip.WouldHaveResolvedTo, or on a downgrade the version passed over.
		would string
	}{
		// block: a flagged version does not resolve. A floating entry falls back to
		// the most recent clean one; a pin is a conflict, not something to re-point.
		{resolve.GateBlock, resolve.ModeLatest, stateClean, resolve.OutcomeResolved, "2.0.0", "", ""},
		{resolve.GateBlock, resolve.ModeLatest, stateFlagged, resolve.OutcomeDowngraded, "1.0.0", "", "2.0.0"},
		{resolve.GateBlock, resolve.ModeLatest, stateActive, resolve.OutcomeDowngraded, "1.0.0", "", "2.0.0"},
		{resolve.GateBlock, resolve.ModeLatest, stateLapsed, resolve.OutcomeDowngraded, "1.0.0", "", "2.0.0"},
		{resolve.GateBlock, resolve.ModePinned, stateClean, resolve.OutcomeResolved, "2.0.0", "", ""},
		{resolve.GateBlock, resolve.ModePinned, stateFlagged, resolve.OutcomeSkipped, "", resolve.ReasonFlaggedBlockedByGate, "2.0.0"},
		{resolve.GateBlock, resolve.ModePinned, stateActive, resolve.OutcomeSkipped, "", resolve.ReasonFlaggedBlockedByGate, "2.0.0"},
		{resolve.GateBlock, resolve.ModePinned, stateLapsed, resolve.OutcomeSkipped, "", resolve.ReasonFlaggedBlockedByGate, "2.0.0"},

		// approval: an unapproved flagged version excludes the entry. Note that a
		// clean 1.0.0 is sitting right there and is NOT taken — that is the point.
		{resolve.GateApproval, resolve.ModeLatest, stateClean, resolve.OutcomeResolved, "2.0.0", "", ""},
		{resolve.GateApproval, resolve.ModeLatest, stateFlagged, resolve.OutcomeSkipped, "", resolve.ReasonFlaggedAwaitingApproval, "2.0.0"},
		{resolve.GateApproval, resolve.ModeLatest, stateActive, resolve.OutcomeOverridden, "2.0.0", "", ""},
		{resolve.GateApproval, resolve.ModeLatest, stateLapsed, resolve.OutcomeSkipped, "", resolve.ReasonFlaggedAwaitingApproval, "2.0.0"},
		{resolve.GateApproval, resolve.ModePinned, stateClean, resolve.OutcomeResolved, "2.0.0", "", ""},
		{resolve.GateApproval, resolve.ModePinned, stateFlagged, resolve.OutcomeSkipped, "", resolve.ReasonFlaggedAwaitingApproval, "2.0.0"},
		{resolve.GateApproval, resolve.ModePinned, stateActive, resolve.OutcomeOverridden, "2.0.0", "", ""},
		{resolve.GateApproval, resolve.ModePinned, stateLapsed, resolve.OutcomeSkipped, "", resolve.ReasonFlaggedAwaitingApproval, "2.0.0"},

		// warn-with-override: FR-035 includes flagged versions and records the
		// override. An acceptance changes whose name is on it, not whether it lands.
		{resolve.GateWarnWithOverride, resolve.ModeLatest, stateClean, resolve.OutcomeResolved, "2.0.0", "", ""},
		{resolve.GateWarnWithOverride, resolve.ModeLatest, stateFlagged, resolve.OutcomeWarned, "2.0.0", "", ""},
		{resolve.GateWarnWithOverride, resolve.ModeLatest, stateActive, resolve.OutcomeOverridden, "2.0.0", "", ""},
		{resolve.GateWarnWithOverride, resolve.ModeLatest, stateLapsed, resolve.OutcomeWarned, "2.0.0", "", ""},
		{resolve.GateWarnWithOverride, resolve.ModePinned, stateClean, resolve.OutcomeResolved, "2.0.0", "", ""},
		{resolve.GateWarnWithOverride, resolve.ModePinned, stateFlagged, resolve.OutcomeWarned, "2.0.0", "", ""},
		{resolve.GateWarnWithOverride, resolve.ModePinned, stateActive, resolve.OutcomeOverridden, "2.0.0", "", ""},
		{resolve.GateWarnWithOverride, resolve.ModePinned, stateLapsed, resolve.OutcomeWarned, "2.0.0", "", ""},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%s/%s", tc.gate, tc.mode, tc.state), func(t *testing.T) {
			got := resolveOne(t, tc.gate, entry(tc.mode, newestIn(tc.state)))

			require.Equal(t, tc.outcome, got.Outcome)
			require.Equal(t, tc.mode, got.Mode, "the entry's declared mode is what the lockfile records")

			if tc.version == "" {
				require.Nil(t, got.Version)
				require.Nil(t, got.Override)
				require.NotNil(t, got.Skip, "an excluded entry must report why (FR-036)")
				require.Equal(t, tc.reason, got.Skip.Reason)
				require.Equal(t, tc.would, got.Skip.WouldHaveResolvedTo)
				require.Equal(t, got.ID, got.Skip.ID)
				require.NotEmpty(t, got.Note, "an excluded entry must have something to say on screen")
				return
			}

			require.Nil(t, got.Skip)
			require.NotNil(t, got.Version)
			require.Equal(t, tc.version, got.Version.Semver)
			require.Equal(t, tc.would != "", got.PassedOver != nil)
			if tc.would != "" {
				require.Equal(t, tc.would, got.PassedOver.Semver)
			}
			require.Equal(t, tc.outcome == resolve.OutcomeOverridden, got.Override != nil,
				"an override is recorded exactly when one let a flagged version through")
			require.Equal(t, tc.outcome == resolve.OutcomeResolved, got.Note == "",
				"a note is written exactly when the gate did something worth stating")
		})
	}
}

func TestAnAcceptanceWithNoExpiryNeverLapses(t *testing.T) {
	got := resolveOne(t, resolve.GateApproval, entry(resolve.ModeLatest,
		newest(resolve.VerdictFlagged, accepted(nil))))

	require.Equal(t, resolve.OutcomeOverridden, got.Outcome)
	require.NotNil(t, got.Override)
	require.Nil(t, got.Override.ExpiresAt)
}

func TestARejectedVersionNeverResolvesWhateverTheGateSays(t *testing.T) {
	for _, gate := range []resolve.Gate{resolve.GateBlock, resolve.GateApproval, resolve.GateWarnWithOverride} {
		t.Run(string(gate), func(t *testing.T) {
			// Pinned, so there is nothing to fall back to and the reason is the
			// rejection itself rather than the absence of an alternative (FR-029).
			got := resolveOne(t, gate, entry(resolve.ModePinned, newest(resolve.VerdictRejected, accepted(&stillValid))))

			require.Equal(t, resolve.OutcomeSkipped, got.Outcome)
			require.Equal(t, resolve.ReasonVersionRejected, got.Skip.Reason)

			// And a floating entry passes over it rather than stopping.
			floating := resolveOne(t, gate, entry(resolve.ModeLatest, newest(resolve.VerdictRejected, nil)))
			require.Equal(t, resolve.OutcomeDowngraded, floating.Outcome)
			require.Equal(t, "1.0.0", floating.Version.Semver)
		})
	}
}

func TestAVersionStillBeingScannedIsPassedOverRatherThanResolved(t *testing.T) {
	floating := resolveOne(t, resolve.GateWarnWithOverride,
		entry(resolve.ModeLatest, newest(resolve.VerdictScanning, nil)))
	require.Equal(t, resolve.OutcomeDowngraded, floating.Outcome)
	require.Equal(t, "1.0.0", floating.Version.Semver)

	pinned := resolveOne(t, resolve.GateWarnWithOverride,
		entry(resolve.ModePinned, newest(resolve.VerdictScanning, nil)))
	require.Equal(t, resolve.OutcomeSkipped, pinned.Outcome)
	require.Equal(t, resolve.ReasonNoCleanVersionAvailable, pinned.Skip.Reason)
	require.Equal(t, "2.0.0", pinned.Skip.WouldHaveResolvedTo)
}

func TestWithNoCleanVersionToFallBackToBlockExcludesTheEntryAndNamesTheGate(t *testing.T) {
	only := newest(resolve.VerdictFlagged, nil)
	got := resolveOne(t, resolve.GateBlock, resolve.Entry{
		ID: "community/postgres-migration-guard", Kind: "skill", Mode: resolve.ModeLatest,
		Candidates: []resolve.Candidate{only},
	})

	require.Equal(t, resolve.OutcomeSkipped, got.Outcome)
	require.Equal(t, resolve.ReasonFlaggedBlockedByGate, got.Skip.Reason)
	require.Equal(t, flagDetail, got.Skip.Detail)
	require.Equal(t, "2.0.0", got.Skip.WouldHaveResolvedTo)
}

func TestAnEntryWithNothingToConsiderIsExcludedRatherThanDroppedSilently(t *testing.T) {
	got := resolveOne(t, resolve.GateWarnWithOverride, resolve.Entry{
		ID: "community/ghost", Kind: "skill", Mode: resolve.ModeLatest,
	})

	require.Equal(t, resolve.OutcomeSkipped, got.Outcome)
	require.Equal(t, resolve.ReasonNoCleanVersionAvailable, got.Skip.Reason)
	require.Empty(t, got.Skip.WouldHaveResolvedTo)
}

func TestAPinAtAVersionTheResolutionCannotSeeIsExcludedRatherThanRePointed(t *testing.T) {
	got := resolveOne(t, resolve.GateWarnWithOverride, resolve.Entry{
		ID: "community/postgres-migration-guard", Kind: "skill", Mode: resolve.ModePinned,
		PinnedID: "guard@9.9.9", Candidates: []resolve.Candidate{older(), newest(resolve.VerdictClean, nil)},
	})

	require.Equal(t, resolve.OutcomeSkipped, got.Outcome)
	require.Equal(t, resolve.ReasonPinTargetMissing, got.Skip.Reason)
	require.Empty(t, got.Skip.WouldHaveResolvedTo, "nothing here knows what the missing pin was")
}

func TestAnArchivedVersionIsIgnoredByAFloatingEntryAndStillHonouredByAPin(t *testing.T) {
	archived := newest(resolve.VerdictClean, nil)
	archived.Visible = false
	candidates := []resolve.Candidate{older(), archived}

	floating := resolveOne(t, resolve.GateWarnWithOverride, resolve.Entry{
		ID: "community/postgres-migration-guard", Mode: resolve.ModeLatest, Candidates: candidates,
	})
	require.Equal(t, "1.0.0", floating.Version.Semver)
	require.Equal(t, resolve.OutcomeResolved, floating.Outcome,
		"an invisible version is not in the pool at all, so passing it is not a downgrade")

	pinned := resolveOne(t, resolve.GateWarnWithOverride, resolve.Entry{
		ID: "community/postgres-migration-guard", Mode: resolve.ModePinned,
		PinnedID: archived.ID, Candidates: candidates,
	})
	require.Equal(t, "2.0.0", pinned.Version.Semver)
}

func TestARangeEntryTakesTheNewestVersionInsideItsConstraint(t *testing.T) {
	got := resolveOne(t, resolve.GateWarnWithOverride, resolve.Entry{
		ID: "community/postgres-migration-guard", Mode: resolve.ModeRange, Range: "<2.0.0",
		Candidates: []resolve.Candidate{older(), newest(resolve.VerdictClean, nil)},
	})

	require.Equal(t, resolve.OutcomeResolved, got.Outcome)
	require.Equal(t, "1.0.0", got.Version.Semver)
	require.Equal(t, resolve.ModeRange, got.Mode)
}

func TestARangeMatchingNothingExcludesTheEntry(t *testing.T) {
	got := resolveOne(t, resolve.GateWarnWithOverride, resolve.Entry{
		ID: "community/postgres-migration-guard", Mode: resolve.ModeRange, Range: "^7.0.0",
		Candidates: []resolve.Candidate{older(), newest(resolve.VerdictClean, nil)},
	})

	require.Equal(t, resolve.OutcomeSkipped, got.Outcome)
	require.Equal(t, resolve.ReasonNoCleanVersionAvailable, got.Skip.Reason)
}

func TestRequiringSignedBundlesExcludesAVersionCarryingNoSignature(t *testing.T) {
	signed := older()
	signed.Signature = &resolve.Signature{Ref: "sigstore:guard@1.0.0"}

	resolveWith := func(candidates ...resolve.Candidate) resolve.Resolution {
		result, err := resolve.Resolve(resolve.Input{
			Gate: resolve.GateWarnWithOverride, RequireSignatures: true, At: resolvedAt,
			Entries: []resolve.Entry{{
				ID: "community/postgres-migration-guard", Mode: resolve.ModeLatest, Candidates: candidates,
			}},
		})
		require.NoError(t, err)
		return result.Entries[0]
	}

	// The newest is unsigned, so the entry falls back to the signed release behind it.
	fell := resolveWith(signed, newest(resolve.VerdictClean, nil))
	require.Equal(t, resolve.OutcomeDowngraded, fell.Outcome)
	require.Equal(t, "1.0.0", fell.Version.Semver)

	// With nothing signed, the entry is excluded under the frozen reason.
	excluded := resolveWith(older(), newest(resolve.VerdictClean, nil))
	require.Equal(t, resolve.OutcomeSkipped, excluded.Outcome)
	require.Equal(t, resolve.ReasonUnsignedSignaturesRequired, excluded.Skip.Reason)
}

func TestResolveRefusesInputItCannotBeSureAbout(t *testing.T) {
	clean := entry(resolve.ModeLatest, newest(resolve.VerdictClean, nil))

	bad := func(gate resolve.Gate, e resolve.Entry) error {
		_, err := resolve.Resolve(resolve.Input{Gate: gate, At: resolvedAt, Entries: []resolve.Entry{e}})
		return err
	}

	require.ErrorContains(t, bad("permissive", clean), "scan gate")

	unknownMode := clean
	unknownMode.Mode = "whatever"
	require.ErrorContains(t, bad(resolve.GateBlock, unknownMode), "entry mode")

	unknownVerdict := entry(resolve.ModeLatest, newest("quarantined", nil))
	require.ErrorContains(t, bad(resolve.GateBlock, unknownVerdict), "verdict")

	notSemver := entry(resolve.ModeLatest, newest(resolve.VerdictClean, nil))
	notSemver.Candidates[1].Semver = "tuesday"
	require.ErrorContains(t, bad(resolve.GateBlock, notSemver), "not a semver")

	duplicate := entry(resolve.ModeLatest, newest(resolve.VerdictClean, nil))
	duplicate.Candidates[1].ID = duplicate.Candidates[0].ID
	require.ErrorContains(t, bad(resolve.GateBlock, duplicate), "share the id")

	noExpression := clean
	noExpression.Mode = resolve.ModeRange
	require.ErrorContains(t, bad(resolve.GateBlock, noExpression), "range expression")

	badRange := noExpression
	badRange.Range = ">>>"
	require.ErrorContains(t, bad(resolve.GateBlock, badRange), "not a constraint")
}

func TestTheResultSplitsIntoTheLockfilesTwoListsInEntryOrder(t *testing.T) {
	result, err := resolve.Resolve(resolve.Input{
		Gate: resolve.GateApproval, At: resolvedAt,
		Entries: []resolve.Entry{
			{ID: "a/one", Mode: resolve.ModeLatest, Candidates: []resolve.Candidate{older()}},
			{ID: "b/two", Mode: resolve.ModeLatest, Candidates: []resolve.Candidate{newest(resolve.VerdictFlagged, nil)}},
			{ID: "c/three", Mode: resolve.ModeLatest, Candidates: []resolve.Candidate{older()}},
		},
	})
	require.NoError(t, err)

	require.Len(t, result.Entries, 3, "the screen draws a row for every entry, skipped ones included")

	resolved := result.Resolved()
	require.Len(t, resolved, 2)
	require.Equal(t, "a/one", resolved[0].ID)
	require.Equal(t, "c/three", resolved[1].ID)

	skipped := result.Skipped()
	require.Len(t, skipped, 1)
	require.Equal(t, resolve.Skip{
		ID:     "b/two",
		Reason: resolve.ReasonFlaggedAwaitingApproval,
		Detail: flagDetail,

		WouldHaveResolvedTo: "2.0.0",
	}, skipped[0])
}

func TestTheSixSkipReasonsAreTheOnesTheResolverCanProduce(t *testing.T) {
	require.Len(t, resolve.Reasons(), 6, "a seventh reason is a contract change, not a commit")

	produced := map[resolve.Reason]bool{}
	for _, reason := range resolve.Reasons() {
		produced[reason] = false
	}
	record := func(got resolve.Resolution) {
		if got.Skip != nil {
			produced[got.Skip.Reason] = true
		}
	}

	record(resolveOne(t, resolve.GateBlock, resolve.Entry{
		ID: "x", Mode: resolve.ModeLatest, Candidates: []resolve.Candidate{newest(resolve.VerdictFlagged, nil)}}))
	record(resolveOne(t, resolve.GateApproval, entry(resolve.ModeLatest, newest(resolve.VerdictFlagged, nil))))
	record(resolveOne(t, resolve.GateBlock, entry(resolve.ModePinned, newest(resolve.VerdictRejected, nil))))
	record(resolveOne(t, resolve.GateBlock, resolve.Entry{ID: "x", Mode: resolve.ModeLatest}))
	record(resolveOne(t, resolve.GateBlock, resolve.Entry{
		ID: "x", Mode: resolve.ModePinned, PinnedID: "gone", Candidates: []resolve.Candidate{older()}}))

	signed, err := resolve.Resolve(resolve.Input{
		Gate: resolve.GateBlock, RequireSignatures: true, At: resolvedAt,
		Entries: []resolve.Entry{{ID: "x", Mode: resolve.ModeLatest, Candidates: []resolve.Candidate{older()}}},
	})
	require.NoError(t, err)
	record(signed.Entries[0])

	for reason, seen := range produced {
		require.Truef(t, seen, "no case in this package produces %q, so nothing tests what it means", reason)
	}
}

// TestThePolicyNoteStatesWhatTheGateDid pins the prose, not just the decision.
//
// US5 scenarios 2 and 3 make the note behaviour: the screen has to STATE that a
// version was blocked and fell back, and that another is excluded pending a named
// reviewer. Asserting the exact sentence is what stops a later edit turning "is
// excluded until one does" into something that reads like a transient error, and
// it is the string T089 compares the rendered screen against.
func TestThePolicyNoteStatesWhatTheGateDid(t *testing.T) {
	cases := []struct {
		name string
		gate resolve.Gate
		mode resolve.Mode
		// candidates defaults to the two-version fixture when nil.
		candidates []resolve.Candidate
		pinnedID   string
		state      string
		want       string
	}{
		{
			name: "a clean resolution says nothing",
			gate: resolve.GateWarnWithOverride, mode: resolve.ModeLatest, state: stateClean,
			want: "",
		},
		{
			name: "block falls back and names the version it fell from",
			gate: resolve.GateBlock, mode: resolve.ModeLatest, state: stateFlagged,
			want: "2.0.0 (SH-INJ-011 in SKILL.md) is flagged and the scan gate blocks flagged " +
				"versions, so this entry resolved to 1.0.0, the most recent clean version.",
		},
		{
			name: "a pin the block gate refuses is stated as a conflict",
			gate: resolve.GateBlock, mode: resolve.ModePinned, state: stateFlagged,
			want: "This entry is pinned to 2.0.0 (SH-INJ-011 in SKILL.md), which is flagged, and the " +
				"scan gate blocks flagged versions. The pin is not re-pointed: change the pin, or " +
				"have a reviewer accept the finding.",
		},
		{
			name: "approval says the entry waits rather than downgrades",
			gate: resolve.GateApproval, mode: resolve.ModeLatest, state: stateFlagged,
			want: "2.0.0 (SH-INJ-011 in SKILL.md) is flagged and the scan gate requires a named " +
				"reviewer to approve it. The entry is excluded until one does; it is not quietly " +
				"downgraded to an older version.",
		},
		{
			name: "approval names the reviewer whose approval ran out",
			gate: resolve.GateApproval, mode: resolve.ModeLatest, state: stateLapsed,
			want: "2.0.0 (SH-INJ-011 in SKILL.md) is flagged and the scan gate requires a named " +
				"reviewer to approve it. The entry is excluded until one does; it is not quietly " +
				"downgraded to an older version. ewojcik@example.com's approval expired on 2025-12-01.",
		},
		{
			name: "approval names the reviewer who granted it",
			gate: resolve.GateApproval, mode: resolve.ModeLatest, state: stateActive,
			want: "2.0.0 (SH-INJ-011 in SKILL.md) is flagged and the scan gate requires approval. " +
				"ewojcik@example.com approved it until 2026-04-12.",
		},
		{
			name: "warn-with-override says nobody has looked at it",
			gate: resolve.GateWarnWithOverride, mode: resolve.ModeLatest, state: stateFlagged,
			want: "2.0.0 (SH-INJ-011 in SKILL.md) is flagged and the scan gate is warn-with-override, " +
				"so it resolves with a warning. No reviewer has accepted this finding.",
		},
		{
			name: "warn-with-override names the acceptance it recorded",
			gate: resolve.GateWarnWithOverride, mode: resolve.ModeLatest, state: stateActive,
			want: "2.0.0 (SH-INJ-011 in SKILL.md) is flagged. ewojcik@example.com accepted the " +
				"finding until 2026-04-12, so it resolves with a warning.",
		},
		{
			name: "warn-with-override says the acceptance lapsed and was not recorded",
			gate: resolve.GateWarnWithOverride, mode: resolve.ModeLatest, state: stateLapsed,
			want: "2.0.0 (SH-INJ-011 in SKILL.md) is flagged and the scan gate is warn-with-override, " +
				"so it resolves with a warning. ewojcik@example.com's acceptance expired on " +
				"2025-12-01, so no override is recorded.",
		},
		{
			name: "a rejected pin says the gate had no say in it",
			gate: resolve.GateWarnWithOverride, mode: resolve.ModePinned,
			candidates: []resolve.Candidate{older(), newest(resolve.VerdictRejected, nil)},
			pinnedID:   "guard@2.0.0",
			want: "2.0.0 was rejected by a reviewer, and a rejected version never resolves, " +
				"whatever the gate says.",
		},
		{
			name: "a missing pin target says it was not re-pointed",
			gate: resolve.GateWarnWithOverride, mode: resolve.ModePinned,
			candidates: []resolve.Candidate{older()}, pinnedID: "guard@9.9.9",
			want: "This entry is pinned to a version this resolution cannot see, so it is excluded " +
				"rather than re-pointed at another one.",
		},
		{
			name: "an entry with no versions at all says so",
			gate: resolve.GateWarnWithOverride, mode: resolve.ModeLatest,
			candidates: []resolve.Candidate{},
			want:       "No version of this package is available to resolve.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			built := entry(tc.mode, newestIn(tc.state))
			if tc.candidates != nil {
				built.Candidates = tc.candidates
				built.PinnedID = tc.pinnedID
			}
			require.Equal(t, tc.want, resolveOne(t, tc.gate, built).Note)
		})
	}
}
