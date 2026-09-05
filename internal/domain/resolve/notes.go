package resolve

import (
	"fmt"
	"strings"
)

// The policy notes.
//
// These are the sentences the profile screen renders under an entry, and US5
// scenarios 2 and 3 make them part of the behaviour rather than decoration: the
// screen must STATE what the gate did. They live here, next to the rules, for the
// same reason the rules live in one package — a note written in a template is a
// second account of what happened, and the second account is the one that goes
// stale.
//
// Every note is a whole sentence or two of plain prose, present tense, naming the
// version and the reason. None of them is safe to interpolate unescaped: they
// carry FlagDetail, which comes out of a package bundle (FR-055).

// dateLayout is date-only and UTC. A policy note is read by a person deciding
// what to do about an entry, and to the hour is precision they cannot act on and
// a timezone they would have to reason about.
const dateLayout = "2006-01-02"

func join(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " ")
}

// flaggedAs names a version and, where the caller supplied one, the finding that
// flagged it.
func flaggedAs(candidate Candidate) string {
	if candidate.FlagDetail == "" {
		return candidate.Semver
	}
	return candidate.Semver + " (" + candidate.FlagDetail + ")"
}

func expiryPhrase(override *Override) string {
	if override.ExpiresAt == nil {
		return "with no expiry"
	}
	return "until " + override.ExpiresAt.UTC().Format(dateLayout)
}

// lapsedOn is the day an acceptance ran out. Only ever called on one that has:
// an override with no expiry cannot lapse.
func lapsedOn(override *Override) string {
	return override.ExpiresAt.UTC().Format(dateLayout)
}

// noteFlagged is what the screen says about a flagged version that RESOLVED. It
// is empty for a clean one: a note on every row that mostly says "nothing
// happened" is a note nobody reads on the row where something did.
func noteFlagged(gate Gate, candidate Candidate, verdict disposition) string {
	if candidate.Verdict != VerdictFlagged {
		return ""
	}
	switch {
	case verdict.override != nil && gate == GateApproval:
		return fmt.Sprintf("%s is flagged and the scan gate requires approval. %s approved it %s.",
			flaggedAs(candidate), verdict.override.Reviewer, expiryPhrase(verdict.override))
	case verdict.override != nil:
		return fmt.Sprintf("%s is flagged. %s accepted the finding %s, so it resolves with a warning.",
			flaggedAs(candidate), verdict.override.Reviewer, expiryPhrase(verdict.override))
	case candidate.Override != nil:
		// A lapsed acceptance only reaches here under warn-with-override, which
		// includes flagged versions anyway. Saying whose it was and when it ran out
		// is the difference between "nobody has looked at this" and "somebody did,
		// and the clock ran out on their decision".
		return fmt.Sprintf(
			"%s is flagged and the scan gate is warn-with-override, so it resolves with a warning. "+
				"%s's acceptance expired on %s, so no override is recorded.",
			flaggedAs(candidate), candidate.Override.Reviewer, lapsedOn(candidate.Override))
	default:
		return fmt.Sprintf(
			"%s is flagged and the scan gate is warn-with-override, so it resolves with a warning. "+
				"No reviewer has accepted this finding.",
			flaggedAs(candidate))
	}
}

// notePassedOver is the first half of a downgrade note: why the version the entry
// wanted was not the version it got.
func notePassedOver(newest Candidate, reason Reason, resolved string) string {
	switch reason {
	case ReasonFlaggedBlockedByGate:
		return fmt.Sprintf(
			"%s is flagged and the scan gate blocks flagged versions, so this entry resolved to %s, "+
				"the most recent clean version.",
			flaggedAs(newest), resolved)
	case ReasonVersionRejected:
		return fmt.Sprintf("%s was rejected by a reviewer, so this entry resolved to %s instead.",
			newest.Semver, resolved)
	case ReasonNoCleanVersionAvailable:
		return fmt.Sprintf("%s has not finished scanning, so this entry resolved to %s instead.",
			newest.Semver, resolved)
	case ReasonUnsignedSignaturesRequired:
		return fmt.Sprintf(
			"%s carries no signature reference and this organisation requires signed bundles, "+
				"so this entry resolved to %s instead.",
			newest.Semver, resolved)
	case ReasonFlaggedAwaitingApproval, ReasonPinTargetMissing:
		// Neither can produce a downgrade: awaiting-approval stops the walk rather
		// than falling through it, and a pin is never re-pointed.
		return ""
	}
	return ""
}

// noteSkipped is what the screen says about an entry the resolution excluded.
func noteSkipped(candidate Candidate, reason Reason, mode Mode) string {
	pinned := mode == ModePinned

	switch reason {
	case ReasonFlaggedBlockedByGate:
		if pinned {
			return fmt.Sprintf(
				"This entry is pinned to %s, which is flagged, and the scan gate blocks flagged versions. "+
					"The pin is not re-pointed: change the pin, or have a reviewer accept the finding.",
				flaggedAs(candidate))
		}
		return fmt.Sprintf(
			"%s is flagged and the scan gate blocks flagged versions, and no clean version of this "+
				"package is available to fall back to, so the entry is excluded.",
			flaggedAs(candidate))

	case ReasonFlaggedAwaitingApproval:
		lapsed := ""
		if candidate.Override != nil {
			lapsed = fmt.Sprintf(" %s's approval expired on %s.",
				candidate.Override.Reviewer, lapsedOn(candidate.Override))
		}
		if pinned {
			return fmt.Sprintf(
				"This entry is pinned to %s, which is flagged and needs a named reviewer's approval, "+
					"so the entry is excluded.%s",
				flaggedAs(candidate), lapsed)
		}
		return fmt.Sprintf(
			"%s is flagged and the scan gate requires a named reviewer to approve it. The entry is "+
				"excluded until one does; it is not quietly downgraded to an older version.%s",
			flaggedAs(candidate), lapsed)

	case ReasonVersionRejected:
		return fmt.Sprintf("%s was rejected by a reviewer, and a rejected version never resolves, "+
			"whatever the gate says.", candidate.Semver)

	case ReasonNoCleanVersionAvailable:
		return fmt.Sprintf("%s has not finished scanning, so there is nothing this entry can resolve to yet.",
			candidate.Semver)

	case ReasonUnsignedSignaturesRequired:
		return fmt.Sprintf("%s carries no signature reference and this organisation requires signed bundles.",
			candidate.Semver)

	case ReasonPinTargetMissing:
		return notePinTargetMissing()
	}
	return ""
}

func notePinTargetMissing() string {
	return "This entry is pinned to a version this resolution cannot see, so it is excluded rather " +
		"than re-pointed at another one."
}

func noteNothingToResolve() string {
	return "No version of this package is available to resolve."
}
