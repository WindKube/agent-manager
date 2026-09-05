package resolve

import (
	"fmt"
	"strings"
)

// The sentences the profile screen renders under an entry. They live next
// to the rules so there's no separate template restating what the gate
// did. Every note carries FlagDetail verbatim: escape at render.

// dateLayout is date-only and UTC: an hour or a timezone isn't actionable.
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

// lapsedOn is only ever called on an override with an expiry.
func lapsedOn(override *Override) string {
	return override.ExpiresAt.UTC().Format(dateLayout)
}

// noteFlagged is empty for a clean version; nobody reads a note that says
// nothing happened.
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
		// Naming whose acceptance lapsed distinguishes "nobody has looked at
		// this" from "somebody did, and it expired".
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

// notePassedOver is the first half of a downgrade note.
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
		return ""
	}
	return ""
}

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
