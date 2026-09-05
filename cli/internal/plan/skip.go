package plan

import "github.com/WindKube/agent-manager/cli/internal/record"

// Skip is one entry that was resolved and then excluded, either by the hub
// or by this build because it cannot install the entry's kind or write its
// target. Reason is a raw string, not an enum, so a value a newer hub adds
// is still reported verbatim rather than dropped.
type Skip struct {
	Profile string
	ID      string

	// Target is set only for a skip this build decided; empty for a hub skip.
	Target record.Target

	Reason string

	// Recognised is false when Reason isn't one of the known values below.
	Recognised bool

	// Detail and WouldHaveResolvedTo are set only for a hub skip.
	Detail              string
	WouldHaveResolvedTo string
}

// Reasons this CLI itself excludes an entry.
const (
	SkipEntryKindUnsupported = "entry-kind-not-installable"

	SkipTargetUnwritable = "target-unwritable"
)

// The skip reasons lockfile.schema.json enumerates.
const (
	SkipFlaggedBlockedByGate       = "flagged-blocked-by-gate"
	SkipFlaggedAwaitingApproval    = "flagged-awaiting-approval"
	SkipVersionRejected            = "version-rejected"
	SkipNoCleanVersionAvailable    = "no-clean-version-available"
	SkipPinTargetMissing           = "pin-target-missing"
	SkipUnsignedSignaturesRequired = "unsigned-and-signatures-required"
)

// KnownSkipReasons returns the frozen six, in schema order.
func KnownSkipReasons() []string {
	return []string{
		SkipFlaggedBlockedByGate,
		SkipFlaggedAwaitingApproval,
		SkipVersionRejected,
		SkipNoCleanVersionAvailable,
		SkipPinTargetMissing,
		SkipUnsignedSignaturesRequired,
	}
}

func IsKnownSkipReason(reason string) bool {
	for _, known := range KnownSkipReasons() {
		if reason == known {
			return true
		}
	}
	return false
}
