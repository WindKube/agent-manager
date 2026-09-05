package plan

// Skip is one entry the hub excluded; Reason is the hub's raw string, not an
// enum, since an unrecognised value must be reported verbatim, never dropped
// or folded into an "other" bucket.
type Skip struct {
	Profile string
	ID      string

	Reason string // verbatim from the lockfile

	Recognised bool // one of the six values frozen at build time; false means report, don't explain

	// Detail and WouldHaveResolvedTo are optionals, left empty rather than guessed when the hub omits them.
	Detail              string
	WouldHaveResolvedTo string
}

// The six skip reasons lockfile.schema.json enumerates; a seventh means a newer hub, not a broken one.
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
