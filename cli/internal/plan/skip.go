package plan

// Skip is one entry the hub resolved and then excluded, carried through with
// the hub's own reason.
//
// Reason is the hub's raw string, not an enum of this package's making: this
// CLI ships separately from the hub, the hub may add a reason, and an
// unrecognised value must be reported verbatim rather than dropped or
// folded into an "other" bucket, which would either silently hide a package
// or tell the user a lie that reads like a fact.
type Skip struct {
	Profile string
	ID      string

	// Reason is verbatim from the lockfile.
	Reason string

	// Recognised says whether Reason is one of the six values the contract
	// froze at the time this build was compiled. False means "report it, say it
	// came from the hub, and do not pretend to explain it".
	Recognised bool

	// Detail and WouldHaveResolvedTo are the lockfile's optionals, reported
	// when the hub supplied them and left empty rather than guessed when it
	// did not.
	Detail              string
	WouldHaveResolvedTo string
}

// The six skip reasons lockfile.schema.json enumerates. Listed so an
// unrecognised value can be flagged as unrecognised — never so that one can be
// rejected. A hub that sends a seventh is a newer hub, not a broken one.
const (
	SkipFlaggedBlockedByGate       = "flagged-blocked-by-gate"
	SkipFlaggedAwaitingApproval    = "flagged-awaiting-approval"
	SkipVersionRejected            = "version-rejected"
	SkipNoCleanVersionAvailable    = "no-clean-version-available"
	SkipPinTargetMissing           = "pin-target-missing"
	SkipUnsignedSignaturesRequired = "unsigned-and-signatures-required"
)

// KnownSkipReasons returns the frozen six, in the schema's own order. A test
// asserts the length, so a seventh cannot be added here without someone
// deciding what it means.
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

// IsKnownSkipReason reports whether this build recognises the value.
func IsKnownSkipReason(reason string) bool {
	for _, known := range KnownSkipReasons() {
		if reason == known {
			return true
		}
	}
	return false
}
