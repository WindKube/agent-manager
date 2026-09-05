package plan

import "github.com/WindKube/agent-manager/cli/internal/record"

// Skip is one entry that was resolved and then excluded — either by the hub
// (FR-011), or by this build because it cannot install the entry's kind or
// cannot write its target. One poisoned package or one unwritable target must
// not refuse the whole plan; the entries either side still install, and this
// is how each excluded one is still reported rather than silently dropped.
//
// Reason is a raw string rather than an enum of this package's making, for
// hub and build skips alike: this CLI ships separately from the hub, the hub
// may add a reason, and an unrecognised value must be reported verbatim
// rather than dropped or folded into an "other" bucket. Dropping it makes a
// package silently absent from a machine, which is the failure FR-011 exists
// to prevent; folding it into "other" tells the user a lie that reads like a
// fact.
type Skip struct {
	Profile string
	ID      string

	// Target is set only for a skip this build decided — an entry kind it
	// cannot install under a target, or a target it cannot write at all — and
	// empty for one the hub decided, since the hub reasons per package rather
	// than per target.
	Target record.Target

	// Reason is verbatim from the lockfile for a hub skip, or one of the two
	// build reasons below for a build skip.
	Reason string

	// Recognised says whether Reason is one of the six values the contract
	// froze at the time this build was compiled. Always true for a build skip,
	// since Reason is then this build's own vocabulary. False means "report
	// it, say it came from the hub, and do not pretend to explain it".
	Recognised bool

	// Detail and WouldHaveResolvedTo are the lockfile's optionals for a hub
	// skip. FR-011 asks for the version the entry would have resolved to, so
	// it is reported when the hub supplied it and left empty rather than
	// guessed when it did not. A build skip carries its explanation in Detail
	// and leaves WouldHaveResolvedTo empty: nothing kept this build from
	// resolving the version, only from installing it.
	Detail              string
	WouldHaveResolvedTo string
}

// The two reasons this CLI itself excludes an entry, as opposed to the hub's
// six reasons above.
const (
	// SkipEntryKindUnsupported: the target refused the entry's kind, e.g. a
	// plugin routed at a target that only skillTarget-style directories serve.
	SkipEntryKindUnsupported = "entry-kind-not-installable"

	// SkipTargetUnwritable: the profile enables a target this build cannot
	// write at all, e.g. codex while research gate R2 is open.
	SkipTargetUnwritable = "target-unwritable"
)

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
