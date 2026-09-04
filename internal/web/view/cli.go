package view

import "time"

// PendingDeviceAuthorization is what the Connect-the-CLI screen shows before the
// viewer confirms (001 FR-041): the host the code is bound to, and when it
// expires.
type PendingDeviceAuthorization struct {
	RequestingHost string
	ExpiresAt      time.Time
}

// CLI is the Connect-the-CLI screen (003 US6).
//
// Pending and the three refusal flags are mutually exclusive outcomes of one
// lookup: a code names an authorisation still awaiting a decision, or it does
// not, for exactly one of three distinguishable reasons (FR-042). Command and
// HubURL are shown whenever there is no code to look up at all — 001 US6
// scenario 4, the screen's own empty state.
type CLI struct {
	// UserCode is what was looked up, kept for redisplay in the form. Never
	// re-derived from a refusal — a refusal names a reason, not a corrected code.
	UserCode string
	Pending  *PendingDeviceAuthorization
	// Countdown is Pending's expiry, rendered against the request's clock. Empty
	// unless Pending is set.
	Countdown string

	Unknown bool
	Expired bool
	Decided bool

	SignedOut   bool
	Unavailable bool

	// Notice is the outcome of a confirm action, shown once (post-redirect-get,
	// like the Scanner screen's decisions).
	Notice *Notice

	// Command is the real `amctl login` invocation, and HubURL the real address
	// it names — both read from configuration, never invented (FR-041 scenario
	// 4). Command is empty when HubURL is not configured; the screen must say so
	// honestly rather than print a command that starts wrong.
	Command string
	HubURL  string
}

// Refused reports whether the lookup ended in one of FR-042's three
// distinguishable reasons.
func (s CLI) Refused() bool { return s.Unknown || s.Expired || s.Decided }
