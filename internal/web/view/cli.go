package view

import "time"

// PendingDeviceAuthorization is what the Connect-the-CLI screen shows before the
// viewer confirms: the host the code is bound to, and when it expires.
type PendingDeviceAuthorization struct {
	RequestingHost string
	ExpiresAt      time.Time
}

// CLI is the Connect-the-CLI screen.
type CLI struct {
	// UserCode is what was looked up, kept for redisplay in the form.
	UserCode string
	Pending  *PendingDeviceAuthorization
	// Countdown is Pending's expiry, rendered against the request's clock.
	Countdown string

	Unknown bool
	Expired bool
	Decided bool

	SignedOut   bool
	Unavailable bool

	// Notice is the outcome of a confirm action, shown once.
	Notice *Notice

	// Command is the real `amctl login` invocation and HubURL the real address it
	// names, both read from configuration. Command is empty when HubURL is not
	// configured.
	Command string
	HubURL  string
}

// Refused reports whether the lookup ended in one of the three distinguishable
// refusal reasons.
func (s CLI) Refused() bool { return s.Unknown || s.Expired || s.Decided }
