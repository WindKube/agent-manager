package view

import "time"

// PendingDeviceAuthorization is what the Connect-the-CLI screen shows before the viewer confirms.
type PendingDeviceAuthorization struct {
	RequestingHost string
	ExpiresAt      time.Time
}

type CLI struct {
	UserCode  string
	Pending   *PendingDeviceAuthorization
	Countdown string

	Unknown bool
	Expired bool
	Decided bool

	SignedOut   bool
	Unavailable bool

	Notice *Notice

	// Command is empty when HubURL is not configured.
	Command string
	HubURL  string
}

func (s CLI) Refused() bool { return s.Unknown || s.Expired || s.Decided }
