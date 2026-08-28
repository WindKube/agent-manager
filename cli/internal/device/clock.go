package device

import (
	"context"
	"time"
)

// Clock is the whole of this package's access to time. Everything the state
// machine does about timing — the expiry, the interval, the wait between polls
// — goes through one of these two methods.
//
// It is an interface and not a convenience because the alternative is
// untestable: a poller that calls time.Sleep can only be shown to honour a
// five second interval by taking five seconds to do it, so the suite that
// proves FR-002 would take minutes and be deleted by the first person in a
// hurry. With a Clock, the same proof is instant and exact.
//
// device_test.go asserts mechanically that no file in this package other than
// clock.go names time.Now, time.Sleep or time.After — see
// TestPackageTouchesTheClockOnlyThroughClock.
type Clock interface {
	// Now is the current time. Only ever used to compare against the device
	// code's expiry.
	Now() time.Time
	// Wait blocks for d, returning nil when the whole of d elapsed and
	// ctx.Err() when the context ended first. A d of zero or less returns
	// immediately with ctx.Err().
	//
	// The two outcomes must stay distinguishable: a cancelled login and a hub
	// that refused are different sentences to print, and collapsing them is
	// how a Ctrl-C comes out as "authorisation denied".
	Wait(ctx context.Context, d time.Duration) error
}

// System is the real clock, and the only code in this package permitted to
// read the wall clock or block. The state machine never constructs one: the
// caller injects it, which is what leaves the tests free to inject a fake.
func System() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) Wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	// A timer rather than time.After: time.After's channel is not collected
	// until it fires, so a cancelled login with a long interval outstanding
	// would keep the timer alive for the rest of the process's life.
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
