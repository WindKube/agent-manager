package device

import (
	"context"
	"time"
)

// Clock is the whole of this package's access to time, so a fake can prove
// polling timing without actually waiting for it. No file but this one may
// call time.Now, time.Sleep or time.After.
type Clock interface {
	Now() time.Time
	// Wait blocks for d, returning nil when the whole of d elapsed and
	// ctx.Err() when the context ended first, so a cancelled login and a hub
	// refusal stay distinguishable to the caller.
	Wait(ctx context.Context, d time.Duration) error
}

// System is the real clock; the caller injects it so tests can inject a fake.
func System() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) Wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	// time.NewTimer, not time.After: its channel is stopped explicitly, while
	// time.After's leaks until it fires, keeping a cancelled long wait alive.
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
