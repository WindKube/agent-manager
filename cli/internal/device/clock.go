package device

import (
	"context"
	"time"
)

// Clock is this package's only access to time, so a fake can prove polling timing.
type Clock interface {
	Now() time.Time
	// Wait returns ctx.Err() if the context ends before d elapses, else nil.
	Wait(ctx context.Context, d time.Duration) error
}

// System is the real clock.
func System() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) Wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	// Not time.After: its timer lives until it fires, keeping a cancelled long wait alive.
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
