package archiveguard

import (
	"context"
	"fmt"
	"io"
	"time"
)

// Clock is an extraction's wall-clock budget layered on the caller's context.
type Clock struct {
	parent context.Context
	ctx    context.Context
	budget time.Duration
}

// StartClock starts a budget of d on top of ctx. The caller must call cancel.
func StartClock(ctx context.Context, d time.Duration) (c *Clock, cancel context.CancelFunc) {
	cctx, cancel := context.WithTimeout(ctx, d)
	return &Clock{parent: ctx, ctx: cctx, budget: d}, cancel
}

// Err returns nil while time remains. The caller's own cancellation passes through wrapped, never as
// a Violation, since a shutdown is not an archive defect; the parent is checked first because the
// budget's context inherits its deadline.
func (c *Clock) Err() error {
	if err := c.parent.Err(); err != nil {
		return fmt.Errorf("extraction stopped: %w", err)
	}
	if err := c.ctx.Err(); err != nil {
		return &Violation{Kind: KindTimeout, Rule: ReasonTimeBudget, Detail: c.budget.String(), Cause: err}
	}
	return nil
}

// ClockReader fails every Read once alive does, so a trickling peer cannot
// outlast the budget. It cannot interrupt a Read that blocks forever.
func ClockReader(r io.Reader, alive func() error) io.Reader {
	return &clockReader{r: r, alive: alive}
}

type clockReader struct {
	r     io.Reader
	alive func() error
}

func (c *clockReader) Read(p []byte) (int, error) {
	if err := c.alive(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
