package worker

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type tickArgs struct{ name string }

func (a tickArgs) Kind() string { return a.name }

type recordingInserter struct {
	mu    sync.Mutex
	kinds []string
	opts  []*river.InsertOpts
}

func (r *recordingInserter) Insert(_ context.Context, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kinds = append(r.kinds, args.Kind())
	r.opts = append(r.opts, opts)
	return &rivertype.JobInsertResult{}, nil
}

func (r *recordingInserter) count(kind string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, k := range r.kinds {
		if k == kind {
			n++
		}
	}
	return n
}

// The role inserts its own periodic jobs: River's PeriodicJobs run only on the
// queue database's single elected leader, which is usually another role.
func TestARoleSchedulesItsOwnPeriodicJobs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	rec := &recordingInserter{}
	schedule(ctx, rec, []PeriodicJob{
		{Interval: 20 * time.Millisecond, Args: tickArgs{"fast"}, RunOnStart: true},
		{Interval: time.Hour, Args: tickArgs{"on-start"}, RunOnStart: true},
		{Interval: time.Hour, Args: tickArgs{"later"}},
	}, zerolog.Nop())

	require.Eventually(t, func() bool { return rec.count("fast") >= 3 }, 2*time.Second, 5*time.Millisecond)
	require.Equal(t, 1, rec.count("on-start"))
	require.Zero(t, rec.count("later"), "without RunOnStart nothing is inserted before the first interval")

	rec.mu.Lock()
	for i, opts := range rec.opts {
		require.NotZero(t, opts.UniqueOpts.ByPeriod, "%s must be unique per period so replicas do not double it", rec.kinds[i])
	}
	rec.mu.Unlock()

	cancel()
	time.Sleep(50 * time.Millisecond)
	stopped := rec.count("fast")
	time.Sleep(60 * time.Millisecond)
	require.Equal(t, stopped, rec.count("fast"), "scheduling stops with the context")
}
