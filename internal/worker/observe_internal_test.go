package worker

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/metrics"
)

func TestJobEventsBecomeCountersByKindQueueAndResult(t *testing.T) {
	job := func(state rivertype.JobState) *rivertype.JobRow {
		return &rivertype.JobRow{Kind: "observe-test", Queue: "observe-q", State: state}
	}
	count := func(result string) float64 {
		return testutil.ToFloat64(metrics.JobsTotal.WithLabelValues("observe-test", "observe-q", result))
	}
	before := map[string]float64{}
	for _, r := range []string{"completed", "retried", "discarded", "cancelled", "snoozed"} {
		before[r] = count(r)
	}
	observed := func() uint64 {
		var m dto.Metric
		require.NoError(t, metrics.JobDuration.WithLabelValues("observe-test", "observe-q").(prometheus.Histogram).Write(&m))
		return m.GetHistogram().GetSampleCount()
	}
	durations := observed()

	events := make(chan *river.Event, 8)
	stats := &river.JobStatistics{RunDuration: 1500 * time.Millisecond}
	events <- &river.Event{Kind: river.EventKindJobCompleted, Job: job(rivertype.JobStateCompleted), JobStats: stats}
	events <- &river.Event{Kind: river.EventKindJobCompleted, Job: job(rivertype.JobStateCompleted), JobStats: stats}
	events <- &river.Event{Kind: river.EventKindJobFailed, Job: job(rivertype.JobStateRetryable), JobStats: stats}
	events <- &river.Event{Kind: river.EventKindJobFailed, Job: job(rivertype.JobStateDiscarded), JobStats: stats}
	events <- &river.Event{Kind: river.EventKindJobCancelled, Job: job(rivertype.JobStateCancelled)}
	events <- &river.Event{Kind: river.EventKindJobSnoozed, Job: job(rivertype.JobStateScheduled)}
	events <- &river.Event{Kind: river.EventKindQueuePaused}
	close(events)
	recordJobEvents(events)

	require.Equal(t, before["completed"]+2, count("completed"))
	require.Equal(t, before["retried"]+1, count("retried"))
	require.Equal(t, before["discarded"]+1, count("discarded"))
	require.Equal(t, before["cancelled"]+1, count("cancelled"))
	require.Equal(t, before["snoozed"]+1, count("snoozed"))
	require.Equal(t, durations+4, observed(), "every event carrying run statistics is observed")
}
