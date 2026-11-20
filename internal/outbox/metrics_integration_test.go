//go:build integration

package outbox_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/metrics"
	"agent-manager/internal/outbox"
)

func TestTheRelayCountsWhatItRelaysAndReportsTheAgeOfWhatItHasNot(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()

	relay := newRelay(t, outbox.RelayConfig{})
	require.NoError(t, relay.Drain(ctx))
	relay.SampleLag(ctx)
	require.Zero(t, testutil.ToFloat64(metrics.OutboxOldestPending.WithLabelValues()), "an empty backlog has no age")

	id := insertPendingRowWithoutNotifying(t, ctx, outbox.KindScan, uuid.NewString())
	_, err := appPool.Exec(ctx, `update outbox set created_at = now() - interval '90 seconds' where id = $1`, id)
	require.NoError(t, err)

	relay.SampleLag(ctx)
	require.InDelta(t, 90, testutil.ToFloat64(metrics.OutboxOldestPending.WithLabelValues()), 10)

	relayed := testutil.ToFloat64(metrics.OutboxRelayed.WithLabelValues(string(outbox.KindScan)))
	require.NoError(t, relay.Drain(ctx))
	require.Equal(t, relayed+1, testutil.ToFloat64(metrics.OutboxRelayed.WithLabelValues(string(outbox.KindScan))))

	relay.SampleLag(ctx)
	require.Zero(t, testutil.ToFloat64(metrics.OutboxOldestPending.WithLabelValues()))
}

type depthProbe struct{}

func (depthProbe) Kind() string { return "depth-probe" }

func TestQueueDepthIsSampledPerQueueAndStateWithZerosForEmptyStates(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()

	client, err := outbox.NewInsertClient(queuePool, nil)
	require.NoError(t, err)

	queue := "depth_" + uuid.NewString()[:8]
	for range 2 {
		_, err = client.Insert(ctx, depthProbe{}, &river.InsertOpts{Queue: queue})
		require.NoError(t, err)
	}
	_, err = client.Insert(ctx, depthProbe{}, &river.InsertOpts{Queue: queue, ScheduledAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)

	outbox.SampleQueues(queuePool, []string{queue}, zerolog.Nop())(ctx)

	require.Equal(t, 2.0, testutil.ToFloat64(metrics.QueueJobs.WithLabelValues(queue, "available")))
	require.Equal(t, 1.0, testutil.ToFloat64(metrics.QueueJobs.WithLabelValues(queue, "scheduled")))
	require.Equal(t, 0.0, testutil.ToFloat64(metrics.QueueJobs.WithLabelValues(queue, "retryable")),
		"a state with no jobs must read 0, not keep its last value")
}
