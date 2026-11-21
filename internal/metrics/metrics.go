// Package metrics is the process's Prometheus instrumentation. It holds no
// datastore handle; samplers live beside the role that owns the credential.
package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const namespace = "agent_manager"

var (
	JobsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "river_jobs_total",
		Help:      "Jobs worked, by kind, queue and result (completed, retried, discarded, cancelled, snoozed).",
	}, []string{"kind", "queue", "result"})

	JobDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "river_job_duration_seconds",
		Help:      "Time a job spent running in its worker.",
		Buckets:   []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120, 300},
	}, []string{"kind", "queue"})

	QueueJobs = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "river_queue_jobs",
		Help:      "Jobs in the queue database, by queue and state. Sampled periodically.",
	}, []string{"queue", "state"})

	OutboxRelayed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "outbox_relayed_total",
		Help:      "Outbox rows handed to the queue, by job kind.",
	}, []string{"kind"})

	// OutboxOldestPending is a vec with no labels only so that a role that never
	// sets it, which is every role but the api, exports no series at all.
	OutboxOldestPending = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "outbox_oldest_pending_age_seconds",
		Help:      "Age of the oldest outbox row not yet relayed; 0 when none is pending.",
	}, nil)

	FetchesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "fetches_total",
		Help:      "Fetch jobs by source kind and result: stored, unchanged, or the failure reason.",
	}, []string{"source", "result"})

	ScansTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "scans_total",
		Help:      "Recorded scans by verdict.",
	}, []string{"verdict"})

	ScanEngineErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "scan_engine_errors_total",
		Help:      "Second-engine scans that produced no analysis: failed (unreachable or broken) or unanalysable (the package).",
	}, []string{"reason"})

	WebhookDeliveries = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "webhook_deliveries_total",
		Help:      "Webhook delivery attempts by response status class, or error when no response arrived.",
	}, []string{"status"})

	SignatureVerifications = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "signature_verifications_total",
		Help:      "Signature checks on fetched archives by result: verified, invalid, unsigned or error.",
	}, []string{"result"})
)

// StatusClass buckets an HTTP status into 2xx..5xx; 0 means no response.
func StatusClass(status int) string {
	switch {
	case status >= 100 && status < 600:
		return string(rune('0'+status/100)) + "xx"
	default:
		return "error"
	}
}

// Poll calls sample now and then every interval until ctx ends, so database
// samplers never stack queries on slow scrapes.
func Poll(ctx context.Context, interval time.Duration, sample func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		sample(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
