package worker

import (
	"maps"
	"slices"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"agent-manager/internal/metrics"
)

// recordJobEvents turns River's job events into counters and the run-time
// histogram until events closes.
func recordJobEvents(events <-chan *river.Event) {
	for event := range events {
		if event.Job == nil {
			continue
		}
		result := jobResult(event)
		if result == "" {
			continue
		}
		metrics.JobsTotal.WithLabelValues(event.Job.Kind, event.Job.Queue, result).Inc()
		if event.JobStats != nil {
			metrics.JobDuration.WithLabelValues(event.Job.Kind, event.Job.Queue).
				Observe(event.JobStats.RunDuration.Seconds())
		}
	}
}

func jobResult(event *river.Event) string {
	switch event.Kind {
	case river.EventKindJobCompleted:
		return "completed"
	case river.EventKindJobCancelled:
		return "cancelled"
	case river.EventKindJobSnoozed:
		return "snoozed"
	case river.EventKindJobFailed:
		if event.Job.State == rivertype.JobStateDiscarded {
			return "discarded"
		}
		return "retried"
	}
	return ""
}

var jobEventKinds = []river.EventKind{
	river.EventKindJobCompleted,
	river.EventKindJobCancelled,
	river.EventKindJobSnoozed,
	river.EventKindJobFailed,
}

func queueNames(def Definition) []string {
	return slices.Sorted(maps.Keys(def.Queues))
}
