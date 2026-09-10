package view

import (
	"strconv"
	"time"
)

// QueueCounts is one queue's jobs by River's own state — the vocabulary is
// River's, not this screen's, and none of the seven is folded into another:
// a queue stalled on Available reads differently from one stuck Retryable.
type QueueCounts struct {
	Queue                                                                            string
	Available, Scheduled, Running, Retryable, Completed, Discarded, Cancelled, Other int64
}

// Label is the card's title. Anything besides the two queues this hub
// registers today still renders under its own name rather than vanishing.
func (q QueueCounts) Label() string {
	switch q.Queue {
	case "fetch":
		return "Fetch queue"
	case "scan":
		return "Scan queue"
	default:
		return q.Queue + " queue"
	}
}

// Active is work not yet finished: waiting to run or currently running.
func (q QueueCounts) Active() int64 { return q.Available + q.Scheduled + q.Running }

// StateRow is one row of a queue card's state table.
type StateRow struct {
	Label string
	Count int64
	Tone  string
}

// Rows is one queue card's state table, ordered so that what is still to
// happen comes before what has already been decided. Other is appended only
// when it is nonzero: a permanent empty row for a state this screen was never
// taught about would be noise.
func (q QueueCounts) Rows() []StateRow {
	rows := []StateRow{
		{Label: "Available", Count: q.Available},
		{Label: "Running", Count: q.Running},
		{Label: "Scheduled", Count: q.Scheduled},
		{Label: "Retryable", Count: q.Retryable, Tone: toneIfPositive(q.Retryable, "warn")},
		{Label: "Discarded", Count: q.Discarded, Tone: toneIfPositive(q.Discarded, "dan")},
		{Label: "Completed", Count: q.Completed},
		{Label: "Cancelled", Count: q.Cancelled},
	}
	if q.Other > 0 {
		rows = append(rows, StateRow{Label: "Other (unrecognised state)", Count: q.Other, Tone: "warn"})
	}
	return rows
}

func toneIfPositive(n int64, tone string) string {
	if n > 0 {
		return tone
	}
	return ""
}

// ErrorEntry is one attempt River recorded on a job row.
type ErrorEntry struct {
	At      string
	Attempt int
	Error   string
}

// JobRow is one discarded or retrying job.
type JobRow struct {
	ID          int64
	Queue       string
	Kind        string
	Attempt     int
	MaxAttempts int
	// When is when a discarded job stopped retrying, or when a retrying one
	// is next scheduled to run — the caller sets which, since the two mean
	// opposite things and neither list holds both.
	When   string
	Errors []ErrorEntry
}

// LatestError is the most recent attempt's message, "" when River recorded
// none — which happens for a job discarded by a cancellation rather than a
// failure.
func (j JobRow) LatestError() string {
	if len(j.Errors) == 0 {
		return ""
	}
	return j.Errors[len(j.Errors)-1].Error
}

// RunBucket is one interval of the run-history chart, as the api reported
// it: raw counts, not yet scaled to a bar height.
type RunBucket struct {
	StartsAt time.Time
	Fetch    int64
	Scan     int64
}

// ChartBarMaxHeight is the tallest a bar may draw, in pixels. It is mirrored
// by .am-runtime-bar-track's height in assets/input.css — the two must
// agree, or a bar taller than its track clips.
const ChartBarMaxHeight = 120

// RunBar is one bucket, scaled for rendering: two stacked segments and the
// x-axis label the chart shows beneath it.
type RunBar struct {
	Label     string
	ShowLabel bool
	Fetch     int64
	Scan      int64
	// FetchHeight and ScanHeight are the pixel heights of the pair's two
	// bars, each at most ChartBarMaxHeight.
	FetchHeight int
	ScanHeight  int
}

// Total is what the bar's height represents.
func (b RunBar) Total() int64 { return b.Fetch + b.Scan }

// Runtime is the whole screen: the job queue's own state, its runners'
// errors, and when they ran.
type Runtime struct {
	Queues        []QueueCounts
	Discarded     []JobRow
	Retrying      []JobRow
	History       []RunBucket
	BucketMinutes int

	GovernanceState
}

// Cards is the headline row, summed across every queue: a reader asks "is
// the pipeline healthy" before they ask "which queue".
func (r Runtime) Cards() []StatCard {
	var active, retrying, discarded, completed int64
	for _, q := range r.Queues {
		active += q.Active()
		retrying += q.Retryable
		discarded += q.Discarded
		completed += q.Completed
	}

	cards := []StatCard{
		{Label: "Active jobs", Value: formatCount(active), Note: "available, scheduled or running"},
		{Label: "Retrying", Value: formatCount(retrying), Note: "failed at least once, will run again"},
		{Label: "Discarded", Value: formatCount(discarded), Note: "retries exhausted, needs attention"},
		{Label: "Completed", Value: formatCount(completed), Note: "across every queue"},
	}
	if retrying > 0 {
		cards[1].Tone = "warn"
	}
	if discarded > 0 {
		cards[2].Tone = "dan"
	}
	return cards
}

func formatCount(n int64) string {
	return strconv.FormatInt(n, 10)
}

// NoDiscarded and NoRetrying back the two lists' empty states, which are
// good news here rather than an absence of data.
func (r Runtime) NoDiscarded() bool { return len(r.Discarded) == 0 }
func (r Runtime) NoRetrying() bool  { return len(r.Retrying) == 0 }

// BucketLabel is the caption stating what one bar covers, so the chart is
// never read without knowing its own units.
func (r Runtime) BucketLabel() string {
	if r.BucketMinutes <= 0 {
		return ""
	}
	if r.BucketMinutes%60 == 0 {
		return plural(r.BucketMinutes/60, "hour")
	}
	return plural(r.BucketMinutes, "minute")
}

// ChartPeak is the tallest single bar, which is one queue's count and not
// the pair's total: the bars in a pair stand side by side, so each one has to
// be readable against the same axis on its own. Zero reads as "0", not as an
// empty axis.
func (r Runtime) ChartPeak() int64 {
	var peak int64
	for _, b := range r.History {
		peak = max(peak, b.Fetch, b.Scan)
	}
	return peak
}

// ChartPeakLabel is ChartPeak rendered.
func (r Runtime) ChartPeakLabel() string { return formatCount(r.ChartPeak()) }

// Title is the bar's hover text: the one place the chart states its exact
// numbers rather than a height a reader has to eyeball.
func (b RunBar) Title() string {
	return b.Label + " UTC — fetch " + formatCount(b.Fetch) + ", scan " + formatCount(b.Scan)
}

// Bars scales History into pixel heights. A label prints only every fourth
// bar (and always the last), so 24 hourly buckets read as a chart rather
// than a wall of overlapping text.
func (r Runtime) Bars() []RunBar {
	peak := r.ChartPeak()
	bars := make([]RunBar, len(r.History))
	for i, b := range r.History {
		bar := RunBar{Label: b.StartsAt.UTC().Format("15:04"), Fetch: b.Fetch, Scan: b.Scan}
		if peak > 0 {
			bar.FetchHeight = int(b.Fetch * ChartBarMaxHeight / peak)
			bar.ScanHeight = int(b.Scan * ChartBarMaxHeight / peak)
		}
		bar.ShowLabel = i%4 == 0 || i == len(r.History)-1
		bars[i] = bar
	}
	return bars
}
