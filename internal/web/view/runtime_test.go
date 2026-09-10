package view_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/view"
)

func TestQueueCountsRowsCoverEveryRiverStateAndToneOnlyTheOnesThatNeedIt(t *testing.T) {
	q := view.QueueCounts{
		Queue: "fetch", Available: 1, Scheduled: 2, Running: 3,
		Retryable: 4, Completed: 5, Discarded: 6, Cancelled: 7,
	}
	rows := q.Rows()

	labels := make(map[string]view.StateRow, len(rows))
	for _, row := range rows {
		labels[row.Label] = row
	}
	for _, label := range []string{"Available", "Scheduled", "Running", "Retryable", "Completed", "Discarded", "Cancelled"} {
		require.Containsf(t, labels, label, "River's %s state is missing from the table", label)
	}

	// Retryable and Discarded are the two states worth a reader's attention;
	// nothing else carries a tone.
	require.Equal(t, "warn", labels["Retryable"].Tone)
	require.Equal(t, "dan", labels["Discarded"].Tone)
	for _, neutral := range []string{"Available", "Scheduled", "Running", "Completed", "Cancelled"} {
		require.Emptyf(t, labels[neutral].Tone, "%s should carry no tone", neutral)
	}
}

func TestQueueCountsOtherIsAppendedOnlyWhenNonzero(t *testing.T) {
	require.Len(t, view.QueueCounts{Queue: "fetch"}.Rows(), 7, "a zero Other must not add an eighth row")

	withOther := view.QueueCounts{Queue: "fetch", Other: 2}.Rows()
	require.Len(t, withOther, 8)
	require.Equal(t, int64(2), withOther[7].Count)
	require.Equal(t, "warn", withOther[7].Tone, "an unrecognised state is worth a reader's attention too")
}

func TestRuntimeCardsSumAcrossEveryQueueAndToneOnlyWhatNeedsAttention(t *testing.T) {
	r := view.Runtime{Queues: []view.QueueCounts{
		{Queue: "fetch", Available: 2, Running: 1, Retryable: 1, Completed: 100},
		{Queue: "scan", Scheduled: 3, Discarded: 2, Completed: 50},
	}}
	cards := r.Cards()
	require.Len(t, cards, 4)

	byLabel := make(map[string]view.StatCard, len(cards))
	for _, c := range cards {
		byLabel[c.Label] = c
	}

	// Active is available + scheduled + running, summed over both queues:
	// 2+1 (fetch) + 3 (scan) = 6.
	require.Equal(t, "6", byLabel["Active jobs"].Value)
	require.Equal(t, "1", byLabel["Retrying"].Value)
	require.Equal(t, "warn", byLabel["Retrying"].Tone)
	require.Equal(t, "2", byLabel["Discarded"].Value)
	require.Equal(t, "dan", byLabel["Discarded"].Tone)
	require.Equal(t, "150", byLabel["Completed"].Value)
}

func TestRuntimeCardsCarryNoToneWhenNothingIsWrong(t *testing.T) {
	cards := view.Runtime{Queues: []view.QueueCounts{{Queue: "fetch", Completed: 10}}}.Cards()
	for _, c := range cards {
		require.Emptyf(t, c.Tone, "%s should carry no tone when its figure is zero", c.Label)
	}
}

func TestBarsScaleToThePeakAndNeverExceedTheMaxHeight(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	r := view.Runtime{History: []view.RunBucket{
		{StartsAt: now.Add(-2 * time.Hour), Fetch: 5, Scan: 5}, // total 10, the peak
		{StartsAt: now.Add(-1 * time.Hour), Fetch: 0, Scan: 0}, // a genuinely quiet hour
		{StartsAt: now, Fetch: 10, Scan: 0},
	}}
	bars := r.Bars()
	require.Len(t, bars, 3)

	require.Equal(t, view.ChartBarMaxHeight/2, bars[0].FetchHeight)
	require.Equal(t, view.ChartBarMaxHeight/2, bars[0].ScanHeight)
	require.Zero(t, bars[1].FetchHeight)
	require.Zero(t, bars[1].ScanHeight)
	// The last bucket's total (10) equals the peak (10), so it draws the
	// full height, not half of it.
	require.Equal(t, view.ChartBarMaxHeight, bars[2].FetchHeight)
	require.LessOrEqual(t, bars[2].FetchHeight+bars[2].ScanHeight, view.ChartBarMaxHeight)
}

func TestBarsWithNoHistoryDrawsNoBarsRatherThanDividingByZero(t *testing.T) {
	require.NotPanics(t, func() {
		bars := view.Runtime{History: []view.RunBucket{{Fetch: 0, Scan: 0}}}.Bars()
		require.Zero(t, bars[0].FetchHeight)
		require.Zero(t, bars[0].ScanHeight)
	})
}

// TestChartLabelsShowOnlyEveryFourthBarAndAlwaysTheLast is what keeps 24
// hourly buckets readable rather than a wall of overlapping text, while
// still labelling the most recent bar so a reader can place "now".
func TestChartLabelsShowOnlyEveryFourthBarAndAlwaysTheLast(t *testing.T) {
	history := make([]view.RunBucket, 10)
	r := view.Runtime{History: history}
	bars := r.Bars()

	for i, bar := range bars {
		want := i%4 == 0 || i == len(bars)-1
		require.Equalf(t, want, bar.ShowLabel, "bar %d", i)
	}
}

func TestBucketLabelPluralisesHoursAndMinutes(t *testing.T) {
	require.Equal(t, "1 hour", view.Runtime{BucketMinutes: 60}.BucketLabel())
	require.Equal(t, "2 hours", view.Runtime{BucketMinutes: 120}.BucketLabel())
	require.Equal(t, "15 minutes", view.Runtime{BucketMinutes: 15}.BucketLabel())
	require.Equal(t, "", view.Runtime{}.BucketLabel(), "an unset width says nothing rather than guessing a unit")
}

func TestLatestErrorIsTheMostRecentAttemptAndEmptyWhenNoneRecorded(t *testing.T) {
	require.Empty(t, view.JobRow{}.LatestError(), "a job discarded by cancellation records no error")

	row := view.JobRow{Errors: []view.ErrorEntry{
		{Attempt: 1, Error: "first failure"},
		{Attempt: 2, Error: "second failure"},
	}}
	require.Equal(t, "second failure", row.LatestError())
}

func TestNoDiscardedAndNoRetryingReportEachListIndependently(t *testing.T) {
	empty := view.Runtime{}
	require.True(t, empty.NoDiscarded())
	require.True(t, empty.NoRetrying())

	withDiscarded := view.Runtime{Discarded: []view.JobRow{{ID: 1}}}
	require.False(t, withDiscarded.NoDiscarded())
	require.True(t, withDiscarded.NoRetrying())
}

// The pair's two bars stand side by side, so each is measured against the
// tallest single bar rather than the tallest pair total. Scaling to the total
// would draw an hour that ran 10 fetches and 10 scans shorter than one that
// ran 12 fetches alone, which is the opposite of what happened.
func TestBarsAreScaledToTheTallestSingleBarNotTheTallestPairTotal(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	r := view.Runtime{History: []view.RunBucket{
		{StartsAt: now.Add(-time.Hour), Fetch: 10, Scan: 10},
		{StartsAt: now, Fetch: 12, Scan: 0},
	}}

	require.EqualValues(t, 12, r.ChartPeak())

	bars := r.Bars()
	require.Equal(t, view.ChartBarMaxHeight, bars[1].FetchHeight,
		"the tallest single bar draws the full height")
	require.Greater(t, bars[0].FetchHeight, view.ChartBarMaxHeight/2,
		"a busier hour split across both queues must not draw shorter than half")
}
