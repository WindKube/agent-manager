package hub_test

// `package hub_test` for the same reason bundles_test.go is: this file drives
// the fake hub and internal/hub/fake imports internal/hub, so an in-package
// test file could not import it.
//
// THE LOAD-BEARING ASSERTION IN THIS FILE IS THE NEGATIVE ONE.
// TestASecondReportOfTheSameSyncWouldBeAdditiveServerSide is executed rather
// than argued: it posts the same body twice straight at the hub and shows the
// accepted-report list grows to two. That is what makes the no-retry policy in
// sync_report.go a consequence instead of an opinion, and it is also the
// negative control for the exactly-once latch — without it,
// TestASyncIsReportedExactlyOnce could pass against a server that deduped and
// prove nothing about this client.

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/hub/fake"
)

func startReportFake(t *testing.T) fake.Target {
	t.Helper()
	h := fake.New(fake.Options{TLS: true})
	t.Cleanup(h.Close)
	return h.Target()
}

func reporterFor(t *testing.T, tg fake.Target) *hub.Reporter {
	t.Helper()
	client, err := hub.New(hub.Config{URL: tg.BaseURL, Token: tg.Token, HTTPClient: tg.HTTPClient})
	require.NoError(t, err)
	rep, err := hub.NewReporter(client)
	require.NoError(t, err)
	return rep
}

// baseReport is a report the fake accepts, built from the fixtures so no slug
// or revision is invented by a test — an invented one is a 404 against the real
// hub, and a 404 is a green test for the wrong reason.
func baseReport(tg fake.Target) hub.Report {
	return hub.Report{
		Profile:  tg.Fixtures.Profile,
		Revision: int(tg.Fixtures.HeadRevision),
		Host:     "report-test-host",
		Targets:  []string{"claude-code"},
	}
}

func TestASyncIsReportedExactlyOnce(t *testing.T) {
	tg := startReportFake(t)
	reporter := reporterFor(t, tg)
	rep := baseReport(tg)

	require.False(t, reporter.Reported(rep), "nothing has been reported yet")
	require.NoError(t, reporter.Report(context.Background(), rep))
	require.True(t, reporter.Reported(rep))

	// The second call must not reach the wire, and it says so rather than
	// returning nil: a duplicate is a caller bug, and the worst a loud one can
	// do is print a line.
	err := reporter.Report(context.Background(), rep)
	require.ErrorIs(t, err, hub.ErrAlreadyReported)

	accepted, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, accepted, 1, "the hub accepted exactly one report for one sync")
	require.Equal(t, rep.Profile, accepted[0].Profile)
	require.Equal(t, int64(rep.Revision), accepted[0].Revision)
	require.Equal(t, rep.Host, accepted[0].Host)
	require.Equal(t, []hub.SyncReportTargets{"claude-code"}, accepted[0].Targets)
	require.Nil(t, accepted[0].Skipped, "an empty local skip list is omitted, not sent as []")
}

// TestASecondReportOfTheSameSyncWouldBeAdditiveServerSide bypasses Reporter
// deliberately and posts through the hub client twice, to
// establish what the SERVER does with a duplicate. The hub's own
// internal/api/commands/sync.go inserts a models.NewID() sync_event with no
// ON CONFLICT and no natural key, sync_event's only constraints are its primary
// key and three foreign keys, and its integration test asserts a count delta
// of exactly one per call — so two calls are two rows. The fake models that
// by appending, and this test pins it: if a future hub ever deduped, this
// test fails and sync_report.go's no-retry comment is the thing to revisit.
func TestASecondReportOfTheSameSyncWouldBeAdditiveServerSide(t *testing.T) {
	tg := startReportFake(t)
	client, err := hub.New(hub.Config{URL: tg.BaseURL, Token: tg.Token, HTTPClient: tg.HTTPClient})
	require.NoError(t, err)

	body := hub.SyncReport{
		Profile:  tg.Fixtures.Profile,
		Revision: tg.Fixtures.HeadRevision,
		Host:     "report-test-host",
		Targets:  []hub.SyncReportTargets{"claude-code"},
	}
	require.NoError(t, client.ReportSync(context.Background(), body))
	require.NoError(t, client.ReportSync(context.Background(), body))

	accepted, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, accepted, 2,
		"reportSync is additive: a retry after an ambiguous failure would write a second audit row and break hub SC-008")
}

func TestAFailedReportIsReturnedForTheCallerToWarnAbout(t *testing.T) {
	// The sync must not fail because the report did. This package's half of
	// that is returning a plain error carrying its own classification, so the
	// verb can put one sentence on stderr and carry on. The unauthorised
	// case is used because it is the one a caller must not mistake for
	// "unreachable".
	tg := startReportFake(t)
	client, err := hub.New(hub.Config{URL: tg.BaseURL, Token: "not-a-token", HTTPClient: tg.HTTPClient})
	require.NoError(t, err)
	reporter, err := hub.NewReporter(client)
	require.NoError(t, err)

	err = reporter.Report(context.Background(), baseReport(tg))
	require.Error(t, err)
	require.ErrorIs(t, err, hub.ErrUnauthorised)
	require.Equal(t, hub.ClassUnauthorised, hub.ClassOf(err))

	accepted, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Empty(t, accepted)
}

func TestAFailedReportIsNotRetried(t *testing.T) {
	// Asserted on the request count rather than inferred from the absence of
	// a loop: one Report call is one POST, even
	// when the POST fails in the way a retry loop exists for.
	tg := startReportFake(t)
	counted := &countingTransport{next: tg.HTTPClient.Transport}
	client, err := hub.New(hub.Config{
		URL:        tg.BaseURL,
		Token:      tg.Token,
		HTTPClient: &http.Client{Transport: counted},
	})
	require.NoError(t, err)
	reporter, err := hub.NewReporter(client)
	require.NoError(t, err)

	rep := baseReport(tg)
	// A profile that does not exist: the hub answers 404, which is terminal and
	// must not be retried either.
	rep.Profile = tg.Fixtures.MissingProfile
	err = reporter.Report(context.Background(), rep)
	require.ErrorIs(t, err, hub.ErrNotFound)
	require.Equal(t, 1, counted.count(), "exactly one attempt; there is no idempotency key that would make a second safe")

	// And the latch was claimed before the request, so the failure is not
	// retried by a second Report call either.
	require.ErrorIs(t, reporter.Report(context.Background(), rep), hub.ErrAlreadyReported)
	require.Equal(t, 1, counted.count())
}

func TestReportsThisClientRefusesToSend(t *testing.T) {
	tg := startReportFake(t)
	reporter := reporterFor(t, tg)

	cases := []struct {
		name   string
		mutate func(*hub.Report)
		expect string
	}{
		{
			name:   "head must be resolved to a number before it is reported",
			mutate: func(r *hub.Report) { r.Revision = 0 },
			expect: "revision 0",
		},
		{
			name:   "a negative revision is not a revision",
			mutate: func(r *hub.Report) { r.Revision = -1 },
			expect: "revision -1",
		},
		{
			name:   "a report with no profile names nothing the hub can file",
			mutate: func(r *hub.Report) { r.Profile = "  " },
			expect: "no profile slug",
		},
		{
			name:   "a report with no host has no audit subject",
			mutate: func(r *hub.Report) { r.Host = "" },
			expect: "no host",
		},
		{
			name:   "no target means nothing was written",
			mutate: func(r *hub.Report) { r.Targets = nil },
			expect: "names no target",
		},
		{
			name:   "a target the contract does not define is refused, not dropped",
			mutate: func(r *hub.Report) { r.Targets = []string{"claude-code", "emacs"} },
			expect: `target "emacs"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := baseReport(tg)
			tc.mutate(&rep)
			err := reporter.Report(context.Background(), rep)
			require.ErrorIs(t, err, hub.ErrReportInput)
			require.ErrorContains(t, err, tc.expect)
			// Refused before the latch, so fixing the report and re-reporting
			// still works. A validation failure that burned the one attempt
			// would turn a client bug into a permanently missing audit row.
			require.False(t, reporter.Reported(rep))
		})
	}

	accepted, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Empty(t, accepted, "nothing this client refuses reaches the hub")
}

func TestTheReportBodyIsNormalisedSoOneSyncIsOneBody(t *testing.T) {
	tg := startReportFake(t)
	reporter := reporterFor(t, tg)

	rep := baseReport(tg)
	rep.Targets = []string{"codex", "claude-code", "claude-code"}
	rep.SkippedLocally = []string{"contoso/gated", "acme/x", "contoso/gated", "  ", ""}
	require.NoError(t, reporter.Report(context.Background(), rep))

	accepted, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, accepted, 1)
	require.Equal(t, []hub.SyncReportTargets{"claude-code", "codex"}, accepted[0].Targets,
		"deduplicated and sorted, so two orderings of one sync are one body")
	require.NotNil(t, accepted[0].Skipped)
	require.Equal(t, []string{"acme/x", "contoso/gated"}, *accepted[0].Skipped)
}

func TestAReporterNeedsAHub(t *testing.T) {
	_, err := hub.NewReporter(nil)
	require.ErrorContains(t, err, "no hub given")
}

// countingTransport counts the requests this client actually issued. The count
// is taken on the wire and not inferred from the absence of a retry loop.
type countingTransport struct {
	next http.RoundTripper

	mu sync.Mutex
	n  int
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	next := c.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(req)
}

func (c *countingTransport) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
