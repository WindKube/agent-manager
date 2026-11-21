package hub_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"
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

// baseReport uses fixture slugs and revisions, since an invented one 404s and passes for the wrong reason.
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

	// The second call must not reach the wire, and says so rather than returning nil.
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

// The negative control for the exactly-once latch, and the reason for the no-retry policy: the hub
// inserts a new sync_event per call. If the hub ever dedupes, revisit sync_report.go.
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
		"reportSync is additive: a retry after an ambiguous failure would write a second audit row")
}

func TestAFailedReportIsReturnedForTheCallerToWarnAbout(t *testing.T) {
	// A plain classified error lets the verb warn and carry on; unauthorised must not read as unreachable.
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
	// One Report call is one POST, even when the POST fails in the way a retry loop exists for.
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
	rep.Profile = tg.Fixtures.MissingProfile
	err = reporter.Report(context.Background(), rep)
	require.ErrorIs(t, err, hub.ErrNotFound)
	require.Equal(t, 1, counted.count(), "exactly one attempt; there is no idempotency key that would make a second safe")

	// The latch was claimed before the request, so a second call does not retry either.
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
			// Refused before the latch, so a fixed report can still be sent.
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

// countingTransport counts the requests actually issued on the wire.
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

func TestAReportWithAMachineCarriesItsInventorySorted(t *testing.T) {
	tg := startReportFake(t)
	rep := baseReport(tg)
	rep.MachineID = uuid.New()
	rep.OS, rep.Arch, rep.AmctlVersion = "linux", "amd64", " 1.2.3 "
	rep.Installed = []hub.Install{
		{ID: "acme/zeta", Version: "1.0.0", Target: "codex"},
		{ID: "acme/alpha", Version: "2.0.0", Target: "claude-code", Changed: true},
	}
	rep.SkippedComponents = []hub.ComponentSkip{
		{Entry: "acme/alpha", Target: "claude-code", Component: "mcp-server lint", Reason: "no claude CLI"},
	}
	require.NoError(t, reporterFor(t, tg).Report(context.Background(), rep))

	accepted, err := tg.Control.SyncReports()
	require.NoError(t, err)
	require.Len(t, accepted, 1)
	got := accepted[0]
	require.Equal(t, rep.MachineID, *got.MachineId)
	require.Equal(t, "1.2.3", *got.AmctlVersion)
	require.Equal(t, "linux", *got.Os)
	require.Len(t, *got.Installed, 2)
	require.Equal(t, "acme/alpha", (*got.Installed)[0].Id)
	require.True(t, *(*got.Installed)[0].Changed)
	require.Nil(t, (*got.Installed)[1].Changed)
	require.Equal(t, "mcp-server lint", (*got.SkippedComponents)[0].Component)
}

func TestAReportWithoutAMachineSendsNoInventory(t *testing.T) {
	tg := startReportFake(t)
	rep := baseReport(tg)
	rep.Installed = []hub.Install{{ID: "acme/alpha", Version: "2.0.0", Target: "claude-code"}}
	require.NoError(t, reporterFor(t, tg).Report(context.Background(), rep))

	accepted, err := tg.Control.SyncReports()
	require.NoError(t, err)
	require.Nil(t, accepted[0].MachineId)
	require.Nil(t, accepted[0].Installed)
}

func TestAMachineWithNothingInstalledSendsAnEmptyList(t *testing.T) {
	tg := startReportFake(t)
	rep := baseReport(tg)
	rep.MachineID = uuid.New()
	require.NoError(t, reporterFor(t, tg).Report(context.Background(), rep))

	accepted, err := tg.Control.SyncReports()
	require.NoError(t, err)
	require.NotNil(t, accepted[0].Installed, "an empty list clears the hub's installs for the profile")
	require.Empty(t, *accepted[0].Installed)
}

func TestAnInstalledTargetOutsideTheContractIsRefusedLocally(t *testing.T) {
	tg := startReportFake(t)
	rep := baseReport(tg)
	rep.MachineID = uuid.New()
	rep.Installed = []hub.Install{{ID: "acme/alpha", Version: "2.0.0", Target: "agents-md"}}
	require.ErrorIs(t, reporterFor(t, tg).Report(context.Background(), rep), hub.ErrReportInput)
}
