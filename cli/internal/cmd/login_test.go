// This file covers T030 (login), T031 (logout) and T033. logout's assertions
// live here rather than in a logout_test.go because the two verbs share every
// helper below and are the two halves of one requirement: login writes exactly
// one credential and logout removes exactly that one.
//
// HOW THESE TESTS ASSERT, AND WHY IT LOOKS AWKWARD.
//
// Nothing here prints the captured output of a login. The diagnostic stream
// carries the user code and the verification_uri_complete URL, and that URL
// embeds the code as `?user_code=...` — precisely the shape
// internal/leakscan's run-wide scan hunts for in the whole suite's output. A
// require.Contains that failed would print its haystack, put the code into the
// output the SC-010 gate reads, and turn one red test into a permanent second
// failure in a different package. So assertions over these buffers use
// require.True/False with a hand-written message and never hand testify the
// haystack — the same discipline leakscan_test.go applies to itself.
//
// For the same reason no test in this file uses leakscan's sentinel user code:
// a display assertion needs the fake hub's own randomly generated code, which
// it has to read back anyway in order to approve the authorisation.
package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/credentials"
	"github.com/WindKube/agent-manager/cli/internal/device"
	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/hub/fake"
	"github.com/WindKube/agent-manager/cli/internal/output"
)

// testHost is the hostname bound to the authorisation, injected so the test
// does not depend on the machine it runs on.
const testHost = "login-test-host"

// advertisedInterval is what the fake hub puts in `interval`. It is ONE SECOND
// and not the five the RFC defaults to, so an assertion that the client waited
// this long proves the value came off the wire rather than out of
// internal/device's own default.
const advertisedInterval = time.Second

// ---------------------------------------------------------------- helpers

// syncBuffer is an io.Writer a test can read while another goroutine writes to
// it. login blocks waiting for approval, so the code it printed has to be
// readable before it returns, and a bytes.Buffer read from two goroutines is a
// data race the -race build correctly refuses.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// gateClock is device.Clock with the sleeping taken out and the ordering put
// in. Wait records the duration it was asked for, advances the clock by exactly
// that much, and then blocks until the test releases it.
//
// The recording is what proves FR-002: the durations are the intervals the
// client was told to honour, and they are asserted against what the fake
// advertised. The blocking is what makes the suite deterministic — a test can
// be certain login has polled once and is now between polls, which is the only
// moment at which it can approve, deny or expire the authorisation and know
// which poll will see it.
//
// The clock is also the FAKE HUB's clock (fake.Options.Now), deliberately. The
// fake enforces the interval it advertised, so if the client's notion of time
// and the server's disagreed, a client that waited exactly as long as it was
// told would still earn slow_down.
type gateClock struct {
	mu      sync.Mutex
	now     time.Time
	waits   []time.Duration
	release chan struct{}
}

func newGateClock() *gateClock {
	return &gateClock{
		now:     time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC),
		release: make(chan struct{}),
	}
}

func (c *gateClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *gateClock) Wait(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.waits = append(c.waits, d)
	c.now = c.now.Add(d)
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.release:
		return nil
	}
}

func (c *gateClock) recorded() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

// waitForFirstPause blocks until login has polled once and parked between
// polls. It is the synchronisation point every negative case needs.
func (c *gateClock) waitForFirstPause(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(c.recorded()) > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("login never paused between polls, so the test cannot say which poll saw its change")
}

func (c *gateClock) letItPoll() { close(c.release) }

// steppingClock is device.Clock with no gate in it: Wait advances the clock by
// exactly what it was asked for and returns immediately.
//
// It exists because gateClock cannot serve a test that has to observe what a
// MISBEHAVING flow does. gateClock's Wait parks until the test releases it, so a
// flow that polls when it should not would hang the suite until go test's
// ten-minute panic rather than failing on an assertion — and a regression that
// hangs is one somebody reruns and shrugs at. Verified both ways: with the
// overflow guard removed, this clock makes
// TestLoginRefusesDeviceSecondsItCannotMeasure fail on the poll count in
// milliseconds.
type steppingClock struct {
	mu  sync.Mutex
	now time.Time
}

func newSteppingClock() *steppingClock {
	return &steppingClock{now: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)}
}

func (c *steppingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *steppingClock) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if d > 0 {
		c.now = c.now.Add(d)
	}
	return nil
}

// testHome points HOME at a scratch directory. Every verb resolves its state
// root from HOME (FR-039), so a test that skipped this would write into the
// developer's own ~/.agent-manager.
func testHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// fileBackendOnly forces the credential store to the file fallback.
//
// Not a shortcut: the alternative is a suite whose result depends on whether a
// Secret Service happens to be running on the machine, and on Linux CI that is
// the difference between exercising the fallback and exercising nothing.
// internal/credentials owns the per-backend round trip (T028); these tests own
// the wiring.
func fileBackendOnly() []keyring.BackendType {
	return []keyring.BackendType{keyring.FileBackend}
}

func openTestStore(t *testing.T, home string) *credentials.Store {
	t.Helper()
	store, err := credentials.Open(credentials.Options{
		StateRoot: filepath.Join(home, DirName),
		Backends:  fileBackendOnly(),
	})
	require.NoError(t, err)
	return store
}

// testOptions builds the Options a verb sees, with the two streams captured.
// It bypasses cobra on purpose: the flag plumbing is exit_test.go's subject,
// and these tests are about what the verb does with the values.
func testOptions(hubURL string, format output.Format) (opts *Options, result, diag *syncBuffer) {
	result, diag = &syncBuffer{}, &syncBuffer{}
	opts = &Options{Hub: hubURL, Output: string(format), result: result, diag: diag}
	opts.streams = output.NewStreams(format, result, diag)
	return opts, result, diag
}

func loginDepsFor(clk device.Clock, client *http.Client) loginDeps {
	return loginDeps{
		clock:      clk,
		httpClient: client,
		hostname:   func() (string, error) { return testHost, nil },
		backends:   fileBackendOnly(),
		lookupEnv:  func(string) (string, bool) { return "", false },
	}
}

func logoutDepsFor() logoutDeps {
	return logoutDeps{
		backends:  fileBackendOnly(),
		lookupEnv: func(string) (string, bool) { return "", false },
	}
}

// startFake starts the fake hub over TLS with the test's clock.
//
// TLS is not optional: amctl refuses a plaintext hub without
// --allow-plaintext-hub (FR-041), so a test of the normal path against a plain
// http fake would be testing the refusal.
func startFake(t *testing.T, clk *gateClock) fake.Target {
	t.Helper()
	h := fake.New(fake.Options{
		Now:           clk.Now,
		PollInterval:  advertisedInterval,
		DeviceCodeTTL: 15 * time.Minute,
		TokenTTL:      time.Hour,
		TLS:           true,
	})
	t.Cleanup(h.Close)
	return h.Target()
}

// displayedUserCode is the code login printed, read back off the diagnostic
// stream. The anchor is login's own layout — the code alone on a line, indented
// — rather than a loose search for the shape, so a timestamp elsewhere in the
// message cannot be mistaken for a code.
var displayedUserCode = regexp.MustCompile(`(?m)^ {4}([0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4})\s*$`)

func codeFrom(t *testing.T, diag *syncBuffer) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := displayedUserCode.FindStringSubmatch(diag.String()); m != nil {
			return m[1]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("login never displayed a user code on the diagnostic stream (FR-001, RFC 8628 3.3)")
	return ""
}

// runLoginAsync starts login and returns a channel carrying its error. login
// blocks on human approval, so every case that needs to act mid-flow needs it
// off the test's own goroutine.
func runLoginAsync(opts *Options, deps loginDeps) <-chan error {
	done := make(chan error, 1)
	go func() { done <- runLogin(context.Background(), opts, deps) }()
	return done
}

func awaitLogin(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("login did not finish")
		return nil
	}
}

// ---------------------------------------------------------------- the flow

// TestLoginStoresACredentialTheStoreCanReadBack is the whole of US1's happy
// path, and it deliberately does not believe login's own report: the credential
// is read back through internal/credentials, which is how every other verb will
// find it. A login that printed a perfect result and stored nothing would pass
// any test that only read the result.
func TestLoginStoresACredentialTheStoreCanReadBack(t *testing.T) {
	home := testHome(t)
	clk := newGateClock()
	target := startFake(t, clk)
	start := clk.Now()

	opts, result, diag := testOptions(target.BaseURL, output.FormatHuman)
	done := runLoginAsync(opts, loginDepsFor(clk, target.HTTPClient))

	code := codeFrom(t, diag)
	clk.waitForFirstPause(t)
	require.NoError(t, target.Control.ApproveDevice(code))
	clk.letItPoll()
	require.NoError(t, awaitLogin(t, done))

	// FR-002, and the reason the interval is one second here: internal/device
	// defaults to the RFC's five when the hub omits `interval`, so a recorded
	// wait of exactly one second can only have come off the wire.
	require.Equal(t, []time.Duration{advertisedInterval}, clk.recorded(),
		"the client must wait exactly the interval the hub advertised, once, between its two polls")

	canonical, err := ParseHub(target.BaseURL)
	require.NoError(t, err)

	stored, found, err := openTestStore(t, home).Load(canonical.URL)
	require.NoError(t, err)
	require.True(t, found, "login reported success and stored no credential")
	require.Equal(t, canonical.URL, stored.Hub)
	require.NotEmpty(t, stored.Token)
	require.Equal(t, testHost, stored.Identity, "FR-001: the credential records the host the grant was bound to")

	// The lifetime is the hub's `expires_in` measured from the clock at
	// receipt, which is one interval after the start. Hand-derived from the
	// fake's TokenTTL rather than read out of the result: the token is opaque
	// and there is nothing in it to check this against, so if this arithmetic is
	// wrong nothing else will ever notice.
	require.Equal(t, start.Add(advertisedInterval).Add(time.Hour), stored.ExpiresAt)
	require.False(t, stored.Expired(stored.ExpiresAt.Add(-time.Second)))
	require.True(t, stored.Expired(stored.ExpiresAt))

	// FR-007 with the real value rather than a sentinel: the fake's tokens are
	// random, so this is the only place the actual issued token can be checked
	// against everything the run printed.
	require.False(t, strings.Contains(result.String(), stored.Token),
		"the access token reached the result stream")
	require.False(t, strings.Contains(diag.String(), stored.Token),
		"the access token reached the diagnostic stream")

	require.True(t, strings.Contains(result.String(), canonical.URL), "the result must name the hub")
	require.True(t, strings.Contains(result.String(), testHost), "the result must name the identity")
	require.False(t, strings.Contains(result.String(), code),
		"FR-007: the user code must not reach a report")

	// FR-003 at the command layer: the fallback is reported on the diagnostic
	// stream, and it names the backend actually chosen.
	require.True(t, strings.Contains(diag.String(), `using "file"`),
		"the fallback to a file was not reported on the diagnostic stream")
}

// TestLoginPutsTheCodeOnStderrAndOneJSONDocumentOnStdout is FR-035.
//
// The user code cannot go to the result stream, because under --output json
// that stream must be a single parseable document and the code is only useful
// before the document exists. This is the assertion that pins the decision: one
// document on stdout, the code on stderr, in the same run.
func TestLoginPutsTheCodeOnStderrAndOneJSONDocumentOnStdout(t *testing.T) {
	testHome(t)
	clk := newGateClock()
	target := startFake(t, clk)

	opts, result, diag := testOptions(target.BaseURL, output.FormatJSON)
	done := runLoginAsync(opts, loginDepsFor(clk, target.HTTPClient))

	code := codeFrom(t, diag)
	clk.waitForFirstPause(t)
	require.NoError(t, target.Control.ApproveDevice(code))
	clk.letItPoll()
	require.NoError(t, awaitLogin(t, done))

	var doc struct {
		Kind   string                 `json:"kind"`
		Result map[string]any         `json:"result"`
		Extra  map[string]json.Number `json:"-"`
	}
	dec := json.NewDecoder(strings.NewReader(result.String()))
	require.NoError(t, dec.Decode(&doc), "the result stream is not one JSON document")
	require.False(t, dec.More(), "exactly one document per run")
	require.Equal(t, "login", doc.Kind)

	for _, forbidden := range []string{"token", "access_token", "code", "user_code", "secret"} {
		require.NotContains(t, doc.Result, forbidden)
	}
	require.Equal(t, testHost, doc.Result["identity"])

	require.True(t, strings.Contains(diag.String(), code),
		"the code must be shown to a human somewhere, and stderr is the only stream left")
	require.False(t, strings.Contains(result.String(), code),
		"a user code inside the JSON document breaks every scripted caller")
}

// TestLoginRunsWithNoTerminalAndNeverPrompts is FR-037's FIRST clause, which is
// the one that applies to login: the device grant exists so that the machine
// needing a credential never has to collect one, so login works under a pipe
// with no flag at all. Under `go test` neither stream is a terminal and both
// are plain buffers here, so a login that consulted one, or read stdin, could
// not complete.
//
// The mechanical half of the same claim is
// TestNoVerbReachesForATerminalOrStandardInput; this half proves the verb
// actually finishes.
func TestLoginRunsWithNoTerminalAndNeverPrompts(t *testing.T) {
	home := testHome(t)
	clk := newGateClock()
	target := startFake(t, clk)

	opts, _, diag := testOptions(target.BaseURL, output.FormatHuman)
	done := runLoginAsync(opts, loginDepsFor(clk, target.HTTPClient))

	code := codeFrom(t, diag)
	clk.waitForFirstPause(t)
	require.NoError(t, target.Control.ApproveDevice(code))
	clk.letItPoll()
	require.NoError(t, awaitLogin(t, done))
	require.Equal(t, CodeNoChanges, ExitCode(opts.Outcome, nil))

	canonical, err := ParseHub(target.BaseURL)
	require.NoError(t, err)
	_, found, err := openTestStore(t, home).Load(canonical.URL)
	require.NoError(t, err)
	require.True(t, found)
}

// TestLoginWithoutAHubRefusesNamingTheFlag is FR-037's SECOND clause. The one
// question login would otherwise ask is which hub; with no TTY there is nobody
// to ask, so it refuses and names --hub. This runs the real command tree,
// because the flag has to be the one the tree registers.
func TestLoginWithoutAHubRefusesNamingTheFlag(t *testing.T) {
	testHome(t)
	var result, diag syncBuffer
	require.Equal(t, CodeRefused, Main([]string{"login"}, &result, &diag))
	require.Contains(t, diag.String(), "--hub",
		"the refusal must name the flag that supplies what it would otherwise have asked for")
	require.Empty(t, result.String(), "a refusal on the result stream would corrupt the json document")
}

// TestLoginRefusesAPlaintextHubUntilTheFlagIsPassed is FR-041.
//
// Both directions, because the refusal is only worth having if the flag
// actually lifts it: without the flag the error is hub.ErrInsecureHub and the
// exit code is CodeRefused, and with it the same URL gets as far as the network
// and fails for a network reason instead.
func TestLoginRefusesAPlaintextHubUntilTheFlagIsPassed(t *testing.T) {
	clk := newGateClock()

	t.Run("refused, naming the flag", func(t *testing.T) {
		testHome(t)
		opts, result, _ := testOptions("http://127.0.0.1:1", output.FormatHuman)
		err := runLogin(context.Background(), opts, loginDepsFor(clk, nil))
		require.ErrorIs(t, err, hub.ErrInsecureHub)
		require.Contains(t, err.Error(), hub.PlaintextFlagName)
		require.True(t, IsRefusal(err), "a plaintext hub URL is the user's to fix")
		require.Equal(t, CodeRefused, ExitCode(opts.Outcome, err))
		require.Empty(t, result.String())
	})

	t.Run("the flag lifts the refusal and warns", func(t *testing.T) {
		testHome(t)
		opts, _, diag := testOptions("http://127.0.0.1:1", output.FormatHuman)
		opts.AllowPlaintextHub = true
		err := runLogin(context.Background(), opts, loginDepsFor(clk, nil))
		require.Error(t, err)
		require.NotErrorIs(t, err, hub.ErrInsecureHub, "the flag must lift exactly this refusal")
		require.ErrorIs(t, err, hub.ErrUnreachable, "and nothing else: the URL is a dead port")
		require.Contains(t, diag.String(), "plaintext",
			"FR-041: a plaintext run warns on the diagnostic stream every time")
	})
}

// ---------------------------------------------------------------- refusals

// TestLoginReportsADenialAndExitsNonZero is US1 scenario 3's sibling: the human
// said no. It must be reported as a denial, exit non-zero, and leave nothing
// stored — a login that wrote a credential it never received is the worst
// possible outcome here.
func TestLoginReportsADenialAndExitsNonZero(t *testing.T) {
	home := testHome(t)
	clk := newGateClock()
	target := startFake(t, clk)

	opts, result, diag := testOptions(target.BaseURL, output.FormatHuman)
	done := runLoginAsync(opts, loginDepsFor(clk, target.HTTPClient))

	code := codeFrom(t, diag)
	clk.waitForFirstPause(t)
	require.NoError(t, target.Control.DenyDevice(code))
	clk.letItPoll()

	err := awaitLogin(t, done)
	require.ErrorIs(t, err, device.ErrDenied)
	require.NotErrorIs(t, err, device.ErrExpired, "a denial is not an expiry")
	require.Equal(t, CodeRefused, ExitCode(opts.Outcome, err))
	require.Empty(t, result.String(), "no result may be emitted for a login that did not happen")

	canonical, err2 := ParseHub(target.BaseURL)
	require.NoError(t, err2)
	_, found, err2 := openTestStore(t, home).Load(canonical.URL)
	require.NoError(t, err2)
	require.False(t, found, "a denied login stored a credential")
}

// TestLoginReportsAnExpiredCodeAndStopsPolling is US1 scenario 3.
//
// The "does not loop" half is the assertion that matters and it is the one
// easiest to fake: it is proven by the number of PAUSES, because continuing to
// poll requires waiting out an interval first. Exactly one pause means exactly
// two polls — the pending one and the expired one — and no third.
func TestLoginReportsAnExpiredCodeAndStopsPolling(t *testing.T) {
	home := testHome(t)
	clk := newGateClock()
	target := startFake(t, clk)

	opts, result, diag := testOptions(target.BaseURL, output.FormatHuman)
	done := runLoginAsync(opts, loginDepsFor(clk, target.HTTPClient))

	code := codeFrom(t, diag)
	clk.waitForFirstPause(t)
	require.NoError(t, target.Control.ExpireDevice(code))
	clk.letItPoll()

	err := awaitLogin(t, done)
	require.ErrorIs(t, err, device.ErrExpired)
	require.NotErrorIs(t, err, device.ErrDenied, "an expiry is not a denial")
	require.Equal(t, CodeRefused, ExitCode(opts.Outcome, err))
	require.Contains(t, err.Error(), "amctl login", "the refusal must say what to do about it")
	require.Len(t, clk.recorded(), 1, "login kept polling after the hub said the code had expired")
	require.Empty(t, result.String())

	canonical, err2 := ParseHub(target.BaseURL)
	require.NoError(t, err2)
	_, found, err2 := openTestStore(t, home).Load(canonical.URL)
	require.NoError(t, err2)
	require.False(t, found, "an expired login stored a credential")
}

// TestLoginDistinguishesUnreachableFromEveryOtherFailure is FR-040.
//
// The four HTTP classes are driven by a server that answers the device
// authorisation with one fixed status, which is the only way to reach 401 and
// 403 on this path at all: /v1/device/authorize is unauthenticated, so a real
// hub has nothing to reject. That is the point of the test — "something went
// wrong" is not an acceptable diagnosis even for a status this endpoint should
// never return.
//
// The fifth row is the one login can actually meet in the field, and it is
// deliberately in the same table: a hub that is reachable, is a hub, and refuses
// the authorisation must not be confused with a hub that is not there.
func TestLoginDistinguishesUnreachableFromEveryOtherFailure(t *testing.T) {
	statuses := []struct {
		name  string
		code  int
		want  error
		class hub.Class
	}{
		{"unauthorised", http.StatusUnauthorized, hub.ErrUnauthorised, hub.ClassUnauthorised},
		{"forbidden", http.StatusForbidden, hub.ErrForbidden, hub.ClassForbidden},
		{"not found", http.StatusNotFound, hub.ErrNotFound, hub.ClassNotFound},
		{"server error", http.StatusInternalServerError, hub.ErrServer, hub.ClassServer},
	}
	for _, tc := range statuses {
		t.Run("a hub answering "+tc.name+" is reported as "+tc.name, func(t *testing.T) {
			testHome(t)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(`{"title":"no","status":0}`))
			}))
			defer srv.Close()

			opts, _, _ := testOptions(srv.URL, output.FormatHuman)
			err := runLogin(context.Background(), opts, loginDepsFor(newGateClock(), srv.Client()))
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, tc.class, hub.ClassOf(err), "FR-040: the class must survive the device flow")
			require.NotErrorIs(t, err, hub.ErrUnreachable,
				"a hub that answered is not an unreachable hub")
		})
	}

	t.Run("a hub that is not there is reported as unreachable", func(t *testing.T) {
		testHome(t)
		// Port 1 is reserved and nothing listens on it; a dial there fails
		// without waiting for a timeout.
		opts, _, _ := testOptions("https://127.0.0.1:1", output.FormatHuman)
		err := runLogin(context.Background(), opts, loginDepsFor(newGateClock(), nil))
		require.ErrorIs(t, err, hub.ErrUnreachable)
		require.Equal(t, hub.ClassUnreachable, hub.ClassOf(err))
		require.NotErrorIs(t, err, hub.ErrUnauthorised)
		require.NotErrorIs(t, err, device.ErrDenied,
			"an unreachable hub must not be reported as a refusal")
	})

	t.Run("a hub that refuses the authorisation is reported as a refusal", func(t *testing.T) {
		testHome(t)
		clk := newGateClock()
		target := startFake(t, clk)
		opts, _, diag := testOptions(target.BaseURL, output.FormatHuman)
		done := runLoginAsync(opts, loginDepsFor(clk, target.HTTPClient))

		code := codeFrom(t, diag)
		clk.waitForFirstPause(t)
		require.NoError(t, target.Control.DenyDevice(code))
		clk.letItPoll()

		err := awaitLogin(t, done)
		require.ErrorIs(t, err, device.ErrDenied)
		require.Zero(t, hub.ClassOf(err), "a denial is the protocol answering, not a transport class")
		require.NotErrorIs(t, err, hub.ErrUnreachable)
	})
}

// TestLoginRefusesAHomeItCannotUse is FR-039: the home check happens before any
// network request. The hub here is a dead port, so if the ordering were the
// other way round the error would be about the network instead.
func TestLoginRefusesAHomeItCannotUse(t *testing.T) {
	t.Setenv("HOME", "")
	opts, _, _ := testOptions("https://127.0.0.1:1", output.FormatHuman)
	err := runLogin(context.Background(), opts, loginDepsFor(newGateClock(), nil))
	require.ErrorIs(t, err, ErrHomeUnset)
	require.NotErrorIs(t, err, hub.ErrUnreachable,
		"FR-039: the home directory is validated before anything is dialled")
	require.Equal(t, CodeRefused, ExitCode(opts.Outcome, err))
}

// TestLoginWarnsThatAnEnvironmentTokenOutranksWhatItStores is FR-005 seen from
// login: the credential is still stored, and the user is told it will be
// ignored. Silence here would let someone believe a login took effect.
func TestLoginWarnsThatAnEnvironmentTokenOutranksWhatItStores(t *testing.T) {
	testHome(t)
	clk := newGateClock()
	target := startFake(t, clk)

	opts, _, diag := testOptions(target.BaseURL, output.FormatHuman)
	deps := loginDepsFor(clk, target.HTTPClient)
	deps.lookupEnv = func(name string) (string, bool) {
		if name == credentials.TokenEnvVar {
			return "an-environment-token", true
		}
		return "", false
	}
	done := runLoginAsync(opts, deps)

	code := codeFrom(t, diag)
	clk.waitForFirstPause(t)
	require.NoError(t, target.Control.ApproveDevice(code))
	clk.letItPoll()
	require.NoError(t, awaitLogin(t, done))

	// require.True and not require.Contains: this diagnostic stream carries the
	// user code, and a failing Contains would print it. See the file comment.
	require.True(t, strings.Contains(diag.String(), credentials.TokenEnvVar),
		"login must say that the environment token will be used in preference to what it stored")
	require.False(t, strings.Contains(diag.String(), "an-environment-token"),
		"FR-007: naming the variable is the point; printing its value is not")
}

// TestLoginRefusesWithoutAHostnameToBindTo is FR-001's negative control. The
// hostname is what the approving human sees, so a login that could not read one
// must refuse rather than send an anonymous request.
func TestLoginRefusesWithoutAHostnameToBindTo(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func() (string, error)
	}{
		{"the OS cannot say", func() (string, error) { return "", fs.ErrPermission }},
		{"the machine has no name", func() (string, error) { return "   ", nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testHome(t)
			opts, _, _ := testOptions("https://127.0.0.1:1", output.FormatHuman)
			deps := loginDepsFor(newGateClock(), nil)
			deps.hostname = tc.fn
			err := runLogin(context.Background(), opts, deps)
			require.Error(t, err)
			require.Contains(t, err.Error(), "hostname")
			require.Equal(t, CodeRefused, ExitCode(opts.Outcome, err))
		})
	}
}

// ---------------------------------------------- refusals that must come FIRST

// plantCredentialFile stores a credential for hubURL through the real store and
// then widens the mode of whatever file that produced.
//
// The path is DISCOVERED by listing the directory rather than recomputed here:
// the item key is derived by unexported code in internal/credentials, and a
// wrong guess would chmod nothing and leave this test green for the wrong
// reason.
func plantCredentialFile(t *testing.T, home, hubURL string, mode fs.FileMode) string {
	t.Helper()
	require.NoError(t, openTestStore(t, home).Save(
		credentials.Issued(hubURL, "an-older-token", 3600, time.Now())))
	dir := filepath.Join(home, DirName, credentials.DirName)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "expected exactly one credential file to widen")
	path := filepath.Join(dir, entries[0].Name())
	require.NoError(t, os.Chmod(path, mode))
	return path
}

// TestLoginRefusesAWideCredentialStoreBeforeSendingAnyoneToABrowser is FR-004
// ordered against FR-001, and the ordering is the whole requirement.
//
// Measured before the fix: with a 0644 credential file already present for the
// hub — a restore from backup, an rsync without -p, a container COPY, since
// keyring itself always creates 0600 — login opened the store without objection
// (credentials.Open touches no item), printed the user code, waited, the human
// approved, the device grant was consumed, and only then did Save refuse. The
// approval was spent on a token that was never stored and the stale wide file
// still held the old one.
//
// The hub here is a DEAD PORT, which is the assertion doing the work: if the
// mode check still ran after the device flow, this would fail as unreachable
// instead. Nothing is displayed and no packet leaves.
func TestLoginRefusesAWideCredentialStoreBeforeSendingAnyoneToABrowser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not the access control on Windows")
	}
	// Port 1 is reserved and nothing listens on it.
	const deadHub = "https://127.0.0.1:1"

	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, home, hubURL string) string
		want  string
	}{
		{
			name: "a world-readable credential file",
			plant: func(t *testing.T, home, hubURL string) string {
				return plantCredentialFile(t, home, hubURL, 0o644)
			},
			want: "is mode 0644",
		},
		{
			name: "a credential directory anybody may write",
			plant: func(t *testing.T, home, _ string) string {
				dir := filepath.Join(home, DirName, credentials.DirName)
				require.NoError(t, os.MkdirAll(dir, 0o700))
				require.NoError(t, os.Chmod(dir, 0o777))
				return dir
			},
			want: "lets another user replace the credential in it",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := testHome(t)
			canonical, err := ParseHub(deadHub)
			require.NoError(t, err)
			path := tc.plant(t, home, canonical.URL)

			opts, result, diag := testOptions(deadHub, output.FormatHuman)
			err = runLogin(context.Background(), opts, loginDepsFor(newGateClock(), nil))

			require.ErrorIs(t, err, credentials.ErrFileMode)
			require.Equal(t, CodeRefused, ExitCode(opts.Outcome, err))
			require.ErrorContains(t, err, tc.want)
			require.ErrorContains(t, err, path)
			require.NotErrorIs(t, err, hub.ErrUnreachable,
				"FR-004 must be decided before the hub is dialled, or a human approves a login that cannot be stored")

			// Nothing was displayed and nothing was reported. require.False and
			// not require.Contains: see the file comment on not handing testify
			// a haystack that may carry a code.
			require.False(t, displayedUserCode.MatchString(diag.String()),
				"login displayed a user code for an authorisation it was never going to be able to store")
			require.Empty(t, result.String(), "a refused login emits no result")
		})
	}

	t.Run("the refusal leaves the file it refused alone", func(t *testing.T) {
		home := testHome(t)
		canonical, err := ParseHub(deadHub)
		require.NoError(t, err)
		path := plantCredentialFile(t, home, canonical.URL, 0o644)
		before, err := os.ReadFile(path) //nolint:gosec // the test wrote this path
		require.NoError(t, err)

		opts, _, _ := testOptions(deadHub, output.FormatHuman)
		require.Error(t, runLogin(context.Background(), opts, loginDepsFor(newGateClock(), nil)))

		after, err := os.ReadFile(path) //nolint:gosec // the test wrote this path
		require.NoError(t, err)
		require.Equal(t, before, after,
			"the refusal must not rewrite or truncate the credential it will not use; `chmod 600` has to still recover it")
		info, err := os.Lstat(path)
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o644), info.Mode().Perm(),
			"amctl refuses a wide file, it does not silently narrow one")
	})
}

// hostileHub answers /v1/device/authorize with numbers of the test's choosing
// and every poll with authorization_pending, counting the polls.
//
// It is a raw handler and not the fake hub deliberately: fake.Options takes
// durations and rounds them into sanity, so it CANNOT express the wire values
// this test is about. The whole defect lived in the int64-seconds-to-Duration
// conversion, which only a raw body can drive.
// hostilePollCap bounds a hostile hub's patience. See the token handler.
const hostilePollCap = 5

func hostileHub(t *testing.T, body string, polls *atomic.Int64) fake.Target {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/device/authorize", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	})
	mux.HandleFunc("/v1/device/token", func(w http.ResponseWriter, _ *http.Request) {
		n := polls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		// authorization_pending would be the honest answer forever, and forever
		// is the problem: with the overflow guard removed, an `expires_in` of
		// -9223372037 wraps to a POSITIVE 292 years, so the flow polls until the
		// heat death of the test binary and the regression shows up as a
		// ten-minute panic instead of a failed assertion. The cap ends the flow
		// so the poll count below is what fails. It is deliberately larger than
		// the zero polls this test demands, so a passing run never reaches it.
		if n > hostilePollCap {
			_, _ = io.WriteString(w, `{"error":"access_denied"}`)
			return
		}
		_, _ = io.WriteString(w, `{"error":"authorization_pending"}`)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return fake.Target{BaseURL: srv.URL, HTTPClient: srv.Client()}
}

// TestLoginRefusesDeviceSecondsItCannotMeasure is FR-002 against the arithmetic,
// and the poll COUNT is the assertion that matters.
//
// `expires_in` and `interval` are unbounded int64 seconds on the wire, and
// time.Duration is int64 NANOSECONDS: `seconds * time.Second` wraps above about
// 9.22e9 seconds. Measured before the fix, with interval 18446744074 and
// expires_in 5, the adapter produced 290.448ms, internal/device had nothing to
// object to — normaliseInterval catches zero and negative, which is all a wrap
// CAN present as — and login made EIGHTEEN HTTP polls inside the five-second
// window against a hub that had asked for one poll every 584 years. Scaled to a
// normal 900-second window that is roughly 3,100 polls instead of 180.
//
// So every row here asserts zero polls of the token endpoint. An assertion that
// only checked for an error would have passed with the defect present, because
// the flow did eventually fail — it just hammered the hub first.
func TestLoginRefusesDeviceSecondsItCannotMeasure(t *testing.T) {
	const codes = `"device_code":"dc","user_code":"WXYZ-2345","verification_uri":"https://hub.example.com/device"`
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "an interval that wraps to a small positive duration",
			body: `{` + codes + `,"expires_in":5,"interval":18446744074}`,
			want: "interval is 18446744074 seconds",
		},
		{
			name: "an expires_in that wraps",
			body: `{` + codes + `,"expires_in":18446744074,"interval":5}`,
			want: "expires_in is 18446744074 seconds",
		},
		{
			// The wrap is symmetric: -9223372037 seconds becomes a POSITIVE 292
			// years, so bounding only the upper end would leave this one live.
			name: "a negative expires_in that wraps positive",
			body: `{` + codes + `,"expires_in":-9223372037,"interval":5}`,
			want: "expires_in is -9223372037 seconds",
		},
		{
			// Representable, so the adapter passes it on; internal/device is
			// what refuses a flow that cannot complete. In the same table
			// because from login's side it is the same class of hub and must not
			// print a code either.
			name: "an interval longer than the code lives, which needs no overflow at all",
			body: `{` + codes + `,"expires_in":900,"interval":86400}`,
			want: "no window in which it could be approved",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testHome(t)
			var polls atomic.Int64
			target := hostileHub(t, tc.body, &polls)

			opts, result, diag := testOptions(target.BaseURL, output.FormatHuman)
			err := runLogin(context.Background(), opts, loginDepsFor(newSteppingClock(), target.HTTPClient))

			require.ErrorIs(t, err, device.ErrProtocol)
			require.ErrorContains(t, err, tc.want)
			require.Zero(t, polls.Load(),
				"FR-002: the token endpoint was polled %d times for an authorisation that could never be polled legally", polls.Load())
			require.False(t, displayedUserCode.MatchString(diag.String()),
				"a code was shown for an authorisation the client had already decided it could not honour")
			require.Empty(t, result.String())
		})
	}
}

// TestAnInterruptedLoginIsNotBlamedOnTheHub is about a diagnosis, not a failure:
// both cases below already ended the flow correctly.
//
// A context cancelled while a poll is in FLIGHT comes back through
// internal/hub's classifyTransport, which classifies a cancelled request as
// ClassUnreachable — correct for that package, since nothing answered. Measured
// before the fix, wrapping that chain produced "login was interrupted before it
// was approved: … hub unreachable at https://…: context canceled", and any
// FR-040 consumer switching on hub.ClassOf got "unreachable" for a hub that was
// answering perfectly.
//
// Latency worth knowing: nothing in amctl installs a signal handler, so
// cmd.Context() is context.Background() and Ctrl-C kills the process outright.
// This path is reached today only by a caller passing its own cancellable
// context. It is asserted anyway, because it goes live the moment someone wires
// signal.NotifyContext and a wrong class is cheaper to fix now.
func TestAnInterruptedLoginIsNotBlamedOnTheHub(t *testing.T) {
	assertInterrupted := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, device.ErrDenied, "an interruption is not a refusal")
		require.NotErrorIs(t, err, device.ErrExpired)
		require.NotErrorIs(t, err, hub.ErrUnreachable,
			"the hub was answering; only the caller stopped")
		require.Zero(t, hub.ClassOf(err),
			"an interrupted login must carry no FR-040 class, or a script switching on ClassOf blames the network")
		require.NotContains(t, err.Error(), "unreachable")
		require.ErrorContains(t, err, "interrupted")
	}

	t.Run("cancelled while a poll is in flight", func(t *testing.T) {
		testHome(t)
		ctx, cancel := context.WithCancel(context.Background())
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/device/authorize", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"device_code":"dc","user_code":"WXYZ-2345",`+
				`"verification_uri":"https://hub.example.com/device","expires_in":900,"interval":1}`)
		})
		mux.HandleFunc("/v1/device/token", func(w http.ResponseWriter, _ *http.Request) {
			// Cancel with the request on the wire, then answer slowly enough
			// that the cancellation is what the client sees.
			cancel()
			time.Sleep(200 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"authorization_pending"}`)
		})
		srv := httptest.NewTLSServer(mux)
		defer srv.Close()

		opts, _, _ := testOptions(srv.URL, output.FormatHuman)
		err := runLogin(ctx, opts, loginDepsFor(newGateClock(), srv.Client()))
		assertInterrupted(t, err)
		require.Equal(t, CodeFailure, ExitCode(opts.Outcome, err),
			"an interruption is the caller's doing, not something the user must fix")
	})

	t.Run("cancelled while parked between polls", func(t *testing.T) {
		testHome(t)
		ctx, cancel := context.WithCancel(context.Background())
		clk := newGateClock()
		target := startFake(t, clk)

		opts, _, diag := testOptions(target.BaseURL, output.FormatHuman)
		done := make(chan error, 1)
		go func() { done <- runLogin(ctx, opts, loginDepsFor(clk, target.HTTPClient)) }()

		codeFrom(t, diag)
		clk.waitForFirstPause(t)
		cancel()
		assertInterrupted(t, awaitLogin(t, done))
	})
}

// ---------------------------------------------------------------- logout

// TestLogoutRemovesTheCredentialAndTouchesNothingElse is FR-008.
//
// The tree is snapshotted by content, so "touches nothing installed" is a
// byte-level claim and not a claim about which functions logout calls. The
// seeded record is written as raw bytes rather than through internal/record on
// purpose: what is being proven is that logout does not rewrite it, and raw
// bytes prove that more directly than a re-serialisation would.
func TestLogoutRemovesTheCredentialAndTouchesNothingElse(t *testing.T) {
	home := testHome(t)
	hubURL := "https://hub.example.com"
	canonical, err := ParseHub(hubURL)
	require.NoError(t, err)

	store := openTestStore(t, home)
	require.NoError(t, store.Save(credentials.Issued(canonical.URL, "a-stored-token", 3600, time.Now())))

	// An installed tree: amctl's own per-hub record, and packages in the two
	// places a target writes. SC-004's unmanaged neighbour is here too, because
	// the failure this guards against does not distinguish them.
	seeded := map[string]string{
		filepath.Join(DirName, canonical.Dir, "state.json"):                `{"schemaVersion":"1.0.0","hub":"` + canonical.URL + `","profiles":[]}`,
		filepath.Join(DirName, "cache", "sha256-abc", "bundle.zst"):        "not really a bundle",
		filepath.Join(".claude", "skills", "acme-code-review", "SKILL.md"): "# managed by amctl",
		filepath.Join(".claude", "skills", "hand-written", "SKILL.md"):     "# not amctl's",
		filepath.Join(".codex", "prompts", "acme-lint.md"):                 "# managed by amctl",
	}
	for rel, content := range seeded {
		path := filepath.Join(home, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}

	before := snapshot(t, home)

	opts, result, _ := testOptions(hubURL, output.FormatHuman)
	require.NoError(t, runLogout(opts, logoutDepsFor()))
	require.Equal(t, CodeNoChanges, ExitCode(opts.Outcome, nil))
	require.Contains(t, result.String(), "removed")
	require.Contains(t, result.String(), canonical.URL)

	require.Equal(t, before, snapshot(t, home),
		"FR-008: logout altered something installed")

	_, found, err := openTestStore(t, home).Load(canonical.URL)
	require.NoError(t, err)
	require.False(t, found, "logout left the credential behind")

	// The negative control, kept in the suite rather than run once by hand: a
	// comparison that cannot fail is a comparison nobody has checked, and the
	// way this one would silently stop working is by excluding too much.
	t.Run("the comparison notices a change to any of the three trees", func(t *testing.T) {
		for _, rel := range []string{
			filepath.Join(DirName, canonical.Dir, "state.json"),
			filepath.Join(".claude", "skills", "hand-written", "SKILL.md"),
			filepath.Join(".codex", "prompts", "acme-lint.md"),
		} {
			path := filepath.Join(home, rel)
			original, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			// Re-baselined per file: restoring the previous one moved its
			// mtime, so comparing every round against the original snapshot
			// would start passing for the wrong reason from the second
			// iteration on.
			base := snapshot(t, home)
			require.NoError(t, os.WriteFile(path, append(original, '!'), 0o600))
			require.NotEqual(t, base, snapshot(t, home), "a changed %s went unnoticed", rel)
			require.NoError(t, os.WriteFile(path, original, 0o600))
		}
	})
}

// TestLogoutOfOneHubLeavesAnotherHubsCredentialAlone is FR-006. Two hubs, one
// logout. No server is needed: logout makes no request, which is itself part of
// the requirement — see newLogoutCmd on why it constructs no hub client.
func TestLogoutOfOneHubLeavesAnotherHubsCredentialAlone(t *testing.T) {
	home := testHome(t)
	first, err := ParseHub("https://first.example.com")
	require.NoError(t, err)
	second, err := ParseHub("https://second.example.com")
	require.NoError(t, err)

	store := openTestStore(t, home)
	require.NoError(t, store.Save(credentials.Issued(first.URL, "first-token", 3600, time.Now())))
	require.NoError(t, store.Save(credentials.Issued(second.URL, "second-token", 3600, time.Now())))

	opts, _, _ := testOptions(first.URL, output.FormatHuman)
	require.NoError(t, runLogout(opts, logoutDepsFor()))

	reopened := openTestStore(t, home)
	_, found, err := reopened.Load(first.URL)
	require.NoError(t, err)
	require.False(t, found)

	kept, found, err := reopened.Load(second.URL)
	require.NoError(t, err)
	require.True(t, found, "logging out of one hub removed another hub's credential")
	require.Equal(t, "second-token", kept.Token)
}

// TestLogoutFindsWhatLoginStoredHoweverTheHubWasSpelled is the invariant that
// makes the pair work at all: both verbs key the credential on the CANONICAL
// hub URL, so the spelling the operator happened to type is irrelevant. A
// second opinion on canonicalisation in either verb would produce a logout that
// removes nothing and reports success.
func TestLogoutFindsWhatLoginStoredHoweverTheHubWasSpelled(t *testing.T) {
	for _, spelling := range []string{
		"hub.example.com",
		"HUB.Example.com.",
		"https://hub.example.com/",
		"https://hub.example.com:443",
	} {
		t.Run(spelling, func(t *testing.T) {
			home := testHome(t)
			canonical, err := ParseHub("https://hub.example.com")
			require.NoError(t, err)
			require.NoError(t, openTestStore(t, home).Save(
				credentials.Issued(canonical.URL, "a-stored-token", 3600, time.Now())))

			opts, result, _ := testOptions(spelling, output.FormatHuman)
			require.NoError(t, runLogout(opts, logoutDepsFor()))
			require.Contains(t, result.String(), "removed")

			_, found, err := openTestStore(t, home).Load(canonical.URL)
			require.NoError(t, err)
			require.False(t, found)
		})
	}
}

// TestLogoutWhenNothingIsStoredSucceedsAndSaysSo: logout twice, and logout on a
// machine that never logged in, are both reasonable things for a provisioning
// script to do. Exit 0, and a message rather than silence.
func TestLogoutWhenNothingIsStoredSucceedsAndSaysSo(t *testing.T) {
	testHome(t)
	opts, result, _ := testOptions("https://hub.example.com", output.FormatJSON)
	require.NoError(t, runLogout(opts, logoutDepsFor()))
	require.Equal(t, CodeNoChanges, ExitCode(opts.Outcome, nil))

	var doc struct {
		Kind   string `json:"kind"`
		Result struct {
			Hub     string `json:"hub"`
			Removed bool   `json:"removed"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &doc))
	require.Equal(t, "logout", doc.Kind)
	require.Equal(t, "https://hub.example.com", doc.Result.Hub)
	require.False(t, doc.Result.Removed,
		"a script must be able to tell 'removed one' from 'there was none' without parsing prose")
}

// TestLogoutWarnsThatAnEnvironmentTokenStillAuthenticates: FR-005 means
// removing the stored credential does not log this shell out.
func TestLogoutWarnsThatAnEnvironmentTokenStillAuthenticates(t *testing.T) {
	testHome(t)
	opts, _, diag := testOptions("https://hub.example.com", output.FormatHuman)
	deps := logoutDepsFor()
	deps.lookupEnv = func(name string) (string, bool) {
		return "an-environment-token", name == credentials.TokenEnvVar
	}
	require.NoError(t, runLogout(opts, deps))
	require.Contains(t, diag.String(), credentials.TokenEnvVar)
	require.False(t, strings.Contains(diag.String(), "an-environment-token"))
}

// TestLogoutRefusesAHomeItCannotUse: the same FR-039 ordering as login, for the
// verb that has no network call to be ordered against — the home is still the
// first thing that has to be true.
func TestLogoutRefusesAHomeItCannotUse(t *testing.T) {
	t.Setenv("HOME", "")
	opts, _, _ := testOptions("https://hub.example.com", output.FormatHuman)
	err := runLogout(opts, logoutDepsFor())
	require.ErrorIs(t, err, ErrHomeUnset)
	require.Equal(t, CodeRefused, ExitCode(opts.Outcome, err))
}

// TestLogoutWithoutAHubRefusesNamingTheFlag: FR-037 again. logout has exactly
// one question and it is the same one.
func TestLogoutWithoutAHubRefusesNamingTheFlag(t *testing.T) {
	testHome(t)
	var result, diag syncBuffer
	require.Equal(t, CodeRefused, Main([]string{"logout"}, &result, &diag))
	require.Contains(t, diag.String(), "--hub")
	require.Empty(t, result.String())
}

// TestLogoutOfAPlaintextHubWorksWithoutTheFlag is the decision in
// newLogoutCmd's comment, asserted rather than argued: logout builds no hub
// client, so deleting a credential stored for an http:// hub does not require
// re-typing the flag that permitted storing it. The alternative leaves the token
// on disk, which is the opposite of what the user asked for.
func TestLogoutOfAPlaintextHubWorksWithoutTheFlag(t *testing.T) {
	home := testHome(t)
	canonical, err := ParseHub("http://hub.example.com")
	require.NoError(t, err)
	require.Equal(t, "http://hub.example.com", canonical.URL)
	require.NoError(t, openTestStore(t, home).Save(
		credentials.Issued(canonical.URL, "a-stored-token", 3600, time.Now())))

	opts, result, _ := testOptions("http://hub.example.com", output.FormatHuman)
	require.False(t, opts.AllowPlaintextHub)
	require.NoError(t, runLogout(opts, logoutDepsFor()))
	require.Contains(t, result.String(), "removed")

	_, found, err := openTestStore(t, home).Load(canonical.URL)
	require.NoError(t, err)
	require.False(t, found)
}

// ---------------------------------------------------------------- FR-037 gate

// TestNoVerbReachesForATerminalOrStandardInput is FR-037 as a property of the
// source rather than of one code path.
//
// A behavioural test can only prove that the paths it exercises do not prompt.
// This proves that no path CAN: nothing in internal/cmd names os.Stdin or a
// terminal check, so there is nothing to prompt with. It is the same shape of
// gate internal/device uses to keep the clock behind its interface, and it
// carries the same negative control — a synthetic file that does prompt, which
// the detector must catch.
//
// If a verb ever genuinely needs an interactive path, this test is where the
// conversation starts: FR-037 wants a flag beside it, and T057 is the audit.
func TestNoVerbReachesForATerminalOrStandardInput(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(name)
		require.NoError(t, readErr)
		checked++
		for _, found := range interactiveUses(t, name, string(src)) {
			t.Errorf("%s: %s — every command must run with no TTY (FR-037); a prompt needs a flag beside it", name, found)
		}
	}
	require.GreaterOrEqual(t, checked, 5, "the scan did not read the package it is guarding")

	t.Run("the detector catches a prompt", func(t *testing.T) {
		bad := "package cmd\nimport (\"bufio\"\n\"os\")\nfunc ask() string {\n" +
			"s := bufio.NewScanner(os.Stdin)\ns.Scan()\nreturn s.Text()\n}\n"
		require.NotEmpty(t, interactiveUses(t, "synthetic.go", bad),
			"the detector would not notice a verb reading stdin")
	})

	t.Run("the detector does not invent one", func(t *testing.T) {
		fine := "package cmd\nimport \"os\"\nfunc h() (string, error) { return os.Hostname() }\n"
		require.Empty(t, interactiveUses(t, "synthetic.go", fine))
	})
}

// interactiveUses reports every reference to standard input or to a terminal
// check in one Go source file. It works over the AST rather than over the text
// so that the words appearing in a comment — as they do all over login.go —
// cannot fire it.
func interactiveUses(t *testing.T, name, src string) []string {
	t.Helper()
	forbidden := map[string]map[string]bool{
		"os":       {"Stdin": true},
		"term":     {"IsTerminal": true, "ReadPassword": true},
		"terminal": {"IsTerminal": true, "ReadPassword": true},
		"isatty":   {"IsTerminal": true, "IsCygwinTerminal": true},
	}

	file, err := parser.ParseFile(token.NewFileSet(), name, src, parser.SkipObjectResolution)
	require.NoError(t, err)

	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if names := forbidden[pkg.Name]; names[sel.Sel.Name] {
			found = append(found, "reads "+pkg.Name+"."+sel.Sel.Name)
		}
		return true
	})
	return found
}

// ---------------------------------------------------------------- snapshot

// fileState is one path's identity for the FR-008 comparison.
type fileState struct {
	Mode    fs.FileMode
	Size    int64
	Digest  string
	ModTime time.Time
}

// snapshot fingerprints every file under root by content, mode and mtime.
//
// Two deliberate exclusions, and each is a thing logout is ALLOWED to change:
// the credential directory itself, and directory modification times, which
// change whenever a file inside one is created or removed. Everything else —
// including every file's mtime — is compared, so a logout that rewrote the
// installation record byte-for-identically would still be caught.
func snapshot(t *testing.T, root string) map[string]fileState {
	t.Helper()
	skip := filepath.Join(root, DirName, credentials.DirName)

	out := map[string]fileState{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == skip {
			return fs.SkipDir
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		if d.IsDir() {
			out[rel+string(filepath.Separator)] = fileState{Mode: info.Mode()}
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(body)
		out[rel] = fileState{
			Mode:    info.Mode(),
			Size:    info.Size(),
			Digest:  hex.EncodeToString(sum[:]),
			ModTime: info.ModTime(),
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, out, fmt.Sprintf("nothing was seeded under %s, so the comparison would pass vacuously", root))
	return out
}
