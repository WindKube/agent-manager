// login's and logout's tests share this file and its helpers.
//
// The diagnostic stream carries the user code inside a `?user_code=` URL, which
// internal/leakscan hunts for in the suite's output, so assertions over these
// buffers use require.True/False with a hand-written message and never hand
// testify the haystack.
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

const testHost = "login-test-host"

// advertisedInterval is one second, not the RFC's default five, so a recorded
// wait of this length proves the value came off the wire.
const advertisedInterval = time.Second

// syncBuffer is an io.Writer safe to read while login writes to it from another goroutine.
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

// gateClock is device.Clock with the sleeping taken out: Wait records the
// duration, advances the clock by it, and blocks until the test releases it, so
// a test knows which poll will see an approval, denial or expiry. It is also the
// fake hub's clock, or a client waiting exactly as told would earn slow_down.
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

// steppingClock advances by what Wait is asked for and returns at once. A
// misbehaving flow under gateClock would hang the suite instead of failing an assertion.
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

// testHome points HOME at a scratch directory so no test writes the developer's ~/.agent-manager.
func testHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// fileBackendOnly forces the file fallback, so results don't depend on
// whether a Secret Service is running.
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

// testOptions bypasses cobra: flag plumbing is exit_test.go's subject.
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

// startFake uses TLS, or a test of the normal path would hit the plaintext refusal.
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

// displayedUserCode anchors on login's own layout, so a timestamp can't be mistaken for a code.
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
	t.Fatal("login never displayed a user code on the diagnostic stream (RFC 8628 3.3)")
	return ""
}

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

// The credential is read back through internal/credentials rather than
// trusting login's report.
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

	// internal/device defaults to five seconds, so a one-second wait came off the wire.
	require.Equal(t, []time.Duration{advertisedInterval}, clk.recorded(),
		"the client must wait exactly the interval the hub advertised, once, between its two polls")

	canonical, err := ParseHub(target.BaseURL)
	require.NoError(t, err)

	stored, found, err := openTestStore(t, home).Load(canonical.URL)
	require.NoError(t, err)
	require.True(t, found, "login reported success and stored no credential")
	require.Equal(t, canonical.URL, stored.Hub)
	require.NotEmpty(t, stored.Token)
	require.Equal(t, testHost, stored.Identity, "the credential records the host the grant was bound to")

	// Hand-derived from the fake's TokenTTL: the token is opaque, so nothing else would catch a wrong lifetime.
	require.Equal(t, start.Add(advertisedInterval).Add(time.Hour), stored.ExpiresAt)
	require.False(t, stored.Expired(stored.ExpiresAt.Add(-time.Second)))
	require.True(t, stored.Expired(stored.ExpiresAt))

	require.False(t, strings.Contains(result.String(), stored.Token),
		"the access token reached the result stream")
	require.False(t, strings.Contains(diag.String(), stored.Token),
		"the access token reached the diagnostic stream")

	require.True(t, strings.Contains(result.String(), canonical.URL), "the result must name the hub")
	require.True(t, strings.Contains(result.String(), testHost), "the result must name the identity")
	require.False(t, strings.Contains(result.String(), code),
		"the user code must not reach a report")

	// The fallback is reported on the diagnostic stream, naming the backend chosen.
	require.True(t, strings.Contains(diag.String(), `using "file"`),
		"the fallback to a file was not reported on the diagnostic stream")
}

// Under --output json stdout must be one document, and the code is only
// useful before the document exists.
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

// Under `go test` neither stream is a terminal, so a login that consulted one
// or read stdin could not complete. TestNoVerbReachesForATerminalOrStandardInput
// is the static half.
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

// Runs the real command tree, since the flag must be the one the tree registers.
func TestLoginWithoutAHubRefusesNamingTheFlag(t *testing.T) {
	testHome(t)
	var result, diag syncBuffer
	require.Equal(t, CodeRefused, Main([]string{"login"}, &result, &diag))
	require.Contains(t, diag.String(), "--hub",
		"the refusal must name the flag that supplies what it would otherwise have asked for")
	require.Empty(t, result.String(), "a refusal on the result stream would corrupt the json document")
}

// The refusal is only worth having if the flag lifts it: with it, the same URL
// fails for a network reason instead.
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
			"a plaintext run warns on the diagnostic stream every time")
	})
}

// A login that stored a credential it never received is the worst outcome here.
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

// Proven by the number of pauses: one pause means exactly two polls, the
// pending one and the expired one.
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

// A fixed-status server is the only way to reach 401/403 on the
// unauthenticated authorize endpoint; a refusing hub must not read as a missing one.
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
			require.Equal(t, tc.class, hub.ClassOf(err), "the class must survive the device flow")
			require.NotErrorIs(t, err, hub.ErrUnreachable,
				"a hub that answered is not an unreachable hub")
		})
	}

	t.Run("a hub that is not there is reported as unreachable", func(t *testing.T) {
		testHome(t)
		// Port 1 is reserved; a dial there fails without waiting for a timeout.
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

// The hub is a dead port, so a network-first ordering would surface a network error instead.
func TestLoginRefusesAHomeItCannotUse(t *testing.T) {
	t.Setenv("HOME", "")
	opts, _, _ := testOptions("https://127.0.0.1:1", output.FormatHuman)
	err := runLogin(context.Background(), opts, loginDepsFor(newGateClock(), nil))
	require.ErrorIs(t, err, ErrHomeUnset)
	require.NotErrorIs(t, err, hub.ErrUnreachable,
		"the home directory is validated before anything is dialled")
	require.Equal(t, CodeRefused, ExitCode(opts.Outcome, err))
}

// Silence here would let someone believe a login took effect.
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

	// require.True, not Contains: this stream carries the user code.
	require.True(t, strings.Contains(diag.String(), credentials.TokenEnvVar),
		"login must say that the environment token will be used in preference to what it stored")
	require.False(t, strings.Contains(diag.String(), "an-environment-token"),
		"naming the variable is the point; printing its value is not")
}

// The approving human sees the hostname, so a login without one must refuse.
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

// plantCredentialFile stores a credential through the real store and widens
// the file's mode. The path is discovered by listing, since the item key is
// derived by unexported code and a wrong guess would chmod nothing.
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

// A wide credential file (restored from backup, rsync without -p) used to be
// refused only at Save, after the human approved and the grant was spent. The
// hub is a dead port, so a mode check after the device flow would fail as unreachable.
func TestLoginRefusesAWideCredentialStoreBeforeSendingAnyoneToABrowser(t *testing.T) {
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
				"the mode check must be decided before the hub is dialled, or a human approves a login that cannot be stored")

			// require.False, not Contains: the haystack may carry a code.
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

// hostilePollCap ends a flow that would otherwise poll forever, so the poll
// count fails instead of the suite hanging; a passing run never reaches it.
const hostilePollCap = 5

// hostileHub is a raw handler, not the fake: fake.Options rounds durations
// into sanity and cannot express the wire values under test.
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

// `seconds * time.Second` wraps above ~9.22e9s; an interval of 18446744074
// became 290ms and login hammered the hub. Every row asserts zero polls, since
// checking only for an error would pass with the defect present.
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
			// The wrap is symmetric, so bounding only the upper end would leave this live.
			name: "a negative expires_in that wraps positive",
			body: `{` + codes + `,"expires_in":-9223372037,"interval":5}`,
			want: "expires_in is -9223372037 seconds",
		},
		{
			// Representable, so internal/device is what refuses it; it still must not print a code.
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
				"the token endpoint was polled %d times for an authorisation that could never be polled legally", polls.Load())
			require.False(t, displayedUserCode.MatchString(diag.String()),
				"a code was shown for an authorisation the client had already decided it could not honour")
			require.Empty(t, result.String())
		})
	}
}

// internal/hub classifies a cancelled request as unreachable, so wrapping that
// chain blamed a hub that was answering fine.
func TestAnInterruptedLoginIsNotBlamedOnTheHub(t *testing.T) {
	assertInterrupted := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, device.ErrDenied, "an interruption is not a refusal")
		require.NotErrorIs(t, err, device.ErrExpired)
		require.NotErrorIs(t, err, hub.ErrUnreachable,
			"the hub was answering; only the caller stopped")
		require.Zero(t, hub.ClassOf(err),
			"an interrupted login must carry no hub class, or a script switching on ClassOf blames the network")
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
			// Cancel with the request on the wire, then answer slowly enough that the cancellation is what the client sees.
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

// The record is seeded as raw bytes, so a rewrite of it is caught directly.
func TestLogoutRemovesTheCredentialAndTouchesNothingElse(t *testing.T) {
	home := testHome(t)
	hubURL := "https://hub.example.com"
	canonical, err := ParseHub(hubURL)
	require.NoError(t, err)

	store := openTestStore(t, home)
	require.NoError(t, store.Save(credentials.Issued(canonical.URL, "a-stored-token", 3600, time.Now())))

	// amctl's record, packages in both target locations, and an unmanaged neighbour.
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
		"logout altered something installed")

	_, found, err := openTestStore(t, home).Load(canonical.URL)
	require.NoError(t, err)
	require.False(t, found, "logout left the credential behind")

	// Negative control: the way this comparison would silently stop working is by excluding too much.
	t.Run("the comparison notices a change to any of the three trees", func(t *testing.T) {
		for _, rel := range []string{
			filepath.Join(DirName, canonical.Dir, "state.json"),
			filepath.Join(".claude", "skills", "hand-written", "SKILL.md"),
			filepath.Join(".codex", "prompts", "acme-lint.md"),
		} {
			path := filepath.Join(home, rel)
			original, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			// Re-baselined per file: restoring the previous one moved its mtime.
			base := snapshot(t, home)
			require.NoError(t, os.WriteFile(path, append(original, '!'), 0o600))
			require.NotEqual(t, base, snapshot(t, home), "a changed %s went unnoticed", rel)
			require.NoError(t, os.WriteFile(path, original, 0o600))
		}
	})
}

// No server is needed: logout makes no request.
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

// Both verbs key on the canonical hub URL, or logout would remove nothing and report success.
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

// Logout twice, or on a machine that never logged in, is normal for a provisioning script.
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

func TestLogoutRefusesAHomeItCannotUse(t *testing.T) {
	t.Setenv("HOME", "")
	opts, _, _ := testOptions("https://hub.example.com", output.FormatHuman)
	err := runLogout(opts, logoutDepsFor())
	require.ErrorIs(t, err, ErrHomeUnset)
	require.Equal(t, CodeRefused, ExitCode(opts.Outcome, err))
}

func TestLogoutWithoutAHubRefusesNamingTheFlag(t *testing.T) {
	testHome(t)
	var result, diag syncBuffer
	require.Equal(t, CodeRefused, Main([]string{"logout"}, &result, &diag))
	require.Contains(t, diag.String(), "--hub")
	require.Empty(t, result.String())
}

// Logout builds no hub client, so removing an http:// hub's credential doesn't need the flag again.
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

// TestNoVerbReachesForATerminalOrStandardInput proves no path can prompt:
// nothing in internal/cmd names os.Stdin or a terminal check. A synthetic
// prompting file is the negative control.
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
			t.Errorf("%s: %s — every command must run with no TTY; a prompt needs a flag beside it", name, found)
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

// interactiveUses walks the AST, so the words in a comment cannot fire it.
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

type fileState struct {
	Mode    fs.FileMode
	Size    int64
	Digest  string
	ModTime time.Time
}

// snapshot fingerprints every file under root by content, mode and mtime,
// excluding only what logout may change: the credential directory and directory mtimes.
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
