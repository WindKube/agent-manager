//go:build integration

// T035 / SC-006: each role boots with ONLY its own environment.
//
// This is a process-level test on purpose. Every cheaper version of it — check
// the config struct, check the compose file — tests a description of the boundary
// rather than the boundary. What SC-006 claims is that the api works with the
// credentials it is given and that the web role cannot reach a datastore with
// what it has, and the only way to know that is to hand a real process a real
// environment and watch what it can do.
//
// The api is booted as `am_api`, not as the superuser the rest of this suite
// uses. A missing grant fails the first time the code runs, and this is that
// first time.
package api_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// apiRolePassword is set on the am_api role by this test. The migration
// deliberately sets no password — a password in a migration is a credential in
// git — so the test sets one out of band, exactly as a deployment does.
const apiRolePassword = "password-set-by-this-test-not-a-secret"

var (
	buildOnce  sync.Once
	binaryPath string
	buildErr   error
)

// binary builds the single image's single binary once per run (principle I: every
// role is a subcommand of this one binary).
func binary(t *testing.T) string {
	t.Helper()

	buildOnce.Do(func() {
		out := filepath.Join(os.TempDir(), fmt.Sprintf("agent-manager-boot-%d", os.Getpid()))
		cmd := exec.Command("go", "build", "-o", out, "./cmd/agent-manager")
		cmd.Dir = "../.."
		if combined, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build agent-manager: %w\n%s", err, combined)
			return
		}
		binaryPath = out
	})
	require.NoError(t, buildErr)
	return binaryPath
}

// datastoreVars are the variables that carry a datastore credential. The web role
// must be handed none of them.
var datastoreVars = []string{
	"AGENT_MANAGER_DATABASE_URL",
	"AGENT_MANAGER_RIVER_DATABASE_URL",
	"AGENT_MANAGER_BLOB_URL",
}

func TestEachRoleBootsWithOnlyItsOwnEnvironment(t *testing.T) {
	ctx := context.Background()

	// The api's real runtime credential, per quickstart.md's configuration table.
	_, err := pool.Exec(ctx, fmt.Sprintf("alter role am_api password %s", quoteLiteral(apiRolePassword)))
	require.NoError(t, err)

	apiDSN := roleDSN(t, "am_api", apiRolePassword, "agent_manager")
	port := freePort(t)

	// The queue migration runs first and to completion, as compose's
	// service_completed_successfully gate makes it: nothing serving starts
	// against an unmigrated schema.
	t.Run("migrate queue boots with only the queue url", func(t *testing.T) {
		out, err := runRole(t, []string{"migrate", "queue"}, map[string]string{
			"AGENT_MANAGER_RIVER_DATABASE_URL": queueURL,
			"AGENT_MANAGER_LOG_FORMAT":         "console",
		}, 90*time.Second)
		require.NoError(t, err, out)
		require.Contains(t, out, "river migration")
	})

	t.Run("serve api works with the api role's environment and nothing else", func(t *testing.T) {
		env := map[string]string{
			"AGENT_MANAGER_DATABASE_URL":       apiDSN,
			"AGENT_MANAGER_RIVER_DATABASE_URL": queueURL,
			"AGENT_MANAGER_BLOB_URL":           "mem://",
			"AGENT_MANAGER_API_ADDR":           fmt.Sprintf("127.0.0.1:%d", port),
			"AGENT_MANAGER_LOG_FORMAT":         "console",
		}

		cmd, stop := startRole(t, []string{"serve", "api"}, env)

		health := fmt.Sprintf("http://127.0.0.1:%d/v1/health", port)
		requireHealthy(t, health)

		// The api's own subcommand probes the same endpoint without a shell, which
		// is what the container health check runs (FR-058).
		out, err := runRole(t, []string{"healthcheck", "--url", health}, nil, 15*time.Second)
		require.NoError(t, err, out)

		// A ping proves the connection, not the grants. These two exercise the
		// read set (profile, membership, revision, session, identity,
		// group_role_map) and then the write set (sync_event, audit_event) through
		// the credential the role actually runs as. A missing grant fails the
		// first time the code runs, and for am_api this is that first time.
		base := fmt.Sprintf("http://127.0.0.1:%d", port)
		require.Equal(t, http.StatusOK, call(t, http.MethodGet, base+"/v1/profiles", kw.token, ""),
			"am_api must be able to serve a read")
		require.Equal(t, http.StatusNoContent, call(t, http.MethodPost, base+"/v1/sync", kw.token,
			`{"profile":"platform-baseline","revision":2,"host":"boot-test","targets":["claude-code"]}`),
			"am_api must be able to commit a mutation and its audit row")

		require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
		require.NoError(t, stop(), "a SIGTERM must drain and exit 0")

		conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if dialErr == nil {
			_ = conn.Close()
		}
		require.Error(t, dialErr, "the port must refuse once the role has stopped")
	})

	t.Run("serve web serves with no datastore credential at all", func(t *testing.T) {
		// An api of its own, because the subtest above deliberately kills the one it
		// started. Two processes are the point: the catalog this renders crosses a
		// real HTTP hop through the GENERATED client, and the credential that read
		// it belongs to the other process.
		apiPort := freePort(t)
		apiCmd, stopAPI := startRole(t, []string{"serve", "api"}, map[string]string{
			"AGENT_MANAGER_DATABASE_URL":       apiDSN,
			"AGENT_MANAGER_RIVER_DATABASE_URL": queueURL,
			"AGENT_MANAGER_BLOB_URL":           "mem://",
			"AGENT_MANAGER_API_ADDR":           fmt.Sprintf("127.0.0.1:%d", apiPort),
			"AGENT_MANAGER_LOG_FORMAT":         "console",
		})
		requireHealthy(t, fmt.Sprintf("http://127.0.0.1:%d/v1/health", apiPort))

		webPort := freePort(t)
		env := map[string]string{
			"AGENT_MANAGER_API_BASE_URL": fmt.Sprintf("http://127.0.0.1:%d", apiPort),
			"AGENT_MANAGER_WEB_ADDR":     fmt.Sprintf("127.0.0.1:%d", webPort),
			"AGENT_MANAGER_LOG_FORMAT":   "console",
		}
		for _, name := range datastoreVars {
			_, present := env[name]
			require.Falsef(t, present, "the web role's environment must not carry %s", name)
		}

		cmd, stop := startRole(t, []string{"serve", "web"}, env)

		base := fmt.Sprintf("http://127.0.0.1:%d", webPort)
		requireHealthy(t, base+"/healthz")

		// Serving a screen, not merely listening. The claim SC-006 makes is that
		// the role still WORKS with what it is given, and the web role's whole
		// premise is that a screen renders without a datastore.
		//
		// With no session it renders the sign-in screen, and that is the point
		// rather than a shortfall: the guard refuses every protected route before
		// any hop, and the web role holds no credential it could substitute
		// (constitution principle II). A page that renders and says why is exactly
		// what a correct hub does here.
		status, body := fetch(t, base+"/catalog")
		require.Equal(t, http.StatusOK, status,
			"the web role must render a screen with no database and no bucket")
		require.Contains(t, body, "am-signin-card",
			"and the screen must be the one that says how to get in")
		require.NotContains(t, body, "am-sidebar",
			"a signed-out request must not reach a shell, empty or otherwise")

		// The api hop, which the request above never made. A cookie is what gets
		// past the guard, and this one is not a session anybody minted — so the api
		// answers 401, the hub client reports that as signed out, and the guard
		// renders the same sign-in screen. One 401 turned into a screen, across two
		// processes.
		status, body = fetchWithSession(t, base+"/catalog", "not-a-session-anyone-minted")
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, "am-signin-card")

		// The negative control, and it needs the cookie for the same reason: with
		// the api gone that request must fail loudly rather than rendering the same
		// page. An outage dressed as a login is one nobody reports, and one dressed
		// as an empty hub is worse — so being unable to reach the api must never
		// read as being signed out (FR-122).
		require.NoError(t, apiCmd.Process.Signal(syscall.SIGTERM))
		require.NoError(t, stopAPI(), "a SIGTERM must drain and exit 0")
		status, body = fetchWithSession(t, base+"/catalog", "not-a-session-anyone-minted")
		require.Equal(t, http.StatusBadGateway, status,
			"an unreachable api must never render as a catalog of any kind, nor as a sign-in")
		require.NotContains(t, body, "am-signin-card",
			"an outage that renders as a sign-in screen sends the person to try their password again")
		require.NotContains(t, body, "am-row")

		require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
		require.NoError(t, stop(), "a SIGTERM must drain and exit 0")
	})

	// The fetcher is booted as am_fetcher, the credential it actually runs as.
	// Nothing cheaper reaches this path: internal/worker's own tests build against
	// memblob with DB: AccessNone, so Build refusing a declared need with no
	// credential behind it, River's client opening the queue database, and the
	// role's Register constructing the handler are all first exercised here.
	t.Run("worker run fetcher boots with the fetcher role's environment", func(t *testing.T) {
		const fetcherRolePassword = "fetcher-password-set-by-this-test-not-a-secret"
		_, alterErr := pool.Exec(ctx,
			fmt.Sprintf("alter role am_fetcher password %s", quoteLiteral(fetcherRolePassword)))
		require.NoError(t, alterErr)

		cmd, log, stop := startRoleWithLog(t, []string{"worker", "run", "fetcher"}, map[string]string{
			"AGENT_MANAGER_DATABASE_URL":       roleDSN(t, "am_fetcher", fetcherRolePassword, "agent_manager"),
			"AGENT_MANAGER_RIVER_DATABASE_URL": queueURL,
			// The only role handed a writable object store (principle II). compose
			// gives it the am-fetcher MinIO key; mem:// is the same capability
			// without the container.
			"AGENT_MANAGER_BLOB_URL": "mem://",
			// json, not the console format the subtests above use: the console
			// writer colours each field, so `blob=read-write` is not a substring of
			// its own output and an assertion on it would pass only by accident.
			"AGENT_MANAGER_LOG_FORMAT": "json",
		})

		// The role has no endpoint to probe, so its own startup line is the signal.
		// It is written after Build, after Register and after River's client is
		// constructed, which is every part of the bootstrap this test is here for.
		requireLogged(t, log, `"message":"worker starting"`)

		// Not decoration: this is the bootstrap honouring the Needs declaration in
		// a real process rather than in a unit test's fake. read-write on the blob
		// is what makes the fetcher the only role holding a blob.Writer.
		require.Contains(t, log.String(), `"blob":"read-write"`)
		require.Contains(t, log.String(), `"outbound":true`)

		require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
		require.NoError(t, stop(), "a SIGTERM must drain and exit 0")
		// River was started, not merely constructed: Stop is only reached past
		// client.Start, and this line is only written past Stop.
		require.Contains(t, log.String(), `"message":"worker stopped"`)
	})
}

// The other half of SC-006: the web role's environment alone cannot reach a
// datastore. Proven by handing it to the only role that opens one.
func TestTheAPIRoleCannotBootOnTheWebRolesEnvironment(t *testing.T) {
	env := map[string]string{
		"AGENT_MANAGER_API_BASE_URL": "http://127.0.0.1:8081",
		"AGENT_MANAGER_LOG_FORMAT":   "console",
	}

	out, err := runRole(t, []string{"serve", "api"}, env, 30*time.Second)
	require.Error(t, err, "serve api must not start without the credentials it needs")
	// Named, not merely absent: a role that silently fell back to a default DSN or
	// a unix socket would also "fail to start" here, for the wrong reason.
	require.Contains(t, out, "AGENT_MANAGER_DATABASE_URL")
}

func TestARoleRefusesOneDatabaseForBothSchemas(t *testing.T) {
	// Principle IX: the queue lives in its own database. Collapsing the two URLs
	// is the one misconfiguration that would put Atlas in front of River's tables,
	// so the api must refuse it rather than start.
	env := map[string]string{
		"AGENT_MANAGER_DATABASE_URL":       appURL,
		"AGENT_MANAGER_RIVER_DATABASE_URL": appURL,
		"AGENT_MANAGER_BLOB_URL":           "mem://",
		"AGENT_MANAGER_API_ADDR":           fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"AGENT_MANAGER_LOG_FORMAT":         "console",
	}

	out, err := runRole(t, []string{"serve", "api"}, env, 30*time.Second)
	require.Error(t, err)
	require.Contains(t, out, "must live in its own database")
}

// ---- process helpers ---------------------------------------------------------

// output collects a child process's combined output. os/exec copies into it from
// its own goroutine while the test reads it to build a failure message, so the
// lock is load-bearing rather than defensive: a plain strings.Builder here is a
// data race that -race fails the whole package on.
type output struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func command(t *testing.T, args []string, env map[string]string) (*exec.Cmd, *output) {
	t.Helper()

	cmd := exec.Command(binary(t), args...)
	// A bare environment: only what the role is given, plus PATH so the process
	// can run at all. Inheriting the test's environment would hand every role
	// every credential, which is the thing under test.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	for name, value := range env {
		cmd.Env = append(cmd.Env, name+"="+value)
	}

	out := &output{}
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd, out
}

func runRole(t *testing.T, args []string, env map[string]string, timeout time.Duration) (string, error) {
	t.Helper()

	cmd, out := command(t, args, env)
	require.NoError(t, cmd.Start())

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return out.String(), fmt.Errorf("%v did not finish within %s", args, timeout)
	}
}

func startRole(t *testing.T, args []string, env map[string]string) (cmd *exec.Cmd, wait func() error) {
	t.Helper()

	cmd, _, wait = startRoleWithLog(t, args, env)
	return cmd, wait
}

// startRoleWithLog is startRole for a role with no endpoint to probe. The log is
// the only readiness signal such a role has.
func startRoleWithLog(t *testing.T, args []string, env map[string]string) (cmd *exec.Cmd, log *output, wait func() error) {
	t.Helper()

	cmd, out := command(t, args, env)
	require.NoError(t, cmd.Start())

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	t.Cleanup(func() { _ = cmd.Process.Kill() })

	return cmd, out, func() error {
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("%v exited with %w\n%s", args, err, out.String())
			}
			return nil
		case <-time.After(30 * time.Second):
			return fmt.Errorf("%v did not exit on SIGTERM\n%s", args, out.String())
		}
	}
}

// requireLogged waits for a line the role writes once it has got somewhere. A
// sleep would pass just as well for a process that had already died.
func requireLogged(t *testing.T, log *output, want string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(log.String(), want) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.FailNowf(t, "the role never logged what it logs on startup",
		"waited 30s for %q\n%s", want, log.String())
}

// call drives the live process over HTTP and returns the status.
func call(t *testing.T, method, url, token, body string) int {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	require.NoError(t, err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		payload := make([]byte, 512)
		n, _ := resp.Body.Read(payload)
		t.Logf("%s %s -> %d: %s", method, url, resp.StatusCode, payload[:n])
	}
	return resp.StatusCode
}

// fetch is call() when the body matters: three outcomes of a catalog read look
// identical by status alone if any two of them ever collapse.
func fetch(t *testing.T, url string) (status int, body string) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	payload, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(payload)
}

// fetchWithSession is the same request from a browser holding a session cookie.
// It is what reaches the api at all: the guard reads the cookie before it asks
// anybody who this is, so a request without one never leaves the web role.
func fetchWithSession(t *testing.T, url, token string) (status int, body string) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "am_session", Value: token})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	payload, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(payload)
}

func requireHealthy(t *testing.T, url string) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			status := resp.StatusCode
			_ = resp.Body.Close()
			if status == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s never became healthy", url)
}

func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return port
}

func roleDSN(t *testing.T, role, password, database string) string {
	t.Helper()

	config := pool.Config().ConnConfig
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		role, password, config.Host, config.Port, database)
}

func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
