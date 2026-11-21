//go:build integration

// Each role boots with only its own environment. Process-level on purpose: checking the
// config struct or compose file tests a description of the boundary, not the boundary.
// The api runs as am_api, so a missing grant fails here first.
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

// apiRolePassword is set out of band, as a deployment does: the migration sets no password.
const apiRolePassword = "password-set-by-this-test-not-a-secret"

var (
	buildOnce  sync.Once
	binaryPath string
	buildErr   error
)

// binary builds the single binary every role runs from, once per run.
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

// datastoreVars carry a datastore credential; the web role must be handed none of them.
var datastoreVars = []string{
	"AGENT_MANAGER_DATABASE_URL",
	"AGENT_MANAGER_RIVER_DATABASE_URL",
	"AGENT_MANAGER_BLOB_URL",
}

func TestEachRoleBootsWithOnlyItsOwnEnvironment(t *testing.T) {
	ctx := context.Background()

	_, err := pool.Exec(ctx, fmt.Sprintf("alter role am_api password %s", quoteLiteral(apiRolePassword)))
	require.NoError(t, err)

	apiDSN := roleDSN(t, "am_api", apiRolePassword, "agent_manager")
	port := freePort(t)

	// Runs first, as compose's service_completed_successfully gate does.
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
			"AGENT_MANAGER_METRICS_ADDR":       fmt.Sprintf("127.0.0.1:%d", freePort(t)),
			"AGENT_MANAGER_LOG_FORMAT":         "console",
		}

		cmd, stop := startRole(t, []string{"serve", "api"}, env)

		health := fmt.Sprintf("http://127.0.0.1:%d/v1/health", port)
		requireHealthy(t, health)

		// The container health check runs this, without a shell.
		out, err := runRole(t, []string{"healthcheck", "--url", health}, nil, 15*time.Second)
		require.NoError(t, err, out)

		// A ping proves the connection, not the grants: exercise the read and write sets as am_api.
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
		// Two processes are the point: the web role reaches data only through the generated
		// client, using the api's credential.
		apiPort := freePort(t)
		apiCmd, stopAPI := startRole(t, []string{"serve", "api"}, map[string]string{
			"AGENT_MANAGER_DATABASE_URL":       apiDSN,
			"AGENT_MANAGER_RIVER_DATABASE_URL": queueURL,
			"AGENT_MANAGER_BLOB_URL":           "mem://",
			"AGENT_MANAGER_API_ADDR":           fmt.Sprintf("127.0.0.1:%d", apiPort),
			"AGENT_MANAGER_METRICS_ADDR":       fmt.Sprintf("127.0.0.1:%d", freePort(t)),
			"AGENT_MANAGER_LOG_FORMAT":         "console",
		})
		requireHealthy(t, fmt.Sprintf("http://127.0.0.1:%d/v1/health", apiPort))

		webPort, metricsPort := freePort(t), freePort(t)
		env := map[string]string{
			"AGENT_MANAGER_API_BASE_URL": fmt.Sprintf("http://127.0.0.1:%d", apiPort),
			"AGENT_MANAGER_WEB_ADDR":     fmt.Sprintf("127.0.0.1:%d", webPort),
			"AGENT_MANAGER_METRICS_ADDR": fmt.Sprintf("127.0.0.1:%d", metricsPort),
			"AGENT_MANAGER_LOG_FORMAT":   "console",
		}
		for _, name := range datastoreVars {
			_, present := env[name]
			require.Falsef(t, present, "the web role's environment must not carry %s", name)
		}

		cmd, stop := startRole(t, []string{"serve", "web"}, env)

		base := fmt.Sprintf("http://127.0.0.1:%d", webPort)
		requireHealthy(t, base+"/healthz")

		// Serving a screen, not merely listening. With no session the guard renders sign-in
		// before any hop; the web role holds no credential it could substitute.
		status, body := fetch(t, base+"/catalog")
		require.Equal(t, http.StatusOK, status,
			"the web role must render a screen with no database and no bucket")
		require.Contains(t, body, "am-signin-card",
			"and the screen must be the one that says how to get in")

		status, body = fetch(t, fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort))
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, `agent_manager_http_requests_total{code="3xx",method="GET",route="/catalog"}`)
		require.NotContains(t, body, "agent_manager_outbox", "web relays nothing, so it must report no outbox series")
		require.NotContains(t, body, "am-sidebar",
			"a signed-out request must not reach a shell, empty or otherwise")

		// A bogus cookie gets past the guard to the api, whose 401 renders as sign-in.
		status, body = fetchWithSession(t, base+"/catalog", "not-a-session-anyone-minted")
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, "am-signin-card")

		// With the api gone the same request must fail loudly: an outage must never read as
		// signed out or as an empty hub.
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

	// internal/worker's tests use memblob and no DB, so the real bootstrap (Build, River's
	// client, Register) is first exercised here, as am_fetcher.
	t.Run("worker run fetcher boots with the fetcher role's environment", func(t *testing.T) {
		const fetcherRolePassword = "fetcher-password-set-by-this-test-not-a-secret"
		_, alterErr := pool.Exec(ctx,
			fmt.Sprintf("alter role am_fetcher password %s", quoteLiteral(fetcherRolePassword)))
		require.NoError(t, alterErr)

		cmd, log, stop := startRoleWithLog(t, []string{"worker", "run", "fetcher"}, map[string]string{
			"AGENT_MANAGER_DATABASE_URL":       roleDSN(t, "am_fetcher", fetcherRolePassword, "agent_manager"),
			"AGENT_MANAGER_RIVER_DATABASE_URL": queueURL,
			// The only role handed a writable object store.
			"AGENT_MANAGER_BLOB_URL": "mem://",
			// json: the console writer colours fields, so substring assertions would be unreliable.
			"AGENT_MANAGER_LOG_FORMAT": "json",
		})

		// No endpoint to probe; this line is written after Build, Register and River's client.
		requireLogged(t, log, `"message":"worker starting"`)

		// The bootstrap honouring the Needs declaration in a real process.
		require.Contains(t, log.String(), `"blob":"read-write"`)
		require.Contains(t, log.String(), `"outbound":true`)

		require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
		require.NoError(t, stop(), "a SIGTERM must drain and exit 0")
		// Only written past Stop, which is only reached past client.Start.
		require.Contains(t, log.String(), `"message":"worker stopped"`)
	})
}

// The web role's environment alone cannot reach a datastore, proven by handing it to the api.
func TestTheAPIRoleCannotBootOnTheWebRolesEnvironment(t *testing.T) {
	env := map[string]string{
		"AGENT_MANAGER_API_BASE_URL": "http://127.0.0.1:8081",
		"AGENT_MANAGER_LOG_FORMAT":   "console",
	}

	out, err := runRole(t, []string{"serve", "api"}, env, 30*time.Second)
	require.Error(t, err, "serve api must not start without the credentials it needs")
	// Named, so a silent fallback to a default DSN would not pass for the wrong reason.
	require.Contains(t, out, "AGENT_MANAGER_DATABASE_URL")
}

func TestARoleRefusesOneDatabaseForBothSchemas(t *testing.T) {
	// Collapsing the two URLs would put Atlas in front of River's tables.
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

// output collects a child's combined output. os/exec writes from its own goroutine
// while the test reads, so the lock is required.
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
	// A bare environment: inheriting the test's would hand every role every credential.
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

// startRoleWithLog is startRole for a role whose only readiness signal is its log.
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

// requireLogged waits for a log line; a sleep would also pass for a dead process.
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

// fetch is call() when the body matters.
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

// fetchWithSession sends a session cookie; without one a request never leaves the web role.
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
