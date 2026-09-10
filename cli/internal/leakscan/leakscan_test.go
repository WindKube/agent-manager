// Package leakscan proves that nothing in this CLI writes a token, a device
// code or a user code anywhere. It lives in its own directory because the
// gate re-runs the whole module's test suite in a child process, so it
// belongs to no single package.
//
// The access token and the device code are unconditional: neither is ever
// shown to a human or typed by one, so any occurrence anywhere is a defect.
// The user code is not unconditional: RFC 8628 requires the client to
// display it, so the rule enforced here is narrower — it may be written
// once, live, to the interactive diagnostic stream, but must never reach a
// result document, the installation record, a log line, or an error value.
//
// Three detectors, each with a gap the others cover:
//
//  1. TestNoSecretReachesAnyOutputOfTheWholeSuite re-runs the whole suite in
//     a child process and scans everything printed, including output that
//     bypassed testing.T entirely. It cannot see a value it cannot name, so
//     the fake hub's randomly generated tokens are covered instead by a
//     credential-assignment shape pattern (`access_token=`, `Bearer x`, …),
//     and it cannot see what no test exercised.
//  2. The planting tests drive the real credential-carrying code with
//     sentinel values through every fmt verb and error branch reachable
//     without a network, and are the anti-vacuity mechanism for detector 1:
//     each logs plantMarker, and the scan fails if that marker is absent.
//  3. TestNoResultTypeCanCarryACredential walks every output.Result
//     implementation's fields structurally, so it cannot rot, but is blind
//     to anything that is not a Result.
//
// The union is not a proof: a leak of a randomly generated token, on a path
// no test runs, in a shape that doesn't look like an assignment, would pass
// all three.
package leakscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/credentials"
	"github.com/WindKube/agent-manager/cli/internal/device"
	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/hub/fake"
	"github.com/WindKube/agent-manager/cli/internal/output"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// The known test secrets. They are long, unmistakable and unlike anything
// else the suite prints, so a match is a leak and never a coincidence.
// sentinelUserCode is a legal user code under the contract's pattern so
// nothing rejects it as malformed, and it is banned from the suite's output
// outright: the one legitimate write of a user code is the live display,
// which a test must instead assert using the fake hub's own random code.
const (
	sentinelAccessToken  = "amctl-sc010-access-token-9f3c1d5b7a2e4680"
	sentinelRefreshToken = "amctl-sc010-refresh-token-4c8a6b1e0d9f2735"
	sentinelDeviceCode   = "amctl-sc010-device-code-1b7e9d3f5a0c8462"
	sentinelUserCode     = "SC10-QRTV"
)

type sentinel struct {
	name  string
	value string
}

func sentinels() []sentinel {
	return []sentinel{
		{"access token", sentinelAccessToken},
		{"refresh token", sentinelRefreshToken},
		{"device code", sentinelDeviceCode},
		{"user code", sentinelUserCode},
	}
}

// childEnvVar stops the run-wide scan from re-entering itself. Without it the
// child's own leakscan package would spawn a grandchild, and so on.
const childEnvVar = "AMCTL_LEAKSCAN_CHILD"

// plantMarker is logged by every planting test. The run-wide scan requires it
// in the child's output: it travels the same path a leak would, so its presence
// proves the scan is reading live output rather than an empty buffer.
const plantMarker = "leakscan: exercised"

// credentialAssignment matches the shape of a leak rather than the value of
// one: a credential-ish key immediately followed by a value. This covers
// the fake hub's randomly generated tokens, which an exact scan cannot name.
// The keyword list is bounded by \b on both sides, so `token_type` does not
// match; AMCTL_TOKEN is listed whole for the same reason.
var credentialAssignment = regexp.MustCompile(
	`(?i)\b(amctl[_-]?token|access[_-]?token|refresh[_-]?token|device[_-]?code|user[_-]?code|token|bearer|authorization|passphrase|password|api[_-]?key)\b["']?\s*[:=]+\s*("?[^\s",}&]+)`)

// redactedValue is the only exemption to credentialAssignment: a key with a
// visibly redacted value is the thing FR-007 asks for, not a violation of it.
// Nothing here exempts a key whose value is an actual string.
var redactedValue = regexp.MustCompile(`(?i)^"?(redacted|\*+|<[^>]*>|-+|nil|null|none|unset|empty|""|''|\[?redacted\]?)"?$`)

type finding struct {
	line int
	what string
	// excerpt has every sentinel replaced by its name, so a gate that
	// reprints the secret it caught does not leak it into what the next run scans.
	excerpt string
}

func (f finding) String() string { return fmt.Sprintf("line %d: %s: %s", f.line, f.what, f.excerpt) }

// scan is the whole detector, as a pure function over text so it can have a
// negative control instead of being trusted.
func scan(text string) []finding {
	var out []finding
	for i, line := range strings.Split(text, "\n") {
		for _, s := range sentinels() {
			if strings.Contains(line, s.value) {
				out = append(out, finding{i + 1, "the test " + s.name + " appears in output", redact(line)})
			}
		}
		for _, m := range credentialAssignment.FindAllStringSubmatch(line, -1) {
			if redactedValue.MatchString(m[2]) {
				continue
			}
			out = append(out, finding{i + 1, "a credential-shaped assignment (" + m[1] + ")", redact(line)})
		}
	}
	return out
}

// childPanicMargin is how much sooner the child's own -timeout fires than
// the deadline this process enforces, long enough for `go test` to write a
// full goroutine dump before the pipe closes.
const childPanicMargin = 90 * time.Second

// childTimeoutPanic is what `go test` prints when a test binary exceeds its
// own -timeout.
const childTimeoutPanic = "panic: test timed out after"

// panicExcerptBytes bounds the goroutine dump a hang reports.
const panicExcerptBytes = 4000

// redactBlock is redact for a multi-line excerpt: the whole block is capped
// rather than each line truncated, which would throw away the stack frames
// that make a dump worth printing.
func redactBlock(s string, limit int) string {
	for _, sent := range sentinels() {
		s = strings.ReplaceAll(s, sent.value, "<the test "+sent.name+">")
	}
	if len(s) > limit {
		s = s[:limit] + "\n...(truncated)"
	}
	return s
}

// timeoutTailBytes is how much of the child's output a timeout failure shows.
const timeoutTailBytes = 1500

// finishedPackages makes a timeout actionable: `go test ./...` buffers a
// package's output until it finishes, so the hung one is precisely the one
// missing from this list.
func finishedPackages(out string) []string {
	var pkgs []string
	for _, line := range strings.Split(out, "\n") {
		for _, prefix := range []string{"ok  \t", "FAIL\t", "?   \t", "--- FAIL: "} {
			rest, found := strings.CutPrefix(line, prefix)
			if !found {
				continue
			}
			name, _, _ := strings.Cut(rest, "\t")
			pkgs = append(pkgs, strings.TrimSpace(name))
		}
	}
	return pkgs
}

// tail is the last n bytes of s, for a failure message that has to show
// something without showing 160KB of it.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

func redact(line string) string {
	for _, s := range sentinels() {
		line = strings.ReplaceAll(line, s.value, "<the test "+s.name+">")
	}
	if len(line) > 300 {
		line = line[:300] + "..."
	}
	return line
}

// ---------------------------------------------------------------- detector 1

// TestNoSecretReachesAnyOutputOfTheWholeSuite re-runs the module's suite in
// a child process and scans everything it printed. -v is required, not
// cosmetic: without it a passing test's t.Log output is discarded. The
// child's exit status is deliberately not asserted, since a broken sibling
// test is that sibling's failure; what is asserted is that the child
// produced a suite's worth of output, so a compile failure cannot pass this
// gate by producing nothing to scan.
func TestNoSecretReachesAnyOutputOfTheWholeSuite(t *testing.T) {
	if os.Getenv(childEnvVar) != "" {
		t.Skip("child run: the suite is being scanned by the parent")
	}
	root := moduleRoot(t)

	// The child's deadline must be shorter than this test's own -test.timeout,
	// or a child that outlives its parent makes the parent panic with
	// nothing scanned at all.
	budget := childBudget(t)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	// The child's own -timeout is deliberately shorter than the deadline
	// above: when `go test` hits its own timeout it panics and dumps every
	// goroutine's stack, naming the hung test, which is captured below. When
	// the context wins instead there is nothing to read but the clock.
	cmd := exec.CommandContext(ctx, goTool(t), "test", "-count=1", "-v",
		"-timeout="+(budget-childPanicMargin).String(), "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), childEnvVar+"=1")
	out, err := cmd.CombinedOutput()
	captured := string(out)
	if err != nil {
		// Not a failure of this gate; see the doc comment.
		t.Logf("the child suite exited non-zero (%v); scanning its output anyway", err)
	}
	// A child killed by the deadline did not finish the suite, so a clean
	// scan proves nothing about the part that never ran.
	if i := strings.Index(captured, childTimeoutPanic); i >= 0 {
		t.Fatalf("the child suite hung and timed itself out, so this scan covered only part of it "+
			"(captured %d bytes).\npackages that finished: %s\nthe child's own report, from the panic:\n%s",
			len(captured), strings.Join(finishedPackages(captured), " "),
			redactBlock(captured[i:], panicExcerptBytes))
	}
	if ctx.Err() != nil {
		t.Fatalf("the child suite did not finish within %s, so this scan covered only part of it "+
			"— a clean scan of half a suite is not evidence (captured %d bytes).\n"+
			"packages that finished: %s\nlast %d bytes of what it printed:\n%s",
			budget, len(captured), strings.Join(finishedPackages(captured), " "),
			timeoutTailBytes, redact(tail(captured, timeoutTailBytes)))
	}

	// Anti-vacuity: each of these must hold before a clean scan means
	// anything, since a scan of a buffer nothing was written to passes
	// forever. require's own Contains/Greater are avoided deliberately,
	// since they print the whole haystack (the suite's output) on failure,
	// which would re-emit any secret into the output the next run scans.
	requireOutput := func(cond bool, why string) {
		t.Helper()
		if !cond {
			t.Fatalf("%s\nthe scan is not looking at a suite's worth of output, so a clean result would mean nothing.\nlast 400 bytes of what it saw:\n%s",
				why, redact(tail(captured, 400)))
		}
	}
	requireOutput(len(captured) > 20_000, "the child run produced almost no output")
	requireOutput(strings.Contains(captured, plantMarker),
		"none of the planting tests reported in, so nothing put a sentinel into the output being scanned")
	requireOutput(strings.Contains(captured, "--- SKIP: "+t.Name()),
		"the child did not skip this test, so either "+childEnvVar+" was not passed through or the child is not this suite")
	requireOutput(strings.Count(captured, "--- PASS") >= 20, "the child suite barely ran")
	for _, pkg := range []string{
		"internal/credentials", "internal/device", "internal/hub", "internal/output",
	} {
		requireOutput(strings.Contains(captured, pkg),
			"the child run never reached "+pkg+", which is one of the packages that handles credentials")
	}

	for _, f := range scan(captured) {
		t.Errorf("FR-007 violation in the suite's output: %s", f)
	}
}

// TestScanCatchesTheLeaksItIsGivenOnPurpose is the permanent negative
// control: each leaky case is output the scan must reject, and the clean
// cases are false positives it must not invent, taken from real suite output.
func TestScanCatchesTheLeaksItIsGivenOnPurpose(t *testing.T) {
	leaky := []struct {
		name string
		text string
	}{
		{"the access token in a log line", "    login_test.go:41: stored " + sentinelAccessToken},
		{"the refresh token in a struct dump", `{Refresh:` + sentinelRefreshToken + `}`},
		{"the device code in an error", "polling for the device token: code " + sentinelDeviceCode + " rejected"},
		{"the user code in a report", `{"kind":"login","result":{"code":"` + sentinelUserCode + `"}}`},
		{"a header dump of an unknown token", "> Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.zzz"},
		{"a form body dump of an unknown device code", "device_code=Zm9vYmFyYmF6&grant_type=urn:ietf"},
		{"a json field holding an unknown token", `{"access_token": "Q2xhdWRlIHdhcyBoZXJlLg"}`},
		{"an env dump", "AMCTL_TOKEN=hunter2"},
	}
	for _, c := range leaky {
		t.Run(c.name, func(t *testing.T) {
			require.NotEmpty(t, scan(c.text), "the scan did not catch a deliberate leak")
		})
	}

	clean := []struct {
		name string
		text string
	}{
		{"a long camel-case test name", "=== RUN   TestR3InterruptionAtEveryStepLeavesOldOrNew"},
		{"the token type from the contract", `{"token_type":"Bearer","expires_in":3600}`},
		{"the redacting Stringer's own output", "credential for https://hub.example as nobody, token redacted, no stated expiry"},
		{"a redacted header dump", "> Authorization: <redacted>"},
		{"prose naming the environment variable", "refusing to persist the token from AMCTL_TOKEN"},
		{"a digest", "digest sha256:" + strings.Repeat("ab", 32)},
		{"an ordinary pass line", "--- PASS: TestTheFileFallbackWritesThePathWePredict (0.00s)"},
	}
	for _, c := range clean {
		t.Run(c.name, func(t *testing.T) {
			require.Empty(t, scan(c.text), "the scan invented a leak")
		})
	}
}

// ---------------------------------------------------------------- detector 2

// TestTheDeviceFlowNeverRendersTheCodesItHolds drives device.Flow through
// every answer the token endpoint can give, with the sentinel codes in it,
// and checks the error and every fmt verb, including %#v, which does not
// consult String.
func TestTheDeviceFlowNeverRendersTheCodesItHolds(t *testing.T) {
	answers := []struct {
		name    string
		code    device.ErrorCode
		issued  *device.Issued
		pollErr error
		wantErr error
	}{
		{name: "denied", code: device.CodeAccessDenied, wantErr: device.ErrDenied},
		{name: "expired", code: device.CodeExpiredToken, wantErr: device.ErrExpired},
		{name: "invalid grant", code: device.CodeInvalidGrant, wantErr: device.ErrInvalidGrant},
		{name: "an unrecognised refusal", code: "teapot", wantErr: device.ErrUnknownRefusal},
		{name: "a refusal with no reason", wantErr: device.ErrUnknownRefusal},
		{name: "pending until the window closes", code: device.CodeAuthorizationPending, wantErr: device.ErrExpired},
		{name: "slow down until the window closes", code: device.CodeSlowDown, wantErr: device.ErrExpired},
		{
			// A transport error is wrapped verbatim, which puts the burden on
			// whatever produces it to not have put the device code in it;
			// this test cannot verify that itself.
			name:    "a transport failure",
			pollErr: errTransportPassedThrough,
			wantErr: errTransportPassedThrough,
		},
		{
			name:    "success with no lifetime",
			issued:  &device.Issued{AccessToken: sentinelAccessToken, TokenType: "Bearer"},
			wantErr: device.ErrProtocol,
		},
	}

	for _, a := range answers {
		t.Run(a.name, func(t *testing.T) {
			clk := &steppingClock{now: time.Unix(1_700_000_000, 0).UTC()}
			flow, err := device.Begin(context.Background(),
				&stubTransport{code: a.code, issued: a.issued, err: a.pollErr}, clk,
				device.AuthorizeRequest{ClientID: "amctl", Host: "leakscan.example"})
			require.NoError(t, err)

			// The two accessors allowed to return the user code, asserted
			// rather than assumed so a Flow that stopped returning it would
			// not make every other assertion here pass vacuously.
			require.Equal(t, sentinelUserCode, flow.UserCode())
			require.Contains(t, flow.VerificationURIComplete(), sentinelUserCode)

			_, err = flow.Wait(context.Background())
			require.Error(t, err)
			require.ErrorIs(t, err, a.wantErr)
			requireNoSentinel(t, "the error", err.Error())
			requireNoSentinelInAnyVerb(t, "the flow", flow)
			requireNoSentinelInAnyVerb(t, "the error value", err)
		})
	}
	planted(t, len(answers))
}

// errTransportPassedThrough is the transport error the stub returns,
// asserted with errors.Is to prove the specific pass-through.
var errTransportPassedThrough = errors.New("connection reset by peer")

func TestAnIssuedTokenNeverRendersItself(t *testing.T) {
	clk := &steppingClock{now: time.Unix(1_700_000_000, 0).UTC()}
	flow, err := device.Begin(context.Background(),
		&stubTransport{issued: &device.Issued{
			AccessToken:  sentinelAccessToken,
			RefreshToken: sentinelRefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    time.Hour,
		}}, clk, device.AuthorizeRequest{ClientID: "amctl", Host: "leakscan.example"})
	require.NoError(t, err)

	tok, err := flow.Wait(context.Background())
	require.NoError(t, err)

	// The accessors must still work, or a Token that stopped returning the
	// token would pass every leak assertion below while breaking login.
	require.Equal(t, sentinelAccessToken, tok.AccessToken())
	refresh, ok := tok.RefreshToken()
	require.True(t, ok)
	require.Equal(t, sentinelRefreshToken, refresh)

	requireNoSentinelInAnyVerb(t, "the token", tok)
	requireNoSentinelInAnyVerb(t, "a struct holding the token", struct {
		Tok  *device.Token
		Flow *device.Flow
	}{tok, flow})
	planted(t, 1)
}

// TestACredentialNeverRendersItsToken covers credentials.Credential's fmt
// verbs, the fallback warning, and the error a corrupt store produces.
func TestACredentialNeverRendersItsToken(t *testing.T) {
	const hubURL = "https://hub.leakscan.example"

	var warnings bytes.Buffer
	store, err := credentials.Open(credentials.Options{
		StateRoot: t.TempDir(),
		Warnf:     func(f string, a ...any) { fmt.Fprintf(&warnings, f+"\n", a...) },
		// The file backend: the only one whose corrupt-blob path can be
		// exercised on any platform, and it keeps this test off the real keychain.
		Backends: []keyring.BackendType{keyring.FileBackend},
	})
	require.NoError(t, err)

	cred := credentials.Issued(hubURL, sentinelAccessToken, 3600, time.Now())
	require.NoError(t, store.Save(cred))

	loaded, found, err := store.Load(hubURL)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, sentinelAccessToken, loaded.Token, "the round trip must still work")

	requireNoSentinelInAnyVerb(t, "the credential", cred)
	requireNoSentinelInAnyVerb(t, "the resolved credential", loaded)
	requireNoSentinel(t, "the fallback warning", warnings.String())
	requireNoSentinel(t, "the store location", store.Location())

	// json.Marshal is a separate serialiser from the fmt verbs above: it
	// ignores String and GoString entirely, so an exported Token field with
	// no `json:"-"` tag would marshal the raw credential.
	requireNoSentinelInJSON(t, "the credential", cred)
	requireNoSentinelInJSON(t, "the resolved credential", loaded)
	requireNoSentinelInJSON(t, "a struct holding a credential", struct {
		Cred     credentials.Credential
		Resolved credentials.Resolved
	}{cred, credentials.Resolved{Credential: loaded, Source: credentials.SourceStore, Location: store.Location()}})

	t.Run("the error from a store it cannot read", func(t *testing.T) {
		// Overwrite the item keyring just wrote with content that has the
		// token in the clear; the key is discovered by listing rather than recomputed.
		dir := credentialDir(t, store)
		items, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, items, 1, "expected exactly one credential item on disk")
		path := filepath.Join(dir, items[0].Name())
		require.NoError(t, os.WriteFile(path,
			[]byte(`{"schema_version":1,"hub":"`+hubURL+`","token":"`+sentinelAccessToken+`"}`), 0o600))

		_, _, err = store.Load(hubURL)
		require.Error(t, err, "an item the backend cannot decrypt must be refused, not read as absent")
		requireNoSentinel(t, "the corrupt-store error", err.Error())
		requireNoSentinelInAnyVerb(t, "the corrupt-store error value", err)
	})

	t.Run("an environment token is refused for persistence without quoting it", func(t *testing.T) {
		t.Setenv(credentials.TokenEnvVar, sentinelAccessToken)
		resolved, found, err := credentials.Resolver{
			Open: func() (*credentials.Store, error) {
				t.Fatal("FR-005: the store must not be opened when the environment supplies a token")
				return nil, nil
			},
		}.Resolve(hubURL)
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, credentials.SourceEnvironment, resolved.Source)

		err = store.Save(resolved.Credential)
		require.Error(t, err)
		requireNoSentinel(t, "the refusal to persist an environment token", err.Error())
		requireNoSentinelInAnyVerb(t, "the resolved environment credential", resolved)
	})

	planted(t, 7)
}

// credentialDir recovers the fallback directory from the store's own
// rendering of it, "file (<dir>)", rather than duplicating the join of
// StateRoot and DirName.
func credentialDir(t *testing.T, s *credentials.Store) string {
	t.Helper()
	loc := s.Location()
	require.True(t, strings.HasPrefix(loc, "file ("), "expected the file backend, got %q", loc)
	return strings.TrimSuffix(strings.TrimPrefix(loc, "file ("), ")")
}

// TestTheHubClientNeverRendersItsBearerToken puts the sentinel token into a
// real hub.Hub and makes it fail two ways, since an error that dumped the
// request would leak the Authorization header.
func TestTheHubClientNeverRendersItsBearerToken(t *testing.T) {
	f := fake.New(fake.Options{TLS: true})
	defer f.Close()
	tg := f.Target()

	h, err := hub.New(hub.Config{URL: tg.BaseURL, Token: sentinelAccessToken, HTTPClient: tg.HTTPClient})
	require.NoError(t, err)

	_, err = h.ListProfiles(context.Background())
	require.Error(t, err, "a token the hub never issued must be refused")
	require.ErrorIs(t, err, hub.ErrUnauthorised)
	requireNoSentinel(t, "the 401 error", err.Error())
	requireNoSentinelInAnyVerb(t, "the 401 error value", err)
	requireNoSentinelInAnyVerb(t, "the hub client", h)

	dead := fake.New(fake.Options{TLS: true})
	deadURL := dead.Target().BaseURL
	deadClient := dead.Target().HTTPClient
	dead.Close()

	unreachable, err := hub.New(hub.Config{URL: deadURL, Token: sentinelAccessToken, HTTPClient: deadClient})
	require.NoError(t, err)
	_, err = unreachable.Health(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, hub.ErrUnreachable)
	requireNoSentinel(t, "the unreachable error", err.Error())
	requireNoSentinelInAnyVerb(t, "the unreachable error value", err)

	planted(t, 2)
}

// ---------------------------------------------------------------- detector 3

// credentialFieldNames must not exist on anything this CLI renders or
// records, matched as a substring so Token, AccessToken and tokenValue all trip.
var credentialFieldNames = []string{
	"token", "secret", "password", "passphrase", "credential",
	"authorization", "bearer", "apikey", "api_key",
	"devicecode", "device_code", "usercode", "user_code",
}

// TestNoResultTypeCanCarryACredential is the half that cannot rot: the set
// of Result implementations is read out of internal/output's source, so a
// sixth type fails this test until it is listed here and walked.
func TestNoResultTypeCanCarryACredential(t *testing.T) {
	results := []output.Result{
		output.LoginResult{},
		output.LogoutResult{},
		output.SyncResult{},
		output.StatusResult{},
		output.VersionResult{},
	}

	declared := resultTypesDeclaredInSource(t)
	var walked []string
	for _, r := range results {
		walked = append(walked, reflect.TypeOf(r).Name())
	}
	sort.Strings(declared)
	sort.Strings(walked)
	require.Equal(t, declared, walked,
		"internal/output declares a Result this test does not walk; add it above")

	for _, r := range results {
		typ := reflect.TypeOf(r)
		t.Run(typ.Name(), func(t *testing.T) {
			forbidCredentialFields(t, typ, typ.Name(), map[reflect.Type]bool{})
		})
	}

	t.Run("the installation record", func(t *testing.T) {
		forbidCredentialFields(t, reflect.TypeOf(record.Record{}), "record.Record", map[reflect.Type]bool{})
	})
}

// TestLoginResultRendersExactlyTheFieldsItIsAllowed pins the JSON document
// by its key set. The reflection walk above would catch a field called
// Token; this catches a field called Blob whose contents happen to be one.
func TestLoginResultRendersExactlyTheFieldsItIsAllowed(t *testing.T) {
	expiry := time.Unix(1_700_003_600, 0).UTC()
	res := output.LoginResult{
		Hub:      "https://hub.leakscan.example",
		Identity: "someone@example.com",
		Store:    "file (/home/someone/.agent-manager/credentials)",
		Expires:  &expiry,
	}

	var buf bytes.Buffer
	require.NoError(t, output.JSONRenderer{}.Render(&buf, res))

	var doc struct {
		Kind   string         `json:"kind"`
		Result map[string]any `json:"result"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	require.Equal(t, "login", doc.Kind)

	keys := make([]string, 0, len(doc.Result))
	for k := range doc.Result {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	require.Equal(t, []string{"expires", "hub", "identity", "store"}, keys,
		"the login result document gained a field; FR-007 forbids one holding a credential")

	var human bytes.Buffer
	require.NoError(t, output.HumanRenderer{}.Render(&human, res))
	require.Empty(t, scan(human.String()), "the human rendering of a login looks like it carries a credential")
	require.Empty(t, scan(buf.String()), "the json rendering of a login looks like it carries a credential")
}

func forbidCredentialFields(t *testing.T, typ reflect.Type, path string, seen map[reflect.Type]bool) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Map {
		forbidCredentialFields(t, typ.Elem(), path+"[]", seen)
		return
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return
	}
	seen[typ] = true

	for i := range typ.NumField() {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		for _, bad := range credentialFieldNames {
			require.NotContains(t, strings.ToLower(f.Name), bad,
				"%s.%s reads as a credential; FR-007 forbids a rendered or recorded type having anywhere to put one", path, f.Name)
			require.NotContains(t, strings.ToLower(tag), bad,
				"%s.%s serialises as %q, which reads as a credential", path, f.Name, tag)
		}
		forbidCredentialFields(t, f.Type, path+"."+f.Name, seen)
	}
}

// resultTypesDeclaredInSource returns the receiver type of every
// `Kind() string` method in internal/output, discovered rather than listed.
func resultTypesDeclaredInSource(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(moduleRoot(t), "internal", "output")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	// One ParseFile per file rather than parser.ParseDir (deprecated, ignores
	// build tags); parsing every file errs toward finding more Result types
	// than a build would compile, the safe direction here.
	fset := token.NewFileSet()
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "Kind" || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			if name := receiverTypeName(fn.Recv.List[0].Type); name != "" {
				names = append(names, name)
			}
		}
	}
	require.NotEmpty(t, names, "found no Result implementations in %s, so this gate is reading the wrong directory", dir)
	return names
}

func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(e.X)
	case *ast.Ident:
		return e.Name
	default:
		return ""
	}
}

// ---------------------------------------------------------------- helpers

// requireNoSentinel reports the sentinel by name and never reprints its
// value, so a failure here does not itself leak into the scanned output.
func requireNoSentinel(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range sentinels() {
		require.NotContains(t, text, s.value,
			"%s contains the test %s (FR-007); rendered length %d", what, s.name, len(text))
	}
}

// device.Flow previously leaked its user code under %#v via a plain string
// field, since %#v does not consult String. internal/device now holds that
// field in a closure like the other two; keep it that way.

// requireNoSentinelInJSON is a separate defence from the fmt one: a type
// whose String method redacts is still marshalled field by field. A type
// that cannot be marshalled fails here too, deliberately, since that would
// make the assertion vacuous.
func requireNoSentinelInJSON(t *testing.T, what string, v any) {
	t.Helper()
	blob, err := json.Marshal(v)
	require.NoError(t, err, "%s could not be marshalled, so this assertion proves nothing", what)
	requireNoSentinel(t, what+" marshalled as JSON", string(blob))
}

// requireNoSentinelInAnyVerb checks the five fmt verbs a careless debug
// print reaches for; %#v and %+v matter most, since neither is served by a
// String method on an unexported field.
func requireNoSentinelInAnyVerb(t *testing.T, what string, v any) {
	t.Helper()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		requireNoSentinel(t, what+" formatted with "+verb, fmt.Sprintf(verb, v))
	}
}

// planted logs the marker the run-wide scan requires; n is only ever
// printed, so a reader can see how much was exercised.
func planted(t *testing.T, n int) {
	t.Helper()
	t.Logf("%s %d credential-bearing renderings", plantMarker, n)
}

// childBudget is how long the child suite may run, comfortably inside
// whatever deadline the parent was given via -test.timeout. An absent
// deadline gets a generous fixed budget rather than an unbounded one, since
// an unbounded child in CI hangs until the runner kills it with no output.
func childBudget(t *testing.T) time.Duration {
	t.Helper()
	const (
		fallback = 8 * time.Minute
		margin   = 2 * time.Minute
	)
	f := flag.Lookup("test.timeout")
	if f == nil {
		return fallback
	}
	parent, err := time.ParseDuration(f.Value.String())
	if err != nil || parent <= 0 {
		return fallback
	}
	if budget := parent - margin; budget > 0 {
		return budget
	}
	// The parent's own deadline is tighter than the margin; use most of it.
	return parent / 2
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "cannot locate this source file")
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "walked past the filesystem root looking for go.mod")
		dir = parent
	}
}

// goTool is the go binary on PATH; runtime.GOROOT is deliberately not used,
// since it is deprecated and meaningless once a binary moves. A missing
// toolchain fails rather than skips, since a leak gate that quietly skips is
// indistinguishable from one that passed.
func goTool(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("go")
	require.NoError(t, err, "no go toolchain on PATH to re-run the suite with")
	return path
}

// stubTransport is a device.Transport that answers every poll the same
// way, since the interesting variation is in the answer, not the sequence.
type stubTransport struct {
	code   device.ErrorCode
	issued *device.Issued
	err    error
}

func (s *stubTransport) Authorize(context.Context, device.AuthorizeRequest) (device.Authorization, error) {
	return device.Authorization{
		DeviceCode:              sentinelDeviceCode,
		UserCode:                sentinelUserCode,
		VerificationURI:         "https://hub.leakscan.example/device",
		VerificationURIComplete: "https://hub.leakscan.example/device?user_code=" + sentinelUserCode,
		ExpiresIn:               30 * time.Second,
		Interval:                5 * time.Second,
	}, nil
}

func (s *stubTransport) Poll(context.Context, device.PollRequest) (*device.Issued, device.ErrorCode, error) {
	return s.issued, s.code, s.err
}

// steppingClock advances by exactly what it is asked to wait, so a flow that
// polls until the window closes terminates in microseconds instead of hanging.
type steppingClock struct{ now time.Time }

func (c *steppingClock) Now() time.Time { return c.now }

func (c *steppingClock) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d > 0 {
		c.now = c.now.Add(d)
	}
	return nil
}
