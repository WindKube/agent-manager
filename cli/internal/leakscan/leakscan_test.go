// Package leakscan holds the SC-010 gate: nothing in this CLI may write a
// token, a device code or a user code anywhere (FR-007), and this package is
// where that is proven rather than asserted.
//
// It is a directory of its own, with no non-test file in it, for two reasons.
// The gate re-runs the WHOLE module's test suite in a child process and scans
// everything it printed, so it belongs to no single package and would look like
// a unit test of whichever one it was filed under. And every other package here
// is owned by the code it tests, whose authors must be free to edit their own
// files without merging with this one.
//
// # WHAT FR-007 MEANS FOR EACH OF THE THREE SECRETS
//
// The access token and the device code are unconditional. Neither is ever shown
// to a human, neither is ever an input a user types, and there is no stream on
// which printing one is useful. Any occurrence anywhere is a defect.
//
// The user code is NOT unconditional, and treating it as though it were would
// be wrong in the other direction. RFC 8628 §3.3 requires the client to display
// it: the flow cannot work unless a human reads it off this terminal and types
// it into the hub. FR-007's words are "any log, report or error", and those are
// exactly the three places it must not go, for a reason that outlives the code:
//
//   - a LOG or a transcript is retained, is copied into bug reports and is read
//     by people who were never at the terminal, while the code is live for the
//     ten minutes of the authorisation window;
//   - a REPORT — the --output json document, the installation record — is a
//     machine-readable artefact that gets committed, shipped to inventory and
//     diffed;
//   - an ERROR is quoted verbatim into all of the above, and by the time it is
//     read the code it names is worthless anyway, so it can only leak.
//
// So the rule this package enforces for the user code is: it may be WRITTEN
// ONCE, live, to the interactive diagnostic stream, by the verb whose job is to
// show it; it may not reach a result document, the installation record, a
// verbose log line, or any error value. The consequence for the run-wide scan
// below is stated where the sentinel is defined: the sentinel user code is
// banned outright, and a test that wants to assert the live display must use
// the fake hub's own randomly generated code — which it needs anyway, to
// approve the authorisation.
//
// # THE THREE DETECTORS, AND WHAT EACH ONE DOES NOT COVER
//
// 1. TestNoSecretReachesAnyOutputOfTheWholeSuite re-runs `go test -v ./...` in
// a child process and scans its combined stdout and stderr. This is the only
// mechanism here that sees "all captured output" in any real sense: it sees
// every package's output including tests written after this file, output that
// bypassed testing.T entirely (a stray fmt.Print, log.Print, a panic, a
// goroutine's stack), and it needs no cooperation from any other file, which is
// what makes it survive contact with a suite several people are still writing.
//
// It does NOT see values it cannot name. The fake hub mints opaque
// base64url-of-32-random-bytes tokens, so a leak of ONE OF THOSE is invisible
// to an exact scan, and a shape-based scan for 43-character base64url runs was
// measured against the real suite output and rejected: `go test -v` prints test
// names, `TestR3InterruptionAtEveryStepLeavesOldOrNew` is a 43-character
// base64url run with mixed case and a digit in it, and 840 lines of the current
// output match. A gate that fires on a colleague's test name gets deleted, and
// then nothing is checked at all. What covers the random values instead is the
// credential-assignment pattern (leakPatterns), which looks for the SHAPE OF A
// LEAK — `access_token=`, `Authorization: Bearer x`, `device_code: y` — rather
// than the shape of a value, and which currently matches zero lines of the
// suite's 163KB of output.
//
// It also does not see what no test exercised. A code path with no test cannot
// leak into output that was never produced; that gap is closed by coverage,
// not by this file.
//
// 2. The planting tests — TestTheDeviceFlowNeverRendersTheCodesItHolds,
// TestAnIssuedTokenNeverRendersItself, TestACredentialNeverRendersItsToken,
// TestTheHubClientNeverRendersItsBearerToken — drive the real credential-
// carrying code with sentinel values through every fmt verb and every error
// branch reachable without a network. They are what puts the sentinels into the
// child run at all, so they are also the anti-vacuity mechanism: each logs
// plantMarker, and the run-wide scan fails if that marker is absent, because a
// scan of a buffer nothing was written to passes forever.
//
// They do NOT cover packages that do not exist yet (internal/cmd's login and
// logout are T030/T031) and they do not cover the ten seconds of an operator's
// real terminal.
//
// 3. TestNoResultTypeCanCarryACredential is structural: the set of
// output.Result implementations is read out of the source, every field of every
// one is walked recursively, and a field whose name or JSON tag reads as a
// credential fails. Plus LoginResult's rendered JSON key set is compared to a
// hand-derived list. This half cannot rot — it fails the moment someone adds
// the field — and it is exhaustive over the renderers.
//
// It is blind to everything that is not a Result: log lines, error strings,
// the installation record's non-Result parts, os.Stdout used directly.
//
// # THE UNION IS NOT A PROOF
//
// Together these say: no NAMED secret reached any output of this suite, no
// output line has the shape of a credential assignment, and no result type has
// anywhere to put a credential. They do not say "no token can ever be
// printed". A leak of a randomly generated token, on a path no test runs, in a
// format that does not look like an assignment, would pass all three. That is
// stated here rather than in a commit message because the failure mode of a
// security gate is someone reading its name and stopping looking.
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

// The known test secrets of SC-010.
//
// They are long, unmistakable and unlike anything else the suite prints, so a
// match is a leak and never a coincidence — the opposite trade to a shape-based
// pattern, which cannot tell a token from an identifier.
//
// sentinelUserCode is a legal user code under the contract's
// ^[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}$ so that nothing rejects it as
// malformed on the way through. It is banned from the suite's output OUTRIGHT,
// which is deliberately stricter than FR-007: the one legitimate write of a
// user code is the live display, and a test asserting that must drive the fake
// hub, whose codes are random and which it must read back to approve the
// authorisation anyway. If a display test ever does need this constant, the
// exemption belongs here, consciously, with the stream it is allowed on named —
// not as a quiet edit to the pattern list.
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

// credentialAssignment matches the SHAPE of a leak rather than the value of
// one: a credential-ish key immediately followed by a value.
//
// This is what covers the fake hub's randomly generated tokens, which an exact
// scan cannot name. The keyword list is bounded by \b on both sides, so
// `token_type` and `authorization_header` do not match — the underscore is a
// word character, so there is no boundary after the keyword. AMCTL_TOKEN is
// listed whole for that same reason: the bare `token` alternative can never
// match inside it, and an env dump is a realistic way for a token to reach a
// log. Measured against
// the whole suite's current output: zero matches, which is why it can be a hard
// gate rather than a warning.
var credentialAssignment = regexp.MustCompile(
	`(?i)\b(amctl[_-]?token|access[_-]?token|refresh[_-]?token|device[_-]?code|user[_-]?code|token|bearer|authorization|passphrase|password|api[_-]?key)\b["']?\s*[:=]+\s*("?[^\s",}&]+)`)

// redactedValue is the only exemption to credentialAssignment: a key with a
// visibly redacted value is the thing FR-007 asks for, not a violation of it.
// Nothing here exempts a key whose value is an actual string.
var redactedValue = regexp.MustCompile(`(?i)^"?(redacted|\*+|<[^>]*>|-+|nil|null|none|unset|empty|""|''|\[?redacted\]?)"?$`)

type finding struct {
	line int
	what string
	// excerpt is the offending line with every sentinel replaced by its NAME.
	// A gate that reprints the secret it caught has leaked it into the very
	// output the next run scans, which would make one failure permanent.
	excerpt string
}

func (f finding) String() string { return fmt.Sprintf("line %d: %s: %s", f.line, f.what, f.excerpt) }

// scan is the whole detector, as a pure function over text so that it can have
// a negative control (TestScanCatchesTheLeaksItIsGivenOnPurpose) instead of
// being trusted.
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

// TestNoSecretReachesAnyOutputOfTheWholeSuite is SC-010.
//
// It re-runs the module's suite in a child process and scans everything it
// printed. -v is required, not cosmetic: without it a passing test's t.Log
// output is discarded and the scan would read only failures.
//
// The child's exit status is deliberately NOT asserted. A broken sibling test
// is that sibling's failure, reported by the parent's own run of it; failing
// here as well would turn every unrelated red build into a spurious "SC-010
// violated". What IS asserted is that the child produced a suite's worth of
// output, so a compile failure cannot pass this gate by producing nothing to
// scan.
func TestNoSecretReachesAnyOutputOfTheWholeSuite(t *testing.T) {
	if os.Getenv(childEnvVar) != "" {
		t.Skip("child run: the suite is being scanned by the parent")
	}
	root := moduleRoot(t)

	// The child's deadline must be shorter than THIS test's, and it is derived
	// rather than guessed: -test.timeout is what the parent was given, and a
	// child allowed to outlive its parent means the parent panics with
	// "test timed out" and the scan reports nothing at all. The first version
	// gave the child 15m under a parent default of 10m and the macOS leg died
	// exactly that way — a red build whose message said nothing about SC-010.
	budget := childBudget(t)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	cmd := exec.CommandContext(ctx, goTool(t), "test", "-count=1", "-v",
		"-timeout="+budget.String(), "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), childEnvVar+"=1")
	out, err := cmd.CombinedOutput()
	captured := string(out)
	if err != nil {
		// Not a failure of this gate; see the doc comment. Recorded so a reader
		// of a red build knows the scan still ran.
		t.Logf("the child suite exited non-zero (%v); scanning its output anyway", err)
	}
	// A child killed by the deadline is different in kind: it did not finish the
	// suite, so a clean scan of its output proves nothing about the part that
	// never ran. Say so rather than passing.
	if ctx.Err() != nil {
		t.Fatalf("the child suite did not finish within %s, so this scan covered only part of it "+
			"— raise the -timeout the CI job gives this package rather than trusting a partial pass "+
			"(captured %d bytes)", budget, len(captured))
	}

	// Anti-vacuity. Each of these has to hold before a clean scan means
	// anything at all: a scan of a buffer nothing was written to passes for
	// ever, and a compile failure in the child is exactly how that happens.
	//
	// None of them uses require's own Contains/Greater helpers, deliberately:
	// those print the HAYSTACK on failure, which here is the whole suite's
	// output — 160KB into the message, and every secret it might contain
	// re-emitted into the output that the NEXT run scans, which would make one
	// failure permanent. The excerpt below is a redacted tail and nothing more.
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

// TestScanCatchesTheLeaksItIsGivenOnPurpose is the permanent negative control.
//
// A one-off experiment — log the token, watch the gate go red, delete the line
// — proves the gate works today and nothing at all tomorrow. This keeps that
// experiment in the suite: each case is output the scan MUST reject, and the
// clean cases are the false positives it must not invent, taken from strings
// the real suite prints.
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
		// Real lines from the suite. A gate that fires on these is a gate
		// somebody deletes.
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

// TestTheDeviceFlowNeverRendersTheCodesItHolds drives device.Flow through every
// answer the token endpoint can give, with the sentinel codes in it, and checks
// the error and every fmt verb.
//
// %#v is checked as well as %v and %+v because it does NOT consult String, and
// it is what a hurried debug print reaches for. device.Flow answers it by
// holding the codes in closures, which print as addresses; this is the test
// that the answer works.
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
			// A transport error is wrapped VERBATIM, which is correct — FR-040's
			// diagnosis has to survive — and which puts the burden somewhere
			// this test cannot reach: whatever produces the error must not have
			// put the device code in it. internal/hub sends the device code in
			// the form body and redacts URLs out of transport errors
			// (redactURLError, safeURL), so the production transport cannot;
			// a future transport that logged its request into an error would
			// leak, and no assertion in this package would notice. Stated,
			// because it is the one hole in this test worth knowing about.
			name:    "a transport failure",
			pollErr: errTransportPassedThrough,
			wantErr: errTransportPassedThrough,
		},
		{
			name:   "success with no lifetime",
			issued: &device.Issued{AccessToken: sentinelAccessToken, TokenType: "Bearer"},
			// issue() refuses expires_in <= 0 rather than inventing a lifetime,
			// and its message must not quote the token it refused.
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

			// The two accessors that are ALLOWED to return the user code: this
			// is the live display FR-007 exempts, and it is a return value, not
			// a write. Asserted rather than assumed, because a Flow that had
			// stopped returning the code would make every other assertion here
			// pass vacuously.
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

// errTransportPassedThrough is the transport error the stub returns, asserted
// with errors.Is so the case proves the pass-through it is named for rather
// than passing on any error at all.
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

	// The accessors are the sanctioned way out, and they must still work: a
	// Token that had stopped returning the token would pass every leak
	// assertion below and break login.
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

// TestACredentialNeverRendersItsToken covers credentials.Credential's fmt verbs,
// the FR-003 fallback warning, and the error a corrupt store produces — which
// is the one that has the token's own bytes in scope while it is being written.
func TestACredentialNeverRendersItsToken(t *testing.T) {
	const hubURL = "https://hub.leakscan.example"

	var warnings bytes.Buffer
	store, err := credentials.Open(credentials.Options{
		StateRoot: t.TempDir(),
		Warnf:     func(f string, a ...any) { fmt.Fprintf(&warnings, f+"\n", a...) },
		// The file backend explicitly: it is the only one that touches the
		// filesystem, so it is the only one whose corrupt-blob path can be
		// exercised on any platform, and forcing it keeps this test off the
		// developer's real keychain.
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

	// json.Marshal is the other serialiser, and it is the one the fmt verbs
	// above say nothing about: it ignores String and GoString entirely. Token
	// was an exported field with no tag, so marshalling a Credential — or
	// anything holding one — emitted {"Hub":…,"Token":"<the bearer token>",…},
	// and internal/output's JSON renderer marshals straight onto the RESULT
	// stream. `json:"-"` is the fix; this is the assertion that would have
	// caught it, and the struct case is the realistic one, because the leak
	// arrives when someone puts a credential inside something else.
	requireNoSentinelInJSON(t, "the credential", cred)
	requireNoSentinelInJSON(t, "the resolved credential", loaded)
	requireNoSentinelInJSON(t, "a struct holding a credential", struct {
		Cred     credentials.Credential
		Resolved credentials.Resolved
	}{cred, credentials.Resolved{Credential: loaded, Source: credentials.SourceStore, Location: store.Location()}})

	t.Run("the error from a store it cannot read", func(t *testing.T) {
		// Overwrite the item keyring just wrote with content that has the token
		// in it in the clear. The item's key is derived from the hub URL by
		// unexported code, so it is discovered by listing rather than
		// recomputed — a wrong guess here would stat nothing and pass.
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

// credentialDir recovers the fallback directory from the store's own rendering
// of it, which is "file (<dir>)". Parsing a human string is ugly; the
// alternative is duplicating the join of StateRoot and DirName, which would
// keep passing if the store moved.
func credentialDir(t *testing.T, s *credentials.Store) string {
	t.Helper()
	loc := s.Location()
	require.True(t, strings.HasPrefix(loc, "file ("), "expected the file backend, got %q", loc)
	return strings.TrimSuffix(strings.TrimPrefix(loc, "file ("), ")")
}

// TestTheHubClientNeverRendersItsBearerToken puts the sentinel token into a
// real hub.Hub and makes it fail two ways, because an error that dumped the
// request would leak the Authorization header it just set.
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

// credentialFieldNames are field names and JSON tags that must not exist on
// anything this CLI renders or records. Matched as a substring of the
// lower-cased name, so Token, AccessToken and tokenValue all trip.
var credentialFieldNames = []string{
	"token", "secret", "password", "passphrase", "credential",
	"authorization", "bearer", "apikey", "api_key",
	"devicecode", "device_code", "usercode", "user_code",
}

// TestNoResultTypeCanCarryACredential is the half that cannot rot.
//
// The set of Result implementations is read out of internal/output's source, so
// a sixth result type fails this test until it is listed here and walked. That
// is the point: an exhaustive check whose list is maintained by hand is a check
// that goes stale the first time someone is in a hurry.
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

	// The installation record is a report under FR-007, and it is the one that
	// persists on disk between runs.
	t.Run("the installation record", func(t *testing.T) {
		forbidCredentialFields(t, reflect.TypeOf(record.Record{}), "record.Record", map[reflect.Type]bool{})
	})
}

// TestLoginResultRendersExactlyTheFieldsItIsAllowed pins the JSON document by
// its key set, hand-derived from FR-003's "report the identity and the hub".
// The reflection walk above would catch a field called Token; this catches a
// field called Blob whose contents happen to be one.
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

// resultTypesDeclaredInSource reads internal/output's non-test files and
// returns the receiver type of every `Kind() string` method — i.e. every
// output.Result implementation, discovered rather than listed.
func resultTypesDeclaredInSource(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(moduleRoot(t), "internal", "output")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	// One ParseFile per file rather than parser.ParseDir, which is deprecated
	// for not honouring build tags. Every file in the directory is parsed
	// whatever its tags, which errs towards finding MORE Result types than a
	// build would compile — the safe direction for a gate whose failure means
	// "a result type is not being walked".
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

// requireNoSentinel is the assertion every planting test ends in. It reports
// the sentinel by NAME and never reprints its value, so a failure here does not
// itself put a secret into the output the run-wide scan reads.
func requireNoSentinel(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range sentinels() {
		require.NotContains(t, text, s.value,
			"%s contains the test %s (FR-007); rendered length %d", what, s.name, len(text))
	}
}

// A NOTE ON THE EXEMPTION THAT USED TO LIVE HERE, because the shape of the
// defect is worth keeping and the code is not.
//
// This file carried a requireFlowRendersNoSecret helper that asserted a device
// Flow leaked its user code under %#v, POSITIVELY, so that the exemption could
// not outlive the defect. It did not: verificationURIComplete was a plain string
// field ending in "?user_code=<the user code>", %#v does not consult String, and
// the four other verbs were clean — so device.Flow's own claim that a careless
// fmt.Sprintf "cannot leak the device code or the user code" held for four verbs
// out of five, and the fifth is the one a hurried debug print reaches for.
// internal/device now holds that field in a closure like the other two, the
// positive assertion fired as designed, and the call site above is the ordinary
// all-five-verbs one. Keep it that way: a Flow has no field that may render.

// requireNoSentinelInJSON is the same assertion for encoding/json, which is a
// separate defence and not a duplicate of the fmt one: a type whose String
// method redacts is still marshalled field by field, and this codebase's one
// serialiser of results is json.NewEncoder(w).Encode onto stdout. A type that
// cannot be marshalled at all fails here too, deliberately — an unmarshalable
// credential type would make the assertion vacuous.
func requireNoSentinelInJSON(t *testing.T, what string, v any) {
	t.Helper()
	blob, err := json.Marshal(v)
	require.NoError(t, err, "%s could not be marshalled, so this assertion proves nothing", what)
	requireNoSentinel(t, what+" marshalled as JSON", string(blob))
}

// requireNoSentinelInAnyVerb checks the five fmt verbs a careless debug print
// reaches for. %#v and %+v matter most: neither is served by a String method on
// an unexported field, which is why the credential-bearing types in this
// codebase hold their secrets in closures.
func requireNoSentinelInAnyVerb(t *testing.T, what string, v any) {
	t.Helper()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		requireNoSentinel(t, what+" formatted with "+verb, fmt.Sprintf(verb, v))
	}
}

// planted logs the marker the run-wide scan requires. n is only ever printed,
// never asserted on: it is there so a reader of the child's output can see how
// much was exercised.
func planted(t *testing.T, n int) {
	t.Helper()
	t.Logf("%s %d credential-bearing renderings", plantMarker, n)
}

// childBudget is how long the child suite may run: comfortably inside whatever
// deadline the parent was given, so the parent is never the one that dies.
//
// go test's -timeout reaches the binary as -test.timeout, and flag.Lookup finds
// it whether or not the caller passed it. A zero or absent value means no
// deadline at all, which is the `-timeout 0` case; the child then gets a
// generous fixed budget rather than an unbounded one, because an unbounded
// child in CI is a job that hangs until the runner kills it with no output.
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
	// The parent's own deadline is tighter than the margin. Use most of it and
	// let the check above report a truncated scan rather than silently passing.
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

// goTool is the go binary on PATH. runtime.GOROOT is deliberately NOT used to
// prefer the toolchain that built this test: it is deprecated precisely because
// it is meaningless once a binary moves, and a mismatched toolchain shows up as
// a compile error in the child rather than as a silent pass.
//
// A missing toolchain FAILS rather than skipping. An SC-010 gate that quietly
// skips is indistinguishable from one that passed, which is the failure mode
// this whole file exists to avoid.
func goTool(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("go")
	require.NoError(t, err, "no go toolchain on PATH to re-run the suite with")
	return path
}

// stubTransport is a device.Transport that answers every poll the same way,
// which is all the state machine's branches need: the interesting variation is
// in the answer, not in the sequence.
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
