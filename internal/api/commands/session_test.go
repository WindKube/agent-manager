package commands_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/api/commands"
	"agent-manager/internal/auth"
)

// T032 — the two properties of the session mint that are load-bearing and easy to
// lose (contracts/auth.md, plan.md's Complexity Tracking row).
//
// The first is that an unset shared secret refuses the mint. Nothing else in the
// system enforces it: config.API deliberately does NOT mark the variable
// `required,notEmpty`, because doing so would take the reads, the health endpoint
// and the device flow down along with sign-in — so if the refusal is not written
// at the mint site, the spec's contract silently does not exist.
//
// The second is that the secret never reaches a log line, an error message or an
// audit row. That one is asserted rather than eyeballed: the logger's output is
// captured and searched. The audit row's half of it is in
// internal/api/session_integration_test.go, where a real database makes the
// strongest version of the assertion available — that the secret appears in NO
// statement bun sent, which covers the audit row, the identity row and the session
// row together.
//
// This file drives the HTTP surface as well as the command, which is unusual for a
// test beside a command. It is deliberate: "the secret never appears in a log
// line" is a property of the pair, and asserting it against the command alone
// would pass while the handler logged the header.

// verifier stands in for auth.Verifier. Nothing here reaches a provider: every
// case below is refused before the token would be verified, which is itself part
// of the property — an unconfigured mint must not even try.
type verifier struct {
	claims auth.Claims
	err    error
}

func (v verifier) Verify(context.Context, string) (auth.Claims, error) { return v.claims, v.err }

// theSecret is what an operator configured. thePresentedSecret is what a caller
// sent. Both are distinctive strings so that a leak of either is unambiguous in a
// log line rather than a substring coincidence.
const (
	theSecret          = "s3cret-configured-in-two-environment-blocks"
	thePresentedSecret = "s3cret-a-caller-guessed-at"
)

func TestTheSessionMintIsRefusedWhenTheSharedSecretIsUnset(t *testing.T) {
	for _, tc := range []struct {
		name      string
		presented string
	}{
		{name: "presenting nothing", presented: ""},
		{name: "presenting a guess", presented: thePresentedSecret},
		// The case a "allow when empty" bypass would let through, and the reason
		// there is no such bypass: with no secret configured, matching the
		// configured value means matching nothing.
		{name: "presenting the empty value the hub itself holds", presented: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mint := commands.SessionMint{Verifier: verifier{claims: auth.Claims{Subject: "sub-1"}}}

			// A nil database, and that is the assertion: reaching one would panic.
			// An unconfigured mint must refuse before it touches the store, before
			// it reaches the provider, and before it writes anything at all.
			_, err := mint.Mint(t.Context(), nil, commands.MintInput{
				Secret:  tc.presented,
				IDToken: "an.id.token",
				Source:  auth.SourceWeb,
			})
			require.ErrorIs(t, err, commands.ErrMintNotConfigured)
			require.NotErrorIs(t, err, commands.ErrMintUnauthorized,
				"an unset secret is a misconfigured hub, not a caller who guessed wrong")
		})
	}
}

func TestTheSessionMintIsRefusedWhenThePresentedSecretIsNotTheConfiguredOne(t *testing.T) {
	mint := commands.SessionMint{
		Secret:   theSecret,
		Verifier: verifier{claims: auth.Claims{Subject: "sub-1"}},
	}

	for _, tc := range []struct {
		name      string
		presented string
	}{
		{name: "a wrong secret", presented: thePresentedSecret},
		{name: "no secret at all", presented: ""},
		// A length-prefix match. It is here because the comparison hashes both
		// sides before comparing them: comparing the raw strings would return on
		// the length mismatch, which leaks the configured secret's length one probe
		// at a time.
		{name: "a prefix of the right secret", presented: theSecret[:10]},
		{name: "the right secret with one byte more", presented: theSecret + "!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mint.Mint(t.Context(), nil, commands.MintInput{
				Secret:  tc.presented,
				IDToken: "an.id.token",
				Source:  auth.SourceWeb,
			})
			require.ErrorIs(t, err, commands.ErrMintUnauthorized)
		})
	}
}

func TestNoRefusalFromTheSessionMintRepeatsEitherSecretInItsMessage(t *testing.T) {
	for _, tc := range []struct {
		name string
		mint commands.SessionMint
	}{
		{name: "with no secret configured", mint: commands.SessionMint{}},
		{name: "with a secret configured", mint: commands.SessionMint{Secret: theSecret}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.mint.Mint(t.Context(), nil, commands.MintInput{
				Secret:  thePresentedSecret,
				IDToken: "an.id.token",
			})
			require.Error(t, err)
			require.NotContains(t, err.Error(), theSecret)
			// The PRESENTED value too. It is attacker-chosen, so an error that
			// echoed it would put an arbitrary string into whatever reads the error
			// next — and a caller who mistyped a secret into the wrong variable would
			// have it copied into a report.
			require.NotContains(t, err.Error(), thePresentedSecret)
		})
	}
}

func TestTheSharedSecretNeverReachesALogLineOrTheResponse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured string
		presented  string
		wantStatus int
	}{
		{
			name:       "when no secret is configured the mint is refused as unavailable",
			configured: "",
			presented:  thePresentedSecret,
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "when the presented secret is wrong the mint is refused as unauthorised",
			configured: theSecret,
			presented:  thePresentedSecret,
			wantStatus: http.StatusUnauthorized,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log bytes.Buffer
			server := api.New(api.Deps{
				SessionMintSecret: tc.configured,
				IDTokens:          verifier{claims: auth.Claims{Subject: "sub-1"}},
				// Trace, so nothing is dropped by level: a secret that only shows up
				// in a debug line is still in a log file somewhere.
				Log: zerolog.New(&log).Level(zerolog.TraceLevel),
			}, api.Options{})

			req := httptest.NewRequest(http.MethodPost, "/v1/sessions",
				strings.NewReader(`{"idToken":"an.id.token"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Session-Mint-Secret", tc.presented)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)

			require.Equal(t, tc.wantStatus, rec.Code)

			// The whole captured log, not one field of it. zerolog writes JSON, so a
			// secret that leaked as an error string, a field value or part of a
			// message is caught by the same search.
			require.NotEmpty(t, log.String(), "the request logged nothing at all, so this asserts nothing")
			require.NotContains(t, log.String(), theSecret)
			require.NotContains(t, log.String(), thePresentedSecret)

			require.NotContains(t, rec.Body.String(), theSecret)
			require.NotContains(t, rec.Body.String(), thePresentedSecret)
			for name, values := range rec.Header() {
				for _, value := range values {
					require.NotContainsf(t, value, theSecret, "the %s response header", name)
					require.NotContainsf(t, value, thePresentedSecret, "the %s response header", name)
				}
			}
		})
	}
}
