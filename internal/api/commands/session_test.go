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

// An unset mint secret must refuse here because config.API deliberately doesn't
// require it, and the secret must never reach a log line or error. The HTTP
// surface is driven too, since "never logged" is a property of handler and
// command together.

type verifier struct {
	claims auth.Claims
	err    error
}

func (v verifier) Verify(context.Context, string) (auth.Claims, error) { return v.claims, v.err }

// Distinctive strings so a leak of either is unambiguous in a log line.
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
		// What an "allow when empty" bypass would let through.
		{name: "presenting the empty value the hub itself holds", presented: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mint := commands.SessionMint{Verifier: verifier{claims: auth.Claims{Subject: "sub-1"}}}

			// A nil database: an unconfigured mint must refuse before touching it.
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
		// Length mismatches must not short-circuit and leak the secret's length.
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
			// The presented value is attacker-chosen and must not be echoed either.
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
				// Trace, so a secret in a debug line is caught too.
				Log: zerolog.New(&log).Level(zerolog.TraceLevel),
			}, api.Options{})

			req := httptest.NewRequest(http.MethodPost, "/v1/sessions",
				strings.NewReader(`{"idToken":"an.id.token"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Session-Mint-Secret", tc.presented)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)

			require.Equal(t, tc.wantStatus, rec.Code)

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
