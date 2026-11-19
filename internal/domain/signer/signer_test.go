package signer_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/domain/signer"
)

const (
	issuer   = "https://token.actions.githubusercontent.com"
	identity = "https://github.com/acme/skills/.github/workflows/release.yaml@refs/tags/v1.2.0"
)

var expected = signer.Expected{Issuer: issuer, Identity: `https://github\.com/acme/skills/\.github/workflows/release\.yaml@refs/tags/v.*`}

func TestEvaluate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		observed signer.Observed
		expected signer.Expected
		want     signer.Status
	}{
		{"no bundle is unsigned", signer.Observed{}, expected, signer.StatusUnsigned},
		{"a bundle that failed is invalid", signer.Observed{Result: "invalid"}, expected, signer.StatusInvalid},
		{"a verified bundle without an expected signer proves nothing", signer.Observed{Result: "verified", Issuer: issuer, Identity: identity}, signer.Expected{}, signer.StatusNoExpectedSigner},
		{"the expected signer matches", signer.Observed{Result: "verified", Issuer: issuer, Identity: identity}, expected, signer.StatusMatching},
		{"another issuer does not", signer.Observed{Result: "verified", Issuer: "https://accounts.google.com", Identity: identity}, expected, signer.StatusUnexpectedSigner},
		{"another identity does not", signer.Observed{Result: "verified", Issuer: issuer, Identity: "https://github.com/evil/skills/.github/workflows/release.yaml@refs/tags/v1"}, expected, signer.StatusUnexpectedSigner},
		{"the pattern is anchored at both ends", signer.Observed{Result: "verified", Issuer: issuer, Identity: "x" + identity}, signer.Expected{Issuer: issuer, Identity: `https://github\.com/acme/.*`}, signer.StatusUnexpectedSigner},
		{"an alternation cannot escape the anchor", signer.Observed{Result: "verified", Issuer: issuer, Identity: "evil@example.com"}, signer.Expected{Issuer: issuer, Identity: `nobody|evil`}, signer.StatusUnexpectedSigner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, signer.Evaluate(tc.observed, tc.expected))
		})
	}
}

func TestNormalise(t *testing.T) {
	got, err := signer.Normalise(signer.Expected{Issuer: " " + issuer + " ", Identity: " release@acme.dev "})
	require.NoError(t, err)
	require.Equal(t, signer.Expected{Issuer: issuer, Identity: "release@acme.dev"}, got)

	got, err = signer.Normalise(signer.Expected{})
	require.NoError(t, err)
	require.False(t, got.Configured())

	for _, bad := range []signer.Expected{
		{Issuer: issuer},
		{Identity: "x"},
		{Issuer: issuer, Identity: "("},
		{Issuer: issuer, Identity: strings.Repeat("a", signer.MaxIdentityLength+1)},
		{Issuer: strings.Repeat("a", signer.MaxIssuerLength+1), Identity: "x"},
	} {
		_, err := signer.Normalise(bad)
		require.ErrorIs(t, err, signer.ErrInvalid, "%+v", bad)
	}
}
