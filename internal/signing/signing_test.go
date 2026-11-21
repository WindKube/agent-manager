package signing_test

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/signing"
	"agent-manager/internal/signing/signingtest"
)

func TestVerify(t *testing.T) {
	ctx := context.Background()
	sigstore := signingtest.New(t)
	verifier := sigstore.Verifier()
	artefact := []byte("the archive bytes")
	signed := sigstore.Sign(t, artefact)

	t.Run("a bundle over the artefact verifies and names its signer", func(t *testing.T) {
		got, err := verifier.Verify(ctx, signed, sha256.Sum256(artefact))
		require.NoError(t, err)
		require.Equal(t, signing.StatusVerified, got.Status, got.Reason)
		assert.Equal(t, signingtest.Issuer, got.Issuer)
		assert.Equal(t, signingtest.Identity, got.Identity)
		assert.NotNil(t, got.SignedAt)
		assert.NotNil(t, got.LogIndex)
		assert.Empty(t, got.Reason)
	})

	t.Run("a tampered artefact is invalid", func(t *testing.T) {
		got, err := verifier.Verify(ctx, signed, sha256.Sum256([]byte("the archive bytes, edited")))
		require.NoError(t, err)
		assert.Equal(t, signing.StatusInvalid, got.Status)
		assert.NotEmpty(t, got.Reason)
		assert.Empty(t, got.Identity)
	})

	t.Run("a bundle over another artefact is invalid", func(t *testing.T) {
		other := sigstore.Sign(t, []byte("some other release"))
		got, err := verifier.Verify(ctx, other, sha256.Sum256(artefact))
		require.NoError(t, err)
		assert.Equal(t, signing.StatusInvalid, got.Status)
	})

	t.Run("a bundle from an untrusted sigstore is invalid", func(t *testing.T) {
		foreign := signingtest.New(t).Sign(t, artefact)
		got, err := verifier.Verify(ctx, foreign, sha256.Sum256(artefact))
		require.NoError(t, err)
		assert.Equal(t, signing.StatusInvalid, got.Status)
	})

	t.Run("garbage is invalid, not an error", func(t *testing.T) {
		got, err := verifier.Verify(ctx, []byte(`{"mediaType":"nonsense"}`), sha256.Sum256(artefact))
		require.NoError(t, err)
		assert.Equal(t, signing.StatusInvalid, got.Status)
		assert.Contains(t, got.Reason, "not a sigstore bundle")
	})

	t.Run("no bundle is unsigned", func(t *testing.T) {
		got, err := verifier.Verify(ctx, nil, sha256.Sum256(artefact))
		require.NoError(t, err)
		assert.Equal(t, signing.StatusUnsigned, got.Status)
	})
}

func TestNewRefusesAnUnreadableTrustedRoot(t *testing.T) {
	_, err := signing.New(signing.Options{TrustedRootPath: filepath.Join(t.TempDir(), "missing.json")})
	require.Error(t, err)

	bad := filepath.Join(t.TempDir(), "trusted_root.json")
	require.NoError(t, os.WriteFile(bad, []byte("{}"), 0o600))
	_, err = signing.New(signing.Options{TrustedRootPath: bad})
	require.Error(t, err)
}

func TestNewNeedsAFetcherWithoutATrustedRoot(t *testing.T) {
	_, err := signing.New(signing.Options{})
	require.Error(t, err)
}
