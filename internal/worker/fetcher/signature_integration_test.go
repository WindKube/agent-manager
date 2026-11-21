//go:build integration

package fetcher_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/fetch"
	"agent-manager/internal/signing/signingtest"
	"agent-manager/internal/store/models"
)

func storedSignature(t *testing.T, versionID string) models.Signature {
	t.Helper()
	var sig models.Signature
	require.NoError(t, db.NewSelect().Model(&sig).Where("version_id = ?", versionID).Scan(context.Background()))
	return sig
}

func TestASignedGitReleaseIsVerifiedAndItsSignerRecorded(t *testing.T) {
	ctx := context.Background()
	var h harness
	base, _ := forgeWith(t, fixtureTree(), func(string) string { return forgeCommit },
		func(tarball []byte) map[string][]byte {
			return map[string][]byte{"plugin-1.3.0.tar.gz.sigstore.json": h.sigstore.Sign(t, tarball)}
		})
	h = newHarness(t, []string{loopbackOf(t, base)})

	versionID, job := register(t, commands.Registration{
		Source: fetch.SourceGit, URL: base + "/org/plugin", Ref: "v1.3.0",
		Publisher: "signed/team", Name: "platform-toolkit",
	})
	require.NoError(t, h.worker.Fetch(ctx, job))

	sig := storedSignature(t, versionID)
	require.Equal(t, models.SignatureKindCosignBundle, sig.Kind)
	require.NotNil(t, sig.Result)
	require.Equal(t, models.SignatureResultVerified, *sig.Result, sig.Reason)
	require.Equal(t, signingtest.Issuer, sig.SignerIssuer)
	require.Equal(t, signingtest.Identity, sig.SignerIdentity)
	require.Contains(t, sig.Ref, "plugin-1.3.0.tar.gz.sigstore.json")
	require.NotEmpty(t, sig.Bundle)
	require.Len(t, sig.ArtifactDigest, 32)
	require.NotNil(t, sig.VerifiedAt)

	texts := auditTexts(t, "fetcher", "stored signed/platform-toolkit@1.3.0%")
	require.Len(t, texts, 1)
	require.Contains(t, texts[0], "signature verified: "+signingtest.Identity)
}

func TestAReleaseBundleOverOtherBytesIsStoredInvalidNotRefused(t *testing.T) {
	ctx := context.Background()
	var h harness
	base, _ := forgeWith(t, fixtureTree(), func(string) string { return forgeCommit },
		func([]byte) map[string][]byte {
			return map[string][]byte{"plugin-1.3.0.tar.gz.sigstore.json": h.sigstore.Sign(t, []byte("a release tarball we never store"))}
		})
	h = newHarness(t, []string{loopbackOf(t, base)})

	versionID, job := register(t, commands.Registration{
		Source: fetch.SourceGit, URL: base + "/org/plugin", Ref: "v1.3.0",
		Publisher: "mismatched/team", Name: "platform-toolkit",
	})
	require.NoError(t, h.worker.Fetch(ctx, job))
	require.True(t, readVersion(t, versionID).Visible, "an invalid signature is a recorded verdict, not a failed fetch")

	sig := storedSignature(t, versionID)
	require.Equal(t, models.SignatureResultInvalid, *sig.Result)
	require.NotEmpty(t, sig.Reason)
	require.Empty(t, sig.SignerIdentity)

	texts := auditTexts(t, "fetcher", "stored mismatched/platform-toolkit@1.3.0%")
	require.Len(t, texts, 1)
	require.Contains(t, texts[0], "signature invalid")
}

func TestAnArchiveURLWithASiblingBundleIsVerified(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for path, body := range fixtureTree() {
		f, err := zw.Create(path)
		require.NoError(t, err)
		_, err = f.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	archive := buf.Bytes()

	var h harness
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dist/platform-toolkit-1.3.0.zip", "/dist/unsigned/platform-toolkit-1.3.0.zip":
			_, _ = w.Write(archive)
		case "/dist/platform-toolkit-1.3.0.zip.sigstore.json":
			_, _ = w.Write(h.sigstore.Sign(t, archive))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	h = newHarness(t, []string{loopbackOf(t, server.URL)})

	versionID, job := register(t, commands.Registration{
		Source: fetch.SourceArchiveURL, URL: server.URL + "/dist/platform-toolkit-1.3.0.zip",
		Publisher: "archived/team", Name: "platform-toolkit", Version: "1.3.0",
	})
	require.NoError(t, h.worker.Fetch(ctx, job))
	sig := storedSignature(t, versionID)
	require.Equal(t, models.SignatureResultVerified, *sig.Result, sig.Reason)
	sum := sha256.Sum256(archive)
	require.Equal(t, sum[:], sig.ArtifactDigest)

	versionID, job = register(t, commands.Registration{
		Source: fetch.SourceArchiveURL, URL: server.URL + "/dist/unsigned/platform-toolkit-1.3.0.zip",
		Publisher: "unsigned/team", Name: "platform-toolkit", Version: "1.3.0",
	})
	require.NoError(t, h.worker.Fetch(ctx, job))
	sig = storedSignature(t, versionID)
	require.Equal(t, models.SignatureKindNone, sig.Kind)
	require.Nil(t, sig.Result)
}

func TestAnUploadCarriesItsBundleThroughTheOutbox(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	archive := forgeTarball(t, "platform-toolkit-1.3.0", fixtureTree())

	versionID, job := register(t, commands.Registration{
		Source: fetch.SourceUpload, Publisher: "uploadsigned/team", Name: "platform-toolkit", Version: "1.3.0",
		Kind: models.PackageKindPlugin, ArchiveName: "platform-toolkit-1.3.0.tar.gz", Archive: archive,
		SigstoreBundle: h.sigstore.Sign(t, archive),
	})
	require.NotEmpty(t, job.Source.SigstoreBundle)
	require.NoError(t, h.worker.Fetch(ctx, job))

	sig := storedSignature(t, versionID)
	require.Equal(t, models.SignatureResultVerified, *sig.Result, sig.Reason)
	require.Equal(t, "uploaded with the archive", sig.Ref)
}
