// Package signingtest signs artefacts with an in-process Sigstore, so tests
// produce real bundles without touching the network.
package signingtest

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	sigtlog "github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"agent-manager/internal/signing"
)

const (
	Issuer   = "https://token.actions.githubusercontent.com"
	Identity = "https://github.com/example/plugin/.github/workflows/release.yaml@refs/tags/v1.0.0"
)

// Sigstore is a throwaway Fulcio, Rekor and TSA.
type Sigstore struct {
	virtual *ca.VirtualSigstore
}

func New(t testing.TB) *Sigstore {
	t.Helper()
	virtual, err := ca.NewVirtualSigstore()
	require.NoError(t, err)
	return &Sigstore{virtual: virtual}
}

// Verifier trusts only this Sigstore. The virtual CA issues no SCTs, so the
// SCT requirement is the one public-good check left out.
func (s *Sigstore) Verifier() *signing.Verifier {
	return signing.NewWithMaterial(s.virtual, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
}

// Sign returns a v0.3 bundle's JSON over artefact, signed as Identity by Issuer.
func (s *Sigstore) Sign(t testing.TB, artefact []byte) []byte {
	return s.SignAs(t, artefact, Identity, Issuer)
}

func (s *Sigstore) SignAs(t testing.TB, artefact []byte, identity, issuer string) []byte {
	t.Helper()
	entity, err := s.virtual.Sign(identity, issuer, artefact)
	require.NoError(t, err)

	content, err := entity.VerificationContent()
	require.NoError(t, err)
	cert, ok := content.(*bundle.Certificate)
	require.True(t, ok)

	signatureContent, err := entity.SignatureContent()
	require.NoError(t, err)
	message, ok := signatureContent.(*bundle.MessageSignature)
	require.True(t, ok)

	entries, err := entity.TlogEntries()
	require.NoError(t, err)
	tlog := make([]*protorekor.TransparencyLogEntry, 0, len(entries))
	for _, entry := range entries {
		tlog = append(tlog, s.complete(t, entry.TransparencyLogEntry()))
	}

	stamps, err := entity.Timestamps()
	require.NoError(t, err)
	signed := make([]*protocommon.RFC3161SignedTimestamp, 0, len(stamps))
	for _, stamp := range stamps {
		signed = append(signed, &protocommon.RFC3161SignedTimestamp{SignedTimestamp: stamp})
	}

	mediaType, err := bundle.MediaTypeString("0.3")
	require.NoError(t, err)
	raw, err := protojson.Marshal(&protobundle.Bundle{
		MediaType: mediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: cert.Certificate().Raw},
			},
			TlogEntries:               tlog,
			TimestampVerificationData: &protobundle.TimestampVerificationData{Rfc3161Timestamps: signed},
		},
		Content: &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: protocommon.HashAlgorithm_SHA2_256,
				Digest:    message.Digest(),
			},
			Signature: message.Signature(),
		}},
	})
	require.NoError(t, err)
	return raw
}

// complete adds what the virtual Rekor leaves off a hashedrekord entry and a
// bundle needs: its kind, its inclusion promise and an inclusion proof.
func (s *Sigstore) complete(t testing.TB, entry *protorekor.TransparencyLogEntry) *protorekor.TransparencyLogEntry {
	t.Helper()
	logID, err := s.virtual.RekorLogID()
	require.NoError(t, err)
	set, err := s.virtual.RekorSignPayload(sigtlog.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(entry.GetCanonicalizedBody()),
		IntegratedTime: entry.GetIntegratedTime(),
		LogIndex:       entry.GetLogIndex(),
		LogID:          logID,
	})
	require.NoError(t, err)
	proof, err := s.virtual.GetInclusionProof(entry.GetCanonicalizedBody())
	require.NoError(t, err)
	hashes := make([][]byte, 0, len(proof.Hashes))
	for _, h := range proof.Hashes {
		decoded, decodeErr := hex.DecodeString(h)
		require.NoError(t, decodeErr)
		hashes = append(hashes, decoded)
	}
	rootHash, err := hex.DecodeString(*proof.RootHash)
	require.NoError(t, err)

	entry.KindVersion = &protorekor.KindVersion{Kind: "hashedrekord", Version: "0.0.1"}
	entry.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
	entry.InclusionProof = &protorekor.InclusionProof{
		LogIndex:   *proof.LogIndex,
		RootHash:   rootHash,
		TreeSize:   *proof.TreeSize,
		Hashes:     hashes,
		Checkpoint: &protorekor.Checkpoint{Envelope: *proof.Checkpoint},
	}
	return entry
}
