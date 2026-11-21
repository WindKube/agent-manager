package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"agent-manager/internal/fetch"
	"agent-manager/internal/metrics"
	"agent-manager/internal/signing"
	"agent-manager/internal/store/models"
)

// verifySignatures keeps the first bundle that verifies, else the first that
// did not. An unverifiable bundle is a recorded verdict, not a failed fetch;
// only an unreachable trust root fails, and is retried.
func (w *Worker) verifySignatures(ctx context.Context, versionID uuid.UUID, tree fetch.Tree) (models.Signature, signing.Result, error) {
	row := models.Signature{VersionID: versionID, Kind: models.SignatureKindNone}
	if len(tree.Signatures) == 0 {
		metrics.SignatureVerifications.WithLabelValues(string(signing.StatusUnsigned)).Inc()
		return row, signing.Result{Status: signing.StatusUnsigned}, nil
	}

	var (
		chosen fetch.SignatureCandidate
		result signing.Result
	)
	for i, candidate := range tree.Signatures {
		got, err := w.verifier.Verify(ctx, candidate.Bundle, tree.ArchiveDigest)
		if err != nil {
			metrics.SignatureVerifications.WithLabelValues("error").Inc()
			return models.Signature{}, signing.Result{}, fmt.Errorf("%w: verify the signature from %s: %w",
				fetch.ErrRemote, candidate.Origin, err)
		}
		if i == 0 || got.Status == signing.StatusVerified {
			chosen, result = candidate, got
		}
		if got.Status == signing.StatusVerified {
			break
		}
	}

	metrics.SignatureVerifications.WithLabelValues(string(result.Status)).Inc()

	now := time.Now().UTC()
	status := models.SignatureResultInvalid
	if result.Status == signing.StatusVerified {
		status = models.SignatureResultVerified
	}
	row.Kind = models.SignatureKindCosignBundle
	row.Ref = chosen.Origin
	row.Result = &status
	row.VerifiedAt = &now
	row.ArtifactDigest = tree.ArchiveDigest[:]
	if json.Valid(chosen.Bundle) && len(chosen.Bundle) <= signing.MaxBundleBytes {
		row.Bundle = json.RawMessage(chosen.Bundle)
	}
	row.SignerIssuer, row.SignerIdentity = result.Issuer, result.Identity
	row.SignedAt, row.LogIndex = result.SignedAt, result.LogIndex
	row.Reason = result.Reason
	return row, result, nil
}
