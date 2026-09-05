package fetcher

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"agent-manager/internal/blob"
	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/fetch"
	"agent-manager/internal/outbox"
)

// Result is what one successful fetch produced.
type Result struct {
	Commit blob.Commit

	// AlreadyStored marks a redelivery that did nothing; delivery is
	// at-least-once, so this is the normal outcome of a duplicate, not an error.
	AlreadyStored bool

	// Latest is whether this version took the package's `latest` dist tag.
	Latest bool

	Package *pkgspec.Package
	Origin  string
}

// Fetch runs the whole pipeline for one job.
func (w *Worker) Fetch(ctx context.Context, job Job) error {
	log := w.deps.Log.With().Str("job", "fetch").Str("version", job.String()).Logger()

	if err := job.Validate(); err != nil {
		return classify(job.String(), err)
	}

	// The idempotency guard is answered by the data, not the queue: a version
	// whose digest is on record has committed bytes, so the fetch already
	// happened.
	already, err := outbox.Delivered(ctx, w.deps.DB, outbox.Job{
		Kind: outbox.KindFetch, SubjectID: job.VersionID, SubjectVersion: job.Semver,
	})
	if err != nil {
		return classify(job.String(), err)
	}
	if already {
		log.Info().Msg("fetch redelivered for a version that already has committed bytes; nothing to do")
		return nil
	}

	result, err := w.run(ctx, job)
	if err != nil {
		// The failure is recorded as a fetch error and nothing else: no
		// finding, no verdict change, no bytes. The version stays invisible
		// with verdict `scanning`, the only state the schema allows for a
		// version with no bytes behind it.
		reason := ReasonOf(err)
		log.Error().Err(err).Str("reason", string(reason)).Msg("fetch failed")
		if auditErr := w.auditFailure(ctx, job, reason, err); auditErr != nil {
			log.Error().Err(auditErr).Msg("recording the fetch failure in the audit log failed")
		}
		return err
	}

	if result.AlreadyStored {
		log.Info().Msg("bundle bytes were already committed for this version; nothing to do")
		return nil
	}

	log.Info().
		Str("digest", hex.EncodeToString(result.Commit.Bundle.Digest[:])).
		Str("object_key", result.Commit.Bundle.Key).
		Int64("size_bytes", result.Commit.Bundle.Size).
		Int("components", len(result.Package.Components)).
		Int("dropped", len(result.Package.Layout.Dropped)).
		Msg("version stored")
	return nil
}

// run is the pipeline proper, with every step's failure classified.
func (w *Worker) run(ctx context.Context, job Job) (Result, error) {
	ref := job.SourceRef()
	ref.Limits = w.limits
	if job.Source.Kind == fetch.SourceUpload {
		ref.Archive = bytes.NewReader(job.Source.Archive)
	}

	tree, err := w.sources.Fetch(ctx, ref)
	if err != nil {
		return Result{}, classify(job.String(), err)
	}

	// Filter to the spec layout, validate the manifests, derive the
	// components — all three are internal/domain/pkgspec's, so the
	// pre-submit preview and this pass cannot disagree.
	pkg, err := pkgspec.InspectWith(w.validator, tree.Files, tree.Root)
	if err != nil {
		return Result{}, classify(job.String(), err)
	}

	// A manifest that names its own version must agree with the version being
	// registered, or the digest would be a lie about which release it is.
	if pkg.Semver != "" && pkg.Semver != job.Semver {
		return Result{}, classify(job.String(),
			fmt.Errorf("%w: manifest says %s, registration says %s", errVersionMismatch, pkg.Semver, job.Semver))
	}
	if pkg.Name != job.Name {
		return Result{}, classify(job.String(),
			fmt.Errorf("%w: manifest name is %q, registration is for %q", pkgspec.ErrManifestInvalid, pkg.Name, job.Name))
	}

	// Pack is deterministic — path order, zeroed mtimes, two modes,
	// single-threaded zstd — which makes the digest a function of the tree
	// alone.
	packed, digest, size, err := bundle.Pack(pkg.Files)
	if err != nil {
		return Result{}, classify(job.String(), err)
	}

	// Latest is false here and moved afterwards: which version is latest is a
	// catalog decision made under a row lock inside the publish transaction
	// below, and deciding it here too would give the object store an
	// independent opinion that could disagree.
	commit, err := w.committer.Commit(ctx, job.VersionRef(), blob.VersionParts{
		Bundle:             packed,
		ManifestObjectName: pkg.ManifestObject,
		Manifest:           pkg.ManifestBytes,
	})
	if err != nil {
		return Result{}, classify(job.String(), err)
	}
	if commit.AlreadyCommitted {
		return Result{AlreadyStored: true, Package: pkg, Origin: tree.Origin}, nil
	}

	// The digest computed on the way into the bucket must match the digest of
	// what was packed; they are computed independently, so a mismatch means
	// the bytes changed in flight.
	if commit.Bundle.Digest != digest || commit.Bundle.Size != size {
		return Result{}, classify(job.String(), fmt.Errorf(
			"stored bundle does not match what was packed: packed %s (%d bytes), stored %s (%d bytes)",
			hex.EncodeToString(digest[:]), size,
			hex.EncodeToString(commit.Bundle.Digest[:]), commit.Bundle.Size))
	}

	published, latest, err := w.publish(ctx, job, pkg, commit)
	if err != nil {
		return Result{}, classify(job.String(), err)
	}
	if !published {
		// The transaction found the version already published — the same
		// redelivery the pre-flight check answers, it just lost the race.
		return Result{AlreadyStored: true, Package: pkg, Origin: tree.Origin}, nil
	}

	// The pointer move follows the commit rather than riding it: a crash in
	// between leaves an index that lags the catalog by one version, corrected
	// by the next publish, rather than an index advertising an unpublished
	// version.
	if latest {
		if err := w.committer.SetLatest(ctx, job.VersionRef().Package(), job.Semver); err != nil {
			return Result{}, classify(job.String(), err)
		}
	}
	return Result{Commit: commit, Package: pkg, Origin: tree.Origin, Latest: latest}, nil
}
