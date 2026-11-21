package fetcher

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"agent-manager/internal/blob"
	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/fetch"
	"agent-manager/internal/metrics"
	"agent-manager/internal/outbox"
)

// Result is what one successful fetch produced.
type Result struct {
	Commit blob.Commit

	// AlreadyStored marks a redelivery that did nothing, not an error.
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
	fetched(job.Source.Kind, result, err)
	if err != nil {
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
		Strs("links_not_stored", result.Package.Layout.Links).
		Msg("version stored")
	return nil
}

func fetched(source fetch.SourceKind, result Result, err error) {
	outcome := "stored"
	switch {
	case err != nil && ReasonOf(err) != "":
		outcome = string(ReasonOf(err))
	case err != nil:
		outcome = "error"
	case result.AlreadyStored:
		outcome = "unchanged"
	}
	metrics.FetchesTotal.WithLabelValues(string(source), outcome).Inc()
}

// run is the pipeline proper, with every step's failure classified.
func (w *Worker) run(ctx context.Context, job Job) (Result, error) {
	ref := job.SourceRef()
	ref.Limits = w.limits
	if job.Source.Kind == fetch.SourceUpload {
		ref.Archive = bytes.NewReader(job.Source.Archive)
	}

	if job.Source.Kind == fetch.SourceGit {
		pin, err := w.git.Resolve(ctx, ref)
		if err != nil {
			return Result{}, classify(job.String(), err)
		}
		if err := w.refuseMovedTag(ctx, job, pin); err != nil {
			return Result{}, classify(job.String(), err)
		}
		ref.Commit = pin.Commit
	}

	tree, err := w.sources.Fetch(ctx, ref)
	if err != nil {
		return Result{}, classify(job.String(), err)
	}

	signature, verdict, err := w.verifySignatures(ctx, job.VersionID, tree)
	if err != nil {
		return Result{}, classify(job.String(), err)
	}

	pkg, err := pkgspec.InspectWith(w.validator, tree.Files, tree.Root)
	if err != nil {
		return Result{}, classify(job.String(), err)
	}

	// A manifest's own version must match the one being registered.
	if pkg.Semver != "" && pkg.Semver != job.Semver {
		return Result{}, classify(job.String(),
			fmt.Errorf("%w: manifest says %s, registration says %s", errVersionMismatch, pkg.Semver, job.Semver))
	}
	if pkg.Name != job.Name {
		return Result{}, classify(job.String(),
			fmt.Errorf("%w: manifest name is %q, registration is for %q", pkgspec.ErrManifestInvalid, pkg.Name, job.Name))
	}

	// Pack is deterministic, so the digest depends only on the tree.
	packed, digest, size, err := bundle.Pack(pkg.Files)
	if err != nil {
		return Result{}, classify(job.String(), err)
	}

	// Latest is decided later, under a row lock in the publish transaction.
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

	// Computed independently, so a mismatch means the bytes changed in flight.
	if commit.Bundle.Digest != digest || commit.Bundle.Size != size {
		return Result{}, classify(job.String(), fmt.Errorf(
			"stored bundle does not match what was packed: packed %s (%d bytes), stored %s (%d bytes)",
			hex.EncodeToString(digest[:]), size,
			hex.EncodeToString(commit.Bundle.Digest[:]), commit.Bundle.Size))
	}

	published, latest, err := w.publish(ctx, job, tree, pkg, commit, stored{signature: signature, verdict: verdict})
	if err != nil {
		return Result{}, classify(job.String(), err)
	}
	if !published {
		// Lost a race with the pre-flight check.
		return Result{AlreadyStored: true, Package: pkg, Origin: tree.Origin}, nil
	}

	if latest {
		if err := w.committer.SetLatest(ctx, job.VersionRef().Package(), job.Semver); err != nil {
			return Result{}, classify(job.String(), err)
		}
	}
	return Result{Commit: commit, Package: pkg, Origin: tree.Origin, Latest: latest}, nil
}

// refuseMovedTag refuses a tag that resolves to a different commit than any
// version from the same repository recorded for it.
func (w *Worker) refuseMovedTag(ctx context.Context, job Job, pin fetch.Pin) error {
	if !pin.Tag {
		return nil
	}
	var semver, namespace, name, recorded string
	err := w.deps.DB.QueryRowContext(ctx,
		`select ver.semver, pkg.namespace, pkg.name, ver.source_commit
		   from version as ver join package as pkg on pkg.id = ver.package_id
		  where ver.source_url = ? and ver.source_ref = ? and ver.source_commit <> ? and ver.id <> ?
		  order by ver.created_at limit 1`,
		pin.RepoURL, pin.Ref, pin.Commit, job.VersionID).Scan(&semver, &namespace, &name, &recorded)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("compare tag %s against the recorded commits: %w", pin.Ref, err)
	}
	return &TagMovedError{
		Repo: pin.RepoURL, Tag: pin.Ref, Version: namespace + "/" + name + "@" + semver,
		From: recorded, To: pin.Commit,
	}
}
