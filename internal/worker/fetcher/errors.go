package fetcher

import (
	"context"
	"errors"
	"fmt"

	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/fetch"
)

// The fetch-error taxonomy. A fetch failure is reported as a fetch failure
// and never as a scan finding: every reason below happened before any bytes
// were read, or because they could not be read at all.

// ErrFetch is the sentinel behind every failure of this pipeline.
var ErrFetch = errors.New("fetch failed")

// Reason is the closed set of fetch-failure reasons. Each is a distinct operator
// action, which is the only justification for telling two failures apart.
type Reason string

const (
	// ReasonRefused is an SSRF refusal: the URL, a redirect hop or a resolved
	// address was not public.
	ReasonRefused Reason = "refused-by-outbound-policy"

	// ReasonRefNotFound covers a ref the remote does not have and a subdirectory
	// that is not in the tree.
	ReasonRefNotFound Reason = "ref-or-subdirectory-not-found"

	// ReasonCredentials is a source the hub holds no credential for.
	ReasonCredentials Reason = "credentials-required"

	// ReasonUnsupported is a forge or a source kind this build cannot fetch.
	ReasonUnsupported Reason = "unsupported-source"

	// ReasonRemote is any other refusal by the remote.
	ReasonRemote Reason = "remote-refused"

	// ReasonArchiveMalformed is an archive that will not read, including a
	// truncated upload.
	ReasonArchiveMalformed Reason = "archive-malformed"

	// ReasonArchiveTooLarge is a bundle cap: size, entry count, ratio, depth.
	ReasonArchiveTooLarge Reason = "archive-exceeds-limits"

	// ReasonArchiveMemberRejected is a member kind refused outright: an absolute
	// path, a traversal, a symlink, a hardlink, a device node, a duplicate.
	ReasonArchiveMemberRejected Reason = "archive-member-rejected"

	// ReasonArchiveTimeout is the extraction wall-clock cap.
	ReasonArchiveTimeout Reason = "archive-extraction-timed-out"

	// ReasonManifestInvalid is a manifest that fails its published schema, a
	// manifest naming a component that is not on disk, or a tree with no
	// manifest at its root.
	ReasonManifestInvalid Reason = "manifest-invalid"

	// ReasonVersionMismatch is a manifest whose own `version` contradicts the
	// version being registered.
	ReasonVersionMismatch Reason = "manifest-version-mismatch"

	// ReasonStore is object storage or the database refusing the write. It is the
	// one reason here that is the hub's fault rather than the source's, which is
	// why it is worth its own value.
	ReasonStore Reason = "store-write-failed"
)

// Error is one fetch failure.
type Error struct {
	Reason  Reason
	Subject string
	cause   error
}

func (e *Error) Error() string {
	return fmt.Sprintf("fetch %s failed (%s): %v", e.Subject, e.Reason, e.cause)
}

func (e *Error) Unwrap() []error { return []error{ErrFetch, e.cause} }

// Retryable reports whether re-running the job could produce a different
// answer: a non-conformant manifest will still be non-conformant on the
// fourth attempt.
func (e *Error) Retryable() bool {
	switch e.Reason {
	case ReasonRemote, ReasonStore, ReasonArchiveTimeout:
		return true
	default:
		return false
	}
}

// classify maps every error the pipeline can produce onto exactly one reason.
func classify(subject string, err error) error {
	if err == nil {
		return nil
	}

	// A cancelled or timed-out caller is a shutdown or a deadline, not a
	// defect in what was being fetched.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	reason := ReasonStore
	switch {
	case errors.Is(err, fetch.ErrBlocked):
		reason = ReasonRefused
	case errors.Is(err, fetch.ErrRefNotFound):
		reason = ReasonRefNotFound
	case errors.Is(err, fetch.ErrCredentialsRequired):
		reason = ReasonCredentials
	case errors.Is(err, fetch.ErrUnsupportedHost), errors.Is(err, fetch.ErrNoSource):
		reason = ReasonUnsupported
	case errors.Is(err, fetch.ErrRemote):
		reason = ReasonRemote
	case errors.Is(err, bundle.ErrTooLarge):
		reason = ReasonArchiveTooLarge
	case errors.Is(err, bundle.ErrRejectedMember):
		reason = ReasonArchiveMemberRejected
	case errors.Is(err, bundle.ErrTimeout):
		reason = ReasonArchiveTimeout
	case errors.Is(err, bundle.ErrMalformed):
		reason = ReasonArchiveMalformed
	case errors.Is(err, pkgspec.ErrManifestInvalid),
		errors.Is(err, pkgspec.ErrNoManifest),
		errors.Is(err, pkgspec.ErrTreeInvalid):
		reason = ReasonManifestInvalid
	case errors.Is(err, pkgspec.ErrSemver):
		reason = ReasonVersionMismatch
	case errors.Is(err, errVersionMismatch):
		reason = ReasonVersionMismatch
	}
	return &Error{Reason: reason, Subject: subject, cause: err}
}

// errVersionMismatch is raised when the manifest's own `version` names a
// different release from the one being registered.
var errVersionMismatch = errors.New("the manifest names a different version")

// ReasonOf returns the reason behind err, or "" when err is not a fetch failure.
func ReasonOf(err error) Reason {
	var fetchErr *Error
	if errors.As(err, &fetchErr) {
		return fetchErr.Reason
	}
	return ""
}
