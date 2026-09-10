package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// BundleRef is where a published version's bytes live and whether they may be
// served.
type BundleRef struct {
	ObjectKey string
	Digest    []byte
	Verdict   models.Verdict
	SizeBytes int64
}

// Distributable reports whether the bundle may be served at all. FR-029: a
// rejected version is never served, regardless of the org gate — the gate governs
// resolution, not distribution of something already refused.
func (b BundleRef) Distributable() bool { return b.Verdict != models.VerdictRejected }

// The first path segment is the NAMESPACE, matched against package.namespace. It
// cannot be the publisher slug: a slug is `example/platform` and a slug in a path
// segment would be two segments. The frozen contract calls the parameter
// `publisher` and describes it as "the publishing namespace, as it appears in the
// catalog" — the description is the accurate half, and this query follows it. The
// publisher table is not joined at all, because nothing here needs it beyond the
// readability predicate, which is over `package` and not `publisher`.
//
// %s is PackageReadable over `pkg`. Folding it into this statement rather than
// checking it afterwards is what makes a private package's specific version
// answer identically to a version that does not exist: both are ErrNotFound,
// and getBundle's separate 403 for a REJECTED version is only reachable once a
// row is actually found, so it can never fire for a version this caller was
// never shown existed.
const bundleRefSQL = `
select v.object_key, v.digest, v.verdict::text, coalesce(v.size_bytes, 0)
from version as v
join package as pkg on pkg.id = v.package_id
where pkg.namespace = ? and pkg.name = ? and v.semver = ? and v.visible and %s`

// Bundle locates one immutable version's bytes. Only a visible version is
// findable: `visible` is commit-last (FR-008), so an in-flight publish is not a
// 500 waiting to happen.
func Bundle(ctx context.Context, db bun.IDB, p auth.Principal, namespace, name, version string) (BundleRef, error) {
	readable, readableArgs := PackageReadable("pkg", p)
	args := append([]any{namespace, name, version}, readableArgs...)

	var ref BundleRef
	err := db.QueryRowContext(ctx, fmt.Sprintf(bundleRefSQL, readable), args...).
		Scan(&ref.ObjectKey, &ref.Digest, &ref.Verdict, &ref.SizeBytes)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return BundleRef{}, ErrNotFound
	case err != nil:
		return BundleRef{}, fmt.Errorf("locate bundle %s/%s@%s: %w", namespace, name, version, err)
	}
	return ref, nil
}

// latestBundleRefSQL is detailSQL's own join (package.go): the LATEST VISIBLE
// version, the one every other panel on the detail screen describes, not an
// arbitrary one a caller could name. %s is PackageReadable, the same
// predicate that statement composes — repeated rather than shared because
// the FROM clause differs, but the two must not drift.
const latestBundleRefSQL = `
select v.object_key, v.digest, v.verdict::text, coalesce(v.size_bytes, 0)
from package as pkg
join version as v on v.id = pkg.latest_version_id and v.visible
where pkg.namespace = ? and pkg.name = ? and %s`

// LatestBundle locates the bytes of a package's latest visible version — the
// file panel's door to the same version view.Package already describes.
func LatestBundle(ctx context.Context, db bun.IDB, p auth.Principal, namespace, name string) (BundleRef, error) {
	readable, readableArgs := PackageReadable("pkg", p)
	args := append([]any{namespace, name}, readableArgs...)

	var ref BundleRef
	err := db.QueryRowContext(ctx, fmt.Sprintf(latestBundleRefSQL, readable), args...).
		Scan(&ref.ObjectKey, &ref.Digest, &ref.Verdict, &ref.SizeBytes)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return BundleRef{}, ErrNotFound
	case err != nil:
		return BundleRef{}, fmt.Errorf("locate latest bundle for %s/%s: %w", namespace, name, err)
	}
	return ref, nil
}
