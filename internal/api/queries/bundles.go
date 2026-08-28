package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

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
// publisher table is not joined at all, because nothing here needs it.
const bundleRefSQL = `
select v.object_key, v.digest, v.verdict::text, coalesce(v.size_bytes, 0)
from version as v
join package as pkg on pkg.id = v.package_id
where pkg.namespace = ? and pkg.name = ? and v.semver = ? and v.visible`

// Bundle locates one immutable version's bytes. Only a visible version is
// findable: `visible` is commit-last (FR-008), so an in-flight publish is not a
// 500 waiting to happen.
func Bundle(ctx context.Context, db bun.IDB, namespace, name, version string) (BundleRef, error) {
	var ref BundleRef
	err := db.QueryRowContext(ctx, bundleRefSQL, namespace, name, version).
		Scan(&ref.ObjectKey, &ref.Digest, &ref.Verdict, &ref.SizeBytes)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return BundleRef{}, ErrNotFound
	case err != nil:
		return BundleRef{}, fmt.Errorf("locate bundle %s/%s@%s: %w", namespace, name, version, err)
	}
	return ref, nil
}
