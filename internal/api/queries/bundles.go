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

// Distributable reports whether the bundle may be served at all. A rejected
// version is never served regardless of the org gate, which governs
// resolution, not distribution.
func (b BundleRef) Distributable() bool { return b.Verdict != models.VerdictRejected }

// The first path segment is the namespace, not the publisher slug (a slug
// contains a slash), despite the contract naming the parameter `publisher`.
// %s is PackageReadable over `pkg`; folding it in makes an unreadable version
// indistinguishable from a missing one, so getBundle's 403 for a rejected
// version never leaks existence.
const bundleRefSQL = `
select v.object_key, v.digest, v.verdict::text, coalesce(v.size_bytes, 0)
from version as v
join package as pkg on pkg.id = v.package_id
where pkg.namespace = ? and pkg.name = ? and v.semver = ? and v.visible and %s`

// Bundle locates one immutable version's bytes. Only a visible version is
// findable, since `visible` is committed last and an in-flight publish has none.
func Bundle(ctx context.Context, db bun.IDB, p auth.Principal, namespace, name, version string) (BundleRef, error) {
	readable, readableArgs := bundleReadable(p)
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

// bundleReadable is PackageReadable, widened for a service token to a version
// a revision of one of its sync-scoped profiles locks — still only where the
// creator can read the package.
func bundleReadable(p auth.Principal) (predicate string, args []any) {
	if !p.IsServiceToken() || p.ServiceToken.Allows(auth.ScopeReadCatalog) {
		return PackageReadable("pkg", p)
	}
	creator, creatorArgs := PackageReadable("pkg", p.ServiceToken.Creator)
	profiles, profileArgs := Readable("prf", p)
	predicate = "(" + creator + " and exists (select 1 from revision as rev " +
		"join profile as prf on prf.id = rev.profile_id where " + profiles +
		" and rev.lockfile -> 'entries' @> jsonb_build_array(jsonb_build_object(" +
		"'id', pkg.namespace || '/' || pkg.name, 'version', v.semver))))"
	return predicate, append(creatorArgs, profileArgs...)
}

// latestBundleRefSQL repeats detailSQL's join (package.go) to the latest
// visible version; the two must not drift. %s is PackageReadable.
const latestBundleRefSQL = `
select v.object_key, v.digest, v.verdict::text, coalesce(v.size_bytes, 0)
from package as pkg
join version as v on v.id = pkg.latest_version_id and v.visible
where pkg.namespace = ? and pkg.name = ? and %s`

// LatestBundle locates the bytes of a package's latest visible version.

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
