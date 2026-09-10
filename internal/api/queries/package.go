package queries

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
)

// The package detail read is five statements: one that identifies the
// package and 404s, then four issued concurrently once its ids are known.
// The first cannot join the rest because four are one-to-many over
// different children, and a single join would multiply every row and then
// need undoing in Go. db must be a pool, not a transaction: the four run concurrently.

// detailSQL identifies the package and everything one-to-one with it. The
// `latest_version_id` join is the same rule catalogFrom uses, so the
// detail page shows exactly what the catalog links to. `visibility =
// 'organisation'` is the same unconditional filter as
// CatalogFilter.baseFilters — repeated rather than shared because this
// statement's FROM clause differs, but the two must not drift.
const detailSQL = `
select
  pkg.id,
  pkg.namespace || '/' || pkg.name,
  pkg.name,
  pkg.kind::text,
  pub.slug,
  pub.display_name,
  pub.verified,
  coalesce(cat.name, ''),
  ver.id,
  ver.semver,
  ver.verdict::text,
  ver.manifest::text,
  ver.tags,
  coalesce(parent.namespace || '/' || parent.name, ''),
  coalesce(parent.name, ''),
  exists (select 1 from scan where scan.version_id = ver.id and scan.finished_at is not null)
from package as pkg
join publisher as pub on pub.id = pkg.publisher_id
join version as ver on ver.id = pkg.latest_version_id and ver.visible
left join category as cat on cat.id = pkg.category_id
left join package as parent on parent.id = pkg.parent_package_id
where pkg.visibility = 'organisation'
  and pkg.namespace = ?
  and pkg.name = ?`

// Package answers one detail page. `namespace` is the first segment of the
// rendered id, not the publisher slug (see bundles.go, where confusing the
// two was a real defect).
func Package(ctx context.Context, db bun.IDB, principal auth.Principal,
	namespace, name string,
) (contract.PackageDetail, error) {
	var (
		detail    contract.PackageDetail
		packageID string
		versionID string
		manifest  string
		parentID  string
		parent    string
	)
	detail.Tags = []string{}

	err := db.QueryRowContext(ctx, detailSQL, namespace, name).Scan(
		&packageID, &detail.ID, &detail.Name, &detail.Kind,
		&detail.Publisher.Slug, &detail.Publisher.DisplayName, &detail.Publisher.Verified,
		&detail.Category,
		&versionID, &detail.Version, &detail.Verdict, &manifest, pgdialect.Array(&detail.Tags),
		&parentID, &parent, &detail.Capabilities.Scanned)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contract.PackageDetail{}, ErrNotFound
	case err != nil:
		return contract.PackageDetail{}, fmt.Errorf("read package %s/%s: %w", namespace, name, err)
	}
	if detail.Tags == nil {
		detail.Tags = []string{}
	}

	detail.Manifest = manifest
	detail.ManifestObject = manifestObject(detail.Kind)
	detail.Description = manifestDescription(manifest)
	detail.Origin = contract.PackageOrigin{
		SpecVersion: specVersion(manifest),
		ParentID:    parentID,
		ParentName:  parent,
	}

	var (
		wait sync.WaitGroup
		errs [4]error
	)
	wait.Add(4)
	go func() {
		defer wait.Done()
		detail.Versions, errs[0] = packageVersions(ctx, db, principal, packageID)
	}()
	go func() {
		defer wait.Done()
		detail.Components, errs[1] = packageComponents(ctx, db, versionID)
	}()
	go func() {
		defer wait.Done()
		detail.Capabilities.Inferred, detail.Capabilities.Expected, errs[2] =
			packageCapabilities(ctx, db, versionID)
	}()
	go func() {
		defer wait.Done()
		detail.Dependents, errs[3] = packageDependents(ctx, db, principal, packageID)
	}()
	wait.Wait()

	if err := errors.Join(errs[:]...); err != nil {
		return contract.PackageDetail{}, err
	}
	return detail, nil
}

// packageVersions is the versions panel. `pinned by N` is derived and
// scoped by the readability predicate — not optional: an unscoped count
// beside the readable dependent-profiles list would leak private profiles
// by arithmetic. Ordering is by `semver_sort` so 0.10.0 sorts above 0.9.0.
func packageVersions(ctx context.Context, db bun.IDB, principal auth.Principal,
	packageID string,
) ([]contract.PackageVersion, error) {
	readable, readableArgs := Readable("pinner", principal)

	query := `
select
  ver.semver,
  ver.dist_tag::text,
  ver.verdict::text,
  ver.created_at,
  ver.object_key,
  coalesce(ver.digest, ''::bytea),
  coalesce(ver.size_bytes, 0),
  (select count(*)
     from profile_entry as pin
     join profile as pinner on pinner.id = pin.profile_id
    where pin.pinned_version_id = ver.id and ` + readable + `)
from version as ver
where ver.package_id = ? and ver.visible
order by ver.semver_sort desc, ver.created_at desc`

	args := append([]any{}, readableArgs...)
	args = append(args, packageID)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read the version history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	versions := []contract.PackageVersion{}
	for rows.Next() {
		var (
			version contract.PackageVersion
			digest  []byte
		)
		if err := rows.Scan(&version.Version, &version.DistTag, &version.Verdict, &version.CreatedAt,
			&version.ObjectKey, &digest, &version.SizeBytes, &version.PinnedBy); err != nil {
			return nil, fmt.Errorf("scan a version row: %w", err)
		}
		if len(digest) > 0 {
			version.Digest = "sha256:" + hex.EncodeToString(digest)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the version history: %w", err)
	}
	return versions, nil
}

// packageComponents is ordered by the enum's declaration order — skill,
// mcp, ext — not the text, which would put ext first. `order by cmp.kind`
// is qualified for that reason: a bare `order by kind` binds to the cast
// output column and sorts alphabetically instead, a defect this query
// actually had.
func packageComponents(ctx context.Context, db bun.IDB, versionID string) ([]contract.PackageComponent, error) {
	const query = `
select cmp.kind::text, cmp.name, cmp.path, coalesce(cmp.note, '')
from component as cmp
where cmp.version_id = ?
order by cmp.kind, cmp.name`

	rows, err := db.QueryContext(ctx, query, versionID)
	if err != nil {
		return nil, fmt.Errorf("read the component list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	components := []contract.PackageComponent{}
	for rows.Next() {
		var component contract.PackageComponent
		if err := rows.Scan(&component.Kind, &component.Name, &component.Path, &component.Note); err != nil {
			return nil, fmt.Errorf("scan a component row: %w", err)
		}
		components = append(components, component)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the component list: %w", err)
	}
	return components, nil
}

// packageCapabilities reads both sources of the inferred/expected
// comparison in one statement, since they are one table keyed by source.
// Two empty slices means never scanned, not "reaches nothing" — the
// `scanned` flag on the detail tells the two cases apart.
func packageCapabilities(ctx context.Context, db bun.IDB, versionID string) (
	inferred, expected []contract.PackageCapability, err error,
) {
	// Ordered by name only: rows split into two slices by source below, so
	// ordering by source would risk the same output-name defect above.
	const query = `
select cap.source::text, cap.name, cap.level::text, coalesce(cap.detail::text, '')
from capability as cap
where cap.version_id = ?
order by cap.name`

	rows, err := db.QueryContext(ctx, query, versionID)
	if err != nil {
		return nil, nil, fmt.Errorf("read the capability rows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	inferred, expected = []contract.PackageCapability{}, []contract.PackageCapability{}
	for rows.Next() {
		var (
			source     string
			capability contract.PackageCapability
			detail     string
		)
		if err := rows.Scan(&source, &capability.Name, &capability.Level, &detail); err != nil {
			return nil, nil, fmt.Errorf("scan a capability row: %w", err)
		}
		capability.Detail, capability.Indefinite = decodeCapabilityDetail(detail)

		if source == "expected" {
			expected = append(expected, capability)
			continue
		}
		inferred = append(inferred, capability)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("read the capability rows: %w", err)
	}
	return inferred, expected, nil
}

// capabilityDetail is decoded permissively: the column is jsonb with no
// check constraint, and an unreadable detail degrades to "no targets
// listed" rather than failing the whole page.
type capabilityDetail struct {
	Targets    []string `json:"targets"`
	Indefinite bool     `json:"indefinite"`
}

func decodeCapabilityDetail(raw string) ([]string, bool) {
	if raw == "" {
		return []string{}, false
	}
	var detail capabilityDetail
	if err := json.Unmarshal([]byte(raw), &detail); err != nil || detail.Targets == nil {
		return []string{}, detail.Indefinite
	}
	return detail.Targets, detail.Indefinite
}

// packageDependents is scoped by the same readability predicate
// /v1/profiles uses: an unreadable profile is never selected. Without it
// this panel would name every private profile pinning the package, from a
// page any authenticated person may open.
func packageDependents(ctx context.Context, db bun.IDB, principal auth.Principal,
	packageID string,
) ([]contract.PackageDependent, error) {
	readable, readableArgs := Readable("prf", principal)

	query := `
select prf.slug, prf.name, entry.mode::text, coalesce(pin.semver, ''), coalesce(entry.range_expr, '')
from profile_entry as entry
join profile as prf on prf.id = entry.profile_id
left join version as pin on pin.id = entry.pinned_version_id
where entry.package_id = ? and ` + readable + `
order by prf.name, prf.slug`

	args := append([]any{any(packageID)}, readableArgs...)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read the dependent profiles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	dependents := []contract.PackageDependent{}
	for rows.Next() {
		var dependent contract.PackageDependent
		if err := rows.Scan(&dependent.Slug, &dependent.Name, &dependent.Mode,
			&dependent.Version, &dependent.Range); err != nil {
			return nil, fmt.Errorf("scan a dependent profile: %w", err)
		}
		dependents = append(dependents, dependent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the dependent profiles: %w", err)
	}
	return dependents, nil
}

// ---- manifest readings --------------------------------------------------------
//
// The three below read the stored manifest rather than a column: `package`
// carries no description or spec version, and adding one would duplicate
// what the manifest already says.

func manifestObject(kind string) string {
	if kind == "skill" {
		return "SKILL.md"
	}
	return "plugin.json"
}

func manifestDescription(manifest string) string {
	var doc struct {
		Description string `json:"description"`
	}
	if err := json.Unmarshal([]byte(manifest), &doc); err != nil {
		return ""
	}
	return doc.Description
}

// specVersion reads the version out of the manifest's `$schema`: Agent
// Plugins has no `agentPluginsVersion` field, so the $id carries the
// version as a path segment instead. A standalone skill has no `$schema`,
// so this returns "" — not a gap to fill, since agentskills.io versions nothing.
func specVersion(manifest string) string {
	var doc struct {
		Schema string `json:"$schema"`
	}
	if err := json.Unmarshal([]byte(manifest), &doc); err != nil || doc.Schema == "" {
		return ""
	}

	// e.g. .../schemas/1.0.0/plugin.schema.json — segment before the file name.
	segments := strings.Split(strings.TrimSuffix(doc.Schema, "/"), "/")
	if len(segments) < 2 {
		return ""
	}
	candidate := segments[len(segments)-2]
	if strings.Count(candidate, ".") != 2 {
		return ""
	}
	return candidate
}
