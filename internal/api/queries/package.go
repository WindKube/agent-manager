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

// The package detail read (US3, FR-016..FR-019).
//
// Five statements: one that identifies the package and 404s, then four issued
// concurrently once its ids are known. The first cannot join the rest, because
// four of them are one-to-many over different children — versions, components,
// capabilities, dependent profiles — and a single join would multiply every row
// by the cardinality of the others and then have to undo it in Go.
//
// db MUST be a pool and not a transaction, for the same reason Catalog says so:
// the four are issued concurrently and a bun.Tx is one connection.

// detailSQL identifies the package and everything one-to-one with it.
//
// The `latest_version_id` join is not an optimisation. It is the same rule the
// catalog uses (see catalogFrom), and applying it here is what makes the detail
// page show exactly what the catalog links to: a package whose only version is
// still being fetched has no pointer, is not in the catalog, and is not openable
// either. A detail page reachable for a package the catalog cannot list would be
// a second, quieter definition of "published".
//
// `visibility = 'organisation'` is the same unconditional filter as
// CatalogFilter.baseFilters, and the same recorded limitation: the column has
// three values and the table names no owning team or identity, so `team` and
// `private` cannot be evaluated against a caller. They are hidden from everyone.
// Repeating the predicate here rather than reusing the catalog's is deliberate —
// this statement's FROM clause is different — but the two must not drift, and if
// `package` ever grows an owner both change together.
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

// Package answers one detail page. `namespace` is the FIRST segment of the
// rendered id and not the publisher slug — a slug is `example/platform`, two
// segments, and the id `example/pii-redactor` is built from the namespace. The
// same confusion is documented at length in bundles.go, where it was a real
// defect.
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

// packageVersions is the versions panel (FR-019).
//
// `pinned by N` is DERIVED here and never stored (data-model.md), and it is
// scoped by the FR-044 readability predicate. The scoping is not optional: the
// dependent-profiles panel already lists only readable profiles, so an unscoped
// pin count beside it would say "pinned by 3" next to a list of one and leak the
// existence of two private profiles by arithmetic.
//
// Ordering is by `semver_sort`, the zero-padded key the column exists for, so
// 0.10.0 sorts above 0.9.0 — which a lexical sort of `semver` does not.
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

// packageComponents is the plugin variant's component list (FR-017).
//
// The ordering is the ENUM's declaration order — skill, mcp, ext — which is the
// order the design lists them in and the order Postgres compares enum values in.
// Sorting the text would put ext first.
//
// `order by cmp.kind` is qualified for exactly that reason, and the qualification
// is load-bearing rather than tidiness. The select list casts the column, so the
// OUTPUT column is also called `kind` and is text; a bare `order by kind` binds
// to the output name in preference to the input one and sorts alphabetically.
// This query did that, and produced ext, mcp, skill while its comment claimed the
// enum order — a defect that works, found only because the test hand-derived the
// expected order from 01-enums.sql instead of from a run.
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

// packageCapabilities reads both sources of the FR-027 comparison in one
// statement, because they are one table keyed by source.
//
// It returns two empty slices for a version that has never been scanned, and the
// caller must NOT read that as "reaches nothing": the scanner writes both sources
// in the transaction that records the scan, so an unscanned version has rows of
// neither. The `scanned` flag on the detail is what tells the two apart, and it
// comes from the scan table rather than from these lengths.
func packageCapabilities(ctx context.Context, db bun.IDB, versionID string) (
	inferred, expected []contract.PackageCapability, err error,
) {
	// Ordered by name only. The rows are split into two slices by source below, so
	// ordering by source would decide nothing about the output — and `order by
	// source` next to a `source::text` in the select list is the same output-name
	// binding that made packageComponents sort its enum alphabetically. An ordering
	// that cannot be observed is not worth a second chance to get wrong.
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

// capabilityDetail is the shape the scanner writes into `capability.detail`
// (T071). It is decoded permissively: the column is jsonb with no check
// constraint, and a detail this cannot read must degrade to "no targets listed"
// rather than fail the whole page.
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

// packageDependents is the dependent-profiles panel (US3 scenario 5), scoped by
// the FR-044 readability predicate.
//
// The scoping is the same one /v1/profiles uses, and for the same reason: an
// unreadable profile is not merely hidden, it is never selected. Without it this
// panel would name every private profile in the organisation, and the exact
// version each of them pins, from a page any authenticated person may open.
//
// The knock-on is deliberate and worth stating: two people can see different
// dependent lists for the same package. The alternative — a scoped list beside
// an unscoped count — is the worse one, because the difference between the two
// numbers is itself the leak.
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
// The three below read the stored manifest rather than a column, because there
// is no column: `package` carries no description and no spec version, and adding
// one would be a second copy of something the manifest already says.

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

// specVersion reads the version out of the manifest's `$schema`, which is the
// only place either specification's version appears: Agent Plugins 1.0.0 has no
// `agentPluginsVersion` field — the design's manifest is non-conformant (R1) —
// and the $id it dispatches on carries the version as a path segment.
//
// A standalone skill has no `$schema` at all, so this returns "" and the origin
// line says "Agent Skills spec" with no version. That is not a gap to fill:
// agentskills.io publishes no schema and versions nothing.
func specVersion(manifest string) string {
	var doc struct {
		Schema string `json:"$schema"`
	}
	if err := json.Unmarshal([]byte(manifest), &doc); err != nil || doc.Schema == "" {
		return ""
	}

	// https://agent-plugins.org/schemas/1.0.0/plugin.schema.json — the segment
	// before the file name. Read positionally rather than by regex because the
	// value is one of a closed set internal/domain/pkgspec already dispatches on,
	// and a pattern here would accept versions that set does not contain.
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
