package commands

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/fetch"
	"agent-manager/internal/repourl"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
	"agent-manager/internal/worker/fetcher"
)

// The registration refusals live beside the shared registration in
// fetcher.Register; these names are what the api's error mapping reads.
var (
	ErrRegistration = fetcher.ErrRegistration
	ErrImmutable    = fetcher.ErrImmutable
)

const (
	// MaxTagCount bounds a registration's own tags. High enough for real
	// use, low enough that the catalog's tag facet stays a facet.
	MaxTagCount = 20
	// MaxTagLength bounds one tag. Every tag in internal/seed and
	// internal/web/fakeapi is well under this.
	MaxTagLength = 40
)

// tagRE is a tag's character set: what the catalog's tag facet and pill
// already render as plain mono text, with no separator character a
// comma-separated field could confuse for another tag.
var tagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)

// Registration is one registration request, reduced to what the command
// needs.
type Registration struct {
	Source       fetch.SourceKind
	URL          string
	Ref          string
	Subdirectory string

	// Publisher is the slug, `example/platform` or just `example`. Namespace
	// is derived in normalise, never supplied directly, since it's what the
	// object key is built from.
	Publisher string
	Namespace string
	Name      string
	Version   string

	Kind       models.PackageKind
	Category   string
	Visibility models.PackageVisibility

	// Keywords seed version.tags so the catalog can filter a version the
	// fetcher hasn't finished yet. Keywords is the archive's own manifest
	// keywords (upload only); Tags is what the publisher typed on the
	// form. Both are unioned into version.tags here, and unioned again
	// with the fetched manifest's keywords at publish — never replaced,
	// in either direction.
	Keywords []string
	// Tags is validated and deduplicated in normalise, matching
	// fetcher.VersionTags's own rule rather than a second one.
	Tags []string

	ArchiveName string
	Archive     []byte
	Preview     *contract.PackagePreview
}

// RegisterPackage is publisher, package, version, the `fetch` job and the
// audit row in one transaction: the version row must exist before the job
// that fills it in is enqueued, so an outbox row committing without its
// version would be a job with nothing to work on. Nothing here writes
// bytes — `worker fetcher` is the only role that may — so the archive
// travels in the outbox payload.
func RegisterPackage(ctx context.Context, db bun.IDB, p auth.Principal, in Registration) (contract.PackageRegistered, error) {
	in, err := in.normalise()
	if err != nil {
		return contract.PackageRegistered{}, err
	}

	ref := blob.VersionRef{Namespace: in.Namespace, Name: in.Name, Semver: in.Version}
	if refErr := ref.Validate(); refErr != nil {
		return contract.PackageRegistered{}, fmt.Errorf("%w: %w", ErrRegistration, refErr)
	}
	if _, err = models.SemverSort(in.Version); err != nil {
		return contract.PackageRegistered{}, fmt.Errorf("%w: %w", ErrRegistration, err)
	}

	out := contract.PackageRegistered{
		Publisher: in.Publisher,
		Name:      in.Name,
		Version:   in.Version,
		Kind:      string(in.Kind),
		ObjectKey: ref.BundleKey(),
		Verdict:   string(models.VerdictScanning),
		Visible:   false,
	}

	err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		publisherID, txErr := upsertPublisher(ctx, tx, in.Publisher)
		if txErr != nil {
			return txErr
		}
		categoryID, txErr := resolveCategory(ctx, tx, in.Category)
		if txErr != nil {
			return txErr
		}
		pkg, txErr := upsertPackage(ctx, tx, publisherID, categoryID, p, in)
		if txErr != nil {
			return txErr
		}
		out.PackageID = pkg.ID.String()
		out.Kind = string(pkg.Kind)

		versionID, txErr := fetcher.Register(ctx, tx, fetcher.Registrar{
			Actor: memberRef(p), ActorKind: models.ActorKindIdentity, Source: p.Source,
		}, pkg, fetcher.NewVersion{
			Semver: in.Version,
			Tags:   fetcher.VersionTags(append(in.Keywords, in.Tags...)),
			Source: fetcher.JobSource{
				Kind:         in.Source,
				URL:          in.URL,
				Ref:          in.Ref,
				Subdirectory: in.Subdirectory,
				ArchiveName:  in.ArchiveName,
				Archive:      in.Archive,
			},
		})
		if txErr != nil {
			return txErr
		}
		out.VersionID = versionID.String()
		return nil
	})
	if err != nil {
		return contract.PackageRegistered{}, err
	}
	return out, nil
}

// normalise fills in what can be derived and refuses what cannot.
func (in Registration) normalise() (Registration, error) {
	in.Publisher = strings.ToLower(strings.TrimSpace(in.Publisher))
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))

	if in.Publisher == "" {
		// No source carries a publisher, and guessing one would make the
		// object key — which is permanent — a guess.
		return in, fmt.Errorf("%w: a registration needs a publisher", ErrRegistration)
	}

	// One or two segments mirrors the schema's own constraint, stated here
	// so the caller learns what's wrong instead of reading a 23514. Either
	// shape gives the namespace a non-empty first segment; what's refused is
	// an empty segment or a third one.
	namespace, team, ok := strings.Cut(in.Publisher, "/")
	if namespace == "" || (ok && (team == "" || strings.Contains(team, "/"))) {
		return in, fmt.Errorf(
			"%w: a publisher is <namespace> or <namespace>/<team>, for example example or example/platform, not %q",
			ErrRegistration, in.Publisher)
	}
	in.Namespace = namespace

	switch in.Source {
	case fetch.SourceUpload:
		if len(in.Archive) == 0 {
			return in, fmt.Errorf("%w: an upload needs an archive", ErrRegistration)
		}
	case fetch.SourceGit, fetch.SourceArchiveURL:
		if in.URL == "" {
			return in, fmt.Errorf("%w: a %s registration needs a url", ErrRegistration, in.Source)
		}
		if in.Name == "" || in.Version == "" {
			derivedName, derivedVersion := deriveFromURL(in)
			if in.Name == "" {
				in.Name = derivedName
			}
			if in.Version == "" {
				in.Version = derivedVersion
			}
		}
	default:
		return in, fmt.Errorf("%w: unknown source kind %q", ErrRegistration, in.Source)
	}

	switch {
	case in.Name == "":
		return in, fmt.Errorf("%w: a registration needs a name", ErrRegistration)
	case !pkgspec.ValidName(in.Name):
		return in, fmt.Errorf("%w: %q is not a valid package name", ErrRegistration, in.Name)
	case in.Version == "":
		return in, fmt.Errorf("%w: a registration needs a version, and none could be derived from the ref", ErrRegistration)
	}

	normalised, err := pkgspec.NormaliseSemver(in.Version)
	if err != nil {
		return in, fmt.Errorf("%w: %w", ErrRegistration, err)
	}
	in.Version = normalised

	if in.Kind == "" {
		in.Kind = models.PackageKindPlugin
	}
	if !in.Kind.Valid() {
		return in, fmt.Errorf("%w: %q is not a package kind", ErrRegistration, in.Kind)
	}
	if in.Visibility == "" {
		in.Visibility = models.PackageVisibilityOrganisation
	}
	if !in.Visibility.Valid() {
		return in, fmt.Errorf("%w: %q is not a visibility", ErrRegistration, in.Visibility)
	}

	tags, err := normaliseTags(in.Tags)
	if err != nil {
		return in, err
	}
	in.Tags = tags

	return in, nil
}

// normaliseTags trims and drops empties before deduping, so "aws" and
// " aws " are the same tag, and dedupes before counting, so typing the same
// tag twice never refuses a registration that would otherwise pass. Unlike
// Decision.Note, which truncates, an over-long or ill-formed tag is refused:
// prose surviving a cut is still readable, but a truncated or stripped tag is
// a silent lie about what was registered.
func normaliseTags(raw []string) ([]string, error) {
	trimmed := make([]string, 0, len(raw))
	for _, tag := range raw {
		if tag = strings.TrimSpace(tag); tag != "" {
			trimmed = append(trimmed, tag)
		}
	}

	tags := fetcher.VersionTags(trimmed)
	if len(tags) > MaxTagCount {
		return nil, fmt.Errorf("%w: at most %d tags are allowed, not %d", ErrRegistration, MaxTagCount, len(tags))
	}
	for _, tag := range tags {
		if len(tag) > MaxTagLength || !tagRE.MatchString(tag) {
			return nil, fmt.Errorf(
				"%w: %q is not a valid tag: letters, digits and hyphens, at most %d characters",
				ErrRegistration, tag, MaxTagLength)
		}
	}
	return tags, nil
}

// deriveFromURL gives the import modal a default name and version only.
func deriveFromURL(in Registration) (name, version string) {
	if repo, err := repourl.Parse(in.URL); err == nil {
		name = repo.Repo
		if in.Ref == "" && repo.Ref != "" {
			in.Ref = repo.Ref
		}
	}
	if in.Ref != "" {
		if semver, err := pkgspec.NormaliseSemver(in.Ref); err == nil {
			version = semver
		}
	}
	return name, version
}

// upsertPublisher creates the namespace on first use. `verified` is left
// alone: it is a catalog admin's decision, never inferred from a registration.
func upsertPublisher(ctx context.Context, tx bun.IDB, slug string) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.NewSelect().Model((*models.Publisher)(nil)).
		Column("id").Where("slug = ?", slug).Scan(ctx, &id)
	if err == nil {
		return id, nil
	}

	publisher := &models.Publisher{ID: models.NewID(), Slug: slug, DisplayName: slug}
	if _, err := tx.NewInsert().Model(publisher).
		On("conflict (slug) do nothing").Exec(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("create publisher %q: %w", slug, err)
	}
	if err := tx.NewSelect().Model((*models.Publisher)(nil)).
		Column("id").Where("slug = ?", slug).Scan(ctx, &id); err != nil {
		return uuid.Nil, fmt.Errorf("read publisher %q: %w", slug, err)
	}
	return id, nil
}

// resolveCategory looks up an admin-curated category by name or slug. An
// unknown one is refused rather than created: the vocabulary is curated.
func resolveCategory(ctx context.Context, tx bun.IDB, nameOrSlug string) (*uuid.UUID, error) {
	if nameOrSlug == "" {
		return nil, nil
	}
	var id uuid.UUID
	err := tx.NewSelect().Model((*models.Category)(nil)).
		Column("id").
		Where("slug = ? or lower(name) = lower(?)", strings.ToLower(nameOrSlug), nameOrSlug).
		Limit(1).Scan(ctx, &id)
	if err != nil {
		return nil, fmt.Errorf("%w: no category %q — categories are curated by a catalog admin (FR-049)",
			ErrRegistration, nameOrSlug)
	}
	return &id, nil
}

// upsertPackage finds or creates the named package. The kind written here
// is provisional for a URL source; the fetcher settles it once the
// manifest is in hand. An existing package keeps its kind.
func upsertPackage(ctx context.Context, tx bun.IDB, publisherID uuid.UUID, categoryID *uuid.UUID,
	p auth.Principal, in Registration,
) (*models.Package, error) {
	// Looked up by (namespace, name), matching the unique index — not by
	// (publisher_id, name), which would miss a name owned by a sibling
	// team in the same namespace.
	existing := new(models.Package)
	err := tx.NewSelect().Model(existing).
		Where("namespace = ? and name = ?", in.Namespace, in.Name).
		Limit(1).Scan(ctx)
	if err == nil {
		if existing.PublisherID != publisherID {
			return nil, fmt.Errorf(
				"%w: %s/%s already belongs to another publisher in the %s namespace",
				ErrRegistration, in.Namespace, in.Name, in.Namespace)
		}
		if categoryID != nil && existing.CategoryID == nil {
			if _, err := tx.NewUpdate().Model(existing).
				Set("category_id = ?", categoryID).
				Set("updated_at = now()").
				WherePK().Exec(ctx); err != nil {
				return nil, fmt.Errorf("set the category of %s: %w", in.Name, err)
			}
		}
		return existing, nil
	}

	pkg := &models.Package{
		ID:          models.NewID(),
		PublisherID: publisherID,
		Namespace:   in.Namespace,
		Name:        in.Name,
		Kind:        in.Kind,
		CategoryID:  categoryID,
		Visibility:  in.Visibility,
	}
	// Recorded at creation, so a new package's first registration is not
	// audited as a change of source.
	source := fetch.ProvenanceOf(fetch.SourceRef{Kind: in.Source, URL: in.URL, Ref: in.Ref, Subdirectory: in.Subdirectory})
	pkg.SourceKind, pkg.SourceURL, pkg.SourceRef, pkg.SourceSubdirectory =
		models.FetchSourceKind(source.Kind), source.URL, source.Ref, source.Subdirectory
	// The owner is the authenticated actor, never a value the request body
	// could name — an identity registering a package it does not control
	// itself would be exactly the hole an owner column exists to close.
	// Set once, at creation: a later registration of the same
	// publisher/name reuses the existing row above and never reassigns it.
	if p.IdentityID != uuid.Nil {
		pkg.OwnerIdentityID = &p.IdentityID
	}
	if _, err := tx.NewInsert().Model(pkg).Exec(ctx); err != nil {
		return nil, fmt.Errorf("create package %s: %w", in.Name, err)
	}
	return pkg, nil
}

// isUniqueViolation reports whether err is Postgres 23505 on the named
// constraint, checked by sqlstate rather than message since messages are
// localised and reworded between releases.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

// PackageNotPermittedError is a visibility or tracking change refused to an identity
// that is neither the package's owner nor a catalog admin, mirroring
// NotPermittedError's shape for the same reason: the caller can already see
// the package (it answered 200, not 404), so the only useful thing left to
// say is who may act on it.
type PackageNotPermittedError struct {
	Owner string
	// Change names what was refused; empty is visibility.
	Change string
}

func (e *PackageNotPermittedError) Error() string {
	who := "it has no recorded owner"
	if e.Owner != "" {
		who = "its owner is " + e.Owner
	}
	change := e.Change
	if change == "" {
		change = "visibility"
	}
	return "this identity may not change this package's " + change + ": that needs the owner or a " +
		"catalog admin, and " + who
}

// SetPackageTracking opts a git package in or out of the upstream check,
// gated like SetPackageVisibility. An empty pattern keeps the current one.
func SetPackageTracking(ctx context.Context, db bun.IDB, p auth.Principal,
	namespace, name string, track bool, pattern string,
) error {
	pattern = strings.TrimSpace(pattern)
	if pattern != "" && !fetcher.ValidTagPattern(pattern) {
		return fmt.Errorf("%w: %q is not a tag pattern: a glob such as v* of at most 100 characters", ErrRegistration, pattern)
	}

	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		pkg := new(models.Package)
		if err := tx.NewSelect().Model(pkg).
			Where("namespace = ? and name = ?", namespace, name).
			For("update").Limit(1).Scan(ctx); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return queries.ErrNotFound
			}
			return fmt.Errorf("read package %s/%s: %w", namespace, name, err)
		}

		if err := permitPackageChange(ctx, tx, p, pkg, "upstream tracking"); err != nil {
			return err
		}
		if pkg.SourceKind != models.FetchSourceGit {
			return fmt.Errorf("%w: %s/%s was not registered from git, so it has no upstream tags to track",
				ErrRegistration, namespace, name)
		}
		if pattern == "" {
			pattern = pkg.TagPattern
		}
		if pkg.TrackUpstream == track && pkg.TagPattern == pattern {
			return nil
		}

		if _, err := tx.NewUpdate().Model((*models.Package)(nil)).
			Set("track_upstream = ?", track).
			Set("tag_pattern = ?", pattern).
			Set("updated_at = now()").
			Where("id = ?", pkg.ID).Exec(ctx); err != nil {
			return fmt.Errorf("set the upstream tracking of %s/%s: %w", namespace, name, err)
		}

		text := fmt.Sprintf("stopped tracking the upstream of %s/%s", namespace, name)
		if track {
			text = fmt.Sprintf("tracking the upstream of %s/%s for tags matching %s", namespace, name, pattern)
		}
		entry := identityAudit(p, models.AuditKindFetch, "tracking-changed", text, audit.Package(namespace, name))
		entry.Data = map[string]any{"trackUpstream": track, "tagPattern": pattern}
		return writeAudit(ctx, tx, entry)
	})
}

// SetPackageVisibility changes an existing package's visibility. FR-126 and
// constitution principle IV: this is a state change distinct from
// registration, gated the same way and audited the same way. Reusing
// AuditKindShare rather than adding a new enum value: both record a
// decision about who may see something, and this is the smaller change.
func SetPackageVisibility(ctx context.Context, db bun.IDB, p auth.Principal,
	namespace, name string, visibility models.PackageVisibility,
) error {
	if !visibility.Valid() {
		return fmt.Errorf("%w: %q is not a visibility", ErrRegistration, visibility)
	}

	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		pkg := new(models.Package)
		if err := tx.NewSelect().Model(pkg).
			Where("namespace = ? and name = ?", namespace, name).
			Limit(1).Scan(ctx); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return queries.ErrNotFound
			}
			return fmt.Errorf("read package %s/%s: %w", namespace, name, err)
		}

		if err := permitPackageChange(ctx, tx, p, pkg, ""); err != nil {
			return err
		}
		if pkg.Visibility == visibility {
			return nil
		}
		// team and private are both enforced by comparing a reader against
		// the OWNER (queries.PackageReadable): an owner-less package narrowed
		// to either would match nobody, ever, including the catalog admin who
		// just narrowed it — a self-inflicted version of the exact leak this
		// whole feature exists to close, just pointed at invisibility instead.
		// Only reachable here at all because a catalog admin may act on a
		// package whose owner is nil; the owner branch above already implies
		// a non-nil owner.
		if visibility != models.PackageVisibilityOrganisation && pkg.OwnerIdentityID == nil {
			return fmt.Errorf("%w: %s/%s has no recorded owner, so only organisation visibility is safe for it",
				ErrRegistration, namespace, name)
		}

		if _, err := tx.NewUpdate().Model(pkg).
			Set("visibility = ?", visibility).
			Set("updated_at = now()").
			WherePK().Exec(ctx); err != nil {
			return fmt.Errorf("set the visibility of %s/%s: %w", namespace, name, err)
		}

		audit := identityAudit(p, models.AuditKindShare, "visibility-changed",
			fmt.Sprintf("changed the visibility of %s/%s to %s", namespace, name, visibility),
			audit.Package(namespace, name))
		audit.Data = map[string]any{"visibility": string(visibility)}
		return writeAudit(ctx, tx, audit)
	})
}

// permitPackageChange lets the owner or a catalog-admin change pkg. Anyone
// else who cannot read it gets not-found, so the refusal never confirms a
// hidden package exists or names its owner.
func permitPackageChange(ctx context.Context, tx bun.Tx, p auth.Principal, pkg *models.Package, change string) error {
	if (pkg.OwnerIdentityID != nil && *pkg.OwnerIdentityID == p.IdentityID) || p.Role == models.OrgRoleCatalogAdmin {
		return nil
	}
	readable, args := queries.PackageReadable("pkg", p)
	ok, err := tx.NewSelect().Model((*models.Package)(nil)).
		Where("pkg.id = ?", pkg.ID).Where(readable, args...).Exists(ctx)
	if err != nil {
		return fmt.Errorf("read package %s/%s: %w", pkg.Namespace, pkg.Name, err)
	}
	if !ok {
		return queries.ErrNotFound
	}
	owner := ""
	if pkg.OwnerIdentityID != nil {
		owner = pkg.OwnerIdentityID.String()
	}
	return &PackageNotPermittedError{Owner: owner, Change: change}
}
