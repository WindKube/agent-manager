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
	"agent-manager/internal/domain/signer"
	"agent-manager/internal/fetch"
	"agent-manager/internal/repourl"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
	"agent-manager/internal/worker/fetcher"
)

// Registration refusals live in fetcher.Register; the api's error mapping reads these.
var (
	ErrRegistration = fetcher.ErrRegistration
	ErrImmutable    = fetcher.ErrImmutable
)

const (
	// MaxTagCount is low enough that the catalog's tag facet stays a facet.
	MaxTagCount  = 20
	MaxTagLength = 40
)

// tagRE excludes any separator a comma-separated field could confuse for
// another tag.
var tagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)

// Registration is one registration request, reduced to what the command needs.
type Registration struct {
	Source       fetch.SourceKind
	URL          string
	Ref          string
	Subdirectory string

	// Publisher is `example/platform` or `example`. Namespace is derived in
	// normalise, never supplied, since the object key is built from it.
	Publisher string
	Namespace string
	Name      string
	Version   string

	Kind       models.PackageKind
	Category   string
	Visibility models.PackageVisibility

	// Keywords (the archive manifest's, upload only) and Tags (typed by the
	// publisher) seed version.tags so the catalog can filter a version the
	// fetcher hasn't finished; publish unions rather than replaces them.
	Keywords []string
	Tags     []string

	ArchiveName string
	Archive     []byte
	// SigstoreBundle is uploaded beside the archive (upload only).
	SigstoreBundle []byte
	Preview        *contract.PackagePreview
}

// RegisterPackage writes publisher, package, version, the `fetch` job and the
// audit row in one transaction, so a job never commits without its version.
// Only `worker fetcher` may write bytes, so the archive travels in the outbox
// payload.
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
				Kind:           in.Source,
				URL:            in.URL,
				Ref:            in.Ref,
				Subdirectory:   in.Subdirectory,
				ArchiveName:    in.ArchiveName,
				Archive:        in.Archive,
				SigstoreBundle: in.SigstoreBundle,
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
		// Guessing would make the permanent object key a guess.
		return in, fmt.Errorf("%w: a registration needs a publisher", ErrRegistration)
	}

	// Mirrors the schema's constraint so the caller gets a reason, not a 23514.
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
		if len(in.SigstoreBundle) > 0 {
			return in, fmt.Errorf("%w: a %s registration carries no signature: the hub looks for one beside the source",
				ErrRegistration, in.Source)
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

// normaliseTags dedupes before counting, so a repeated tag never trips the
// limit. Unlike Decision.Note, a bad tag is refused rather than truncated: a
// truncated tag would silently misstate what was registered.
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

// upsertPublisher creates the namespace on first use. `verified` is a catalog
// admin's decision, never inferred from a registration.
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

// resolveCategory refuses an unknown category rather than creating it: the
// vocabulary is curated.
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

// upsertPackage finds or creates the named package. The kind is provisional
// for a URL source until the fetcher reads the manifest.
func upsertPackage(ctx context.Context, tx bun.IDB, publisherID uuid.UUID, categoryID *uuid.UUID,
	p auth.Principal, in Registration,
) (*models.Package, error) {
	// By (namespace, name), the unique index, so a sibling team's name is found.
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
	// Recorded at creation, so the first registration isn't audited as a source change.
	source := fetch.ProvenanceOf(fetch.SourceRef{Kind: in.Source, URL: in.URL, Ref: in.Ref, Subdirectory: in.Subdirectory})
	pkg.SourceKind, pkg.SourceURL, pkg.SourceRef, pkg.SourceSubdirectory =
		models.FetchSourceKind(source.Kind), source.URL, source.Ref, source.Subdirectory
	// The owner is the authenticated actor, never a body value, and is set
	// only at creation.
	if p.IdentityID != uuid.Nil {
		pkg.OwnerIdentityID = &p.IdentityID
	}
	if _, err := tx.NewInsert().Model(pkg).Exec(ctx); err != nil {
		return nil, fmt.Errorf("create package %s: %w", in.Name, err)
	}
	return pkg, nil
}

// isUniqueViolation checks sqlstate 23505 rather than the localised message.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

// PackageNotPermittedError refuses a package change to a reader who is
// neither owner nor catalog admin; it names who may act instead.
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

// SetPackageSigner sets or, with both fields empty, clears the expected
// signer. No version is re-verified: the binding is evaluated at resolution.
func SetPackageSigner(ctx context.Context, db bun.IDB, p auth.Principal,
	namespace, name string, want signer.Expected,
) error {
	want, err := signer.Normalise(want)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRegistration, err)
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

		owns := pkg.OwnerIdentityID != nil && *pkg.OwnerIdentityID == p.IdentityID
		if !owns && p.Role != models.OrgRoleCatalogAdmin {
			owner := ""
			if pkg.OwnerIdentityID != nil {
				owner = pkg.OwnerIdentityID.String()
			}
			return &PackageNotPermittedError{Owner: owner, Change: "expected signer"}
		}
		if pkg.ExpectedSignerIssuer == want.Issuer && pkg.ExpectedSignerIdentity == want.Identity {
			return nil
		}

		if _, err := tx.NewUpdate().Model((*models.Package)(nil)).
			Set("expected_signer_issuer = ?", nullIfBlank(want.Issuer)).
			Set("expected_signer_identity = ?", nullIfBlank(want.Identity)).
			Set("updated_at = now()").
			Where("id = ?", pkg.ID).Exec(ctx); err != nil {
			return fmt.Errorf("set the expected signer of %s/%s: %w", namespace, name, err)
		}

		text := fmt.Sprintf("cleared the expected signer of %s/%s", namespace, name)
		if want.Configured() {
			text = fmt.Sprintf("expect %s/%s to be signed by an identity matching %s issued by %s",
				namespace, name, want.Identity, want.Issuer)
		}
		entry := identityAudit(p, models.AuditKindPolicy, "signer-changed", text, audit.Package(namespace, name))
		entry.Data = map[string]any{
			"issuer": want.Issuer, "identity": want.Identity,
			"previousIssuer": pkg.ExpectedSignerIssuer, "previousIdentity": pkg.ExpectedSignerIdentity,
		}
		return writeAudit(ctx, tx, entry)
	})
}

func nullIfBlank(s string) *string {
	if s == "" {
		return nil
	}
	return &s
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

// SetPackageVisibility changes an existing package's visibility, audited as
// AuditKindShare since both record who may see something.
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
		// team and private compare readers against the owner, so an owner-less
		// package narrowed to either would be visible to nobody.
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
