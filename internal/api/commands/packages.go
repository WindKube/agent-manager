package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/fetch"
	"agent-manager/internal/outbox"
	"agent-manager/internal/repourl"
	"agent-manager/internal/store/models"
	"agent-manager/internal/worker/fetcher"
)

// ErrRegistration is a registration the caller could fix. ErrImmutable is the one
// it cannot: FR-007 makes a published version final.
var (
	ErrRegistration = errors.New("registration refused")
	ErrImmutable    = errors.New("this version is already published and its bytes are immutable")
)

// uniqueVersionConstraint is the index behind FR-007. It is named here because
// Postgres reports the constraint and not the requirement, and translating
// 23505-on-this-index into the immutability error is the whole point: a bare
// "duplicate key" tells a publisher nothing about why the hub refused.
const uniqueVersionConstraint = "version_package_semver"

// Registration is one registration request, already reduced to what the command
// needs. The HTTP layer owns the multipart form; this owns the database.
type Registration struct {
	Source       fetch.SourceKind
	URL          string
	Ref          string
	Subdirectory string

	// Publisher is the two-segment slug, `example/platform`. Namespace is its
	// first segment and is DERIVED in normalise, never supplied: it is the segment
	// the object key and the rendered package id are both built from, so a caller
	// able to set it independently could put a package's bytes under a namespace
	// its publisher does not belong to.
	Publisher string
	Namespace string
	Name      string
	Version   string

	Kind       models.PackageKind
	Category   string
	Visibility models.PackageVisibility

	// Keywords are the manifest's, known only for an upload. They seed
	// version.tags so the catalog can filter a version the fetcher has not
	// finished yet; the fetcher rewrites them from the authoritative manifest.
	Keywords []string

	ArchiveName string
	Archive     []byte

	// Preview is the upload path's pre-submit report, carried through so the
	// response can show what was accepted.
	Preview *contract.PackagePreview
}

// RegisterPackage is T042: publisher, package, version, the `fetch` job and the
// audit row, in ONE transaction.
//
// The transaction is not a tidiness preference. The R5 idempotency key for a
// fetch is (fetch, version id, semver) evaluated against the VERSION ROW, so the
// row has to exist before the job that fills it in is enqueued — and an outbox
// row that commits without its version would be a job with nothing to work on,
// while a version that commits without its job would be a version nothing ever
// fetches. Neither is recoverable by retrying.
//
// Nothing here writes bytes. `worker fetcher` is the only role that may
// (principle II), so the archive travels in the outbox payload.
func RegisterPackage(ctx context.Context, db bun.IDB, p auth.Principal, in Registration) (contract.PackageRegistered, error) {
	in, err := in.normalise()
	if err != nil {
		return contract.PackageRegistered{}, err
	}

	ref := blob.VersionRef{Namespace: in.Namespace, Name: in.Name, Semver: in.Version}
	if refErr := ref.Validate(); refErr != nil {
		return contract.PackageRegistered{}, fmt.Errorf("%w: %w", ErrRegistration, refErr)
	}
	sortKey, err := models.SemverSort(in.Version)
	if err != nil {
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
		pkg, txErr := upsertPackage(ctx, tx, publisherID, categoryID, in)
		if txErr != nil {
			return txErr
		}
		out.PackageID = pkg.ID.String()
		out.Kind = string(pkg.Kind)

		version := &models.Version{
			ID:         models.NewID(),
			PackageID:  pkg.ID,
			Semver:     in.Version,
			SemverSort: sortKey,
			ObjectKey:  ref.BundleKey(),
			// manifest is NOT NULL and the authoritative manifest is in bytes the
			// hub has not fetched yet, so it starts empty and the fetcher transcribes
			// the real one (data-model.md). digest stays null, which the
			// `digest is not null or verdict = 'scanning'` check permits and which is
			// what makes this row answer the fetch idempotency question.
			Manifest: json.RawMessage(`{}`),
			Tags:     in.Keywords,
			DistTag:  models.DistTagNone,
			Verdict:  models.VerdictScanning,
			Visible:  false,
		}
		if version.Tags == nil {
			version.Tags = []string{}
		}
		if _, insertErr := tx.NewInsert().Model(version).Exec(ctx); insertErr != nil {
			if isUniqueViolation(insertErr, uniqueVersionConstraint) {
				// FR-007 and US1 scenario 4. The rollback is what leaves the stored
				// version untouched: no object key is rewritten, no digest is
				// cleared, and no fetch job is enqueued that could overwrite bytes.
				return fmt.Errorf("%w: %s@%s", ErrImmutable, ref.Package(), in.Version)
			}
			return fmt.Errorf("create version %s: %w", ref, insertErr)
		}
		out.VersionID = version.ID.String()

		job := fetcher.Job{
			VersionID: version.ID,
			PackageID: pkg.ID,
			Namespace: in.Namespace,
			Name:      in.Name,
			Semver:    in.Version,
			Source: fetcher.JobSource{
				Kind:         in.Source,
				URL:          in.URL,
				Ref:          in.Ref,
				Subdirectory: in.Subdirectory,
				ArchiveName:  in.ArchiveName,
				Archive:      in.Archive,
			},
		}
		outboxJob, txErr := job.OutboxJob()
		if txErr != nil {
			return fmt.Errorf("%w: %w", ErrRegistration, txErr)
		}
		if _, enqueueErr := (outbox.Writer{}).Enqueue(ctx, tx, outboxJob); enqueueErr != nil {
			return fmt.Errorf("enqueue the fetch of %s: %w", ref, enqueueErr)
		}

		actor := p.Email
		if actor == "" {
			actor = p.Subject
		}
		text := fmt.Sprintf("registered %s from %s", ref, describeRegistrationSource(in))
		return writeAudit(ctx, tx, models.AuditKindFetch, actor, string(models.ActorKindIdentity),
			text, p.Source)
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
		// No source carries a publisher: a repository has an owner, an archive URL
		// has a host, and neither is a namespace this hub chose. Guessing one would
		// make the object key — which is permanent — a guess.
		return in, fmt.Errorf("%w: a registration needs a publisher", ErrRegistration)
	}

	// The two-segment shape is load-bearing rather than stylistic. The namespace is
	// the first segment and nothing else; `publisher_slug_is_two_segments` in the
	// schema says the same thing, and this is the same rule stated where the caller
	// can be told what is wrong with their input rather than reading a 23514.
	namespace, team, ok := strings.Cut(in.Publisher, "/")
	if !ok || namespace == "" || team == "" || strings.Contains(team, "/") {
		return in, fmt.Errorf(
			"%w: a publisher is <namespace>/<team>, for example example/platform, not %q",
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
	return in, nil
}

// deriveFromURL is what the import modal shows as a default: the repository name
// becomes the package name and the ref becomes the version. Both are only
// defaults — the manifest is the authority on the name, and the fetcher refuses a
// tree whose manifest disagrees.
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

func describeRegistrationSource(in Registration) string {
	switch in.Source {
	case fetch.SourceUpload:
		if in.ArchiveName != "" {
			return "upload " + in.ArchiveName
		}
		return "an upload"
	default:
		described := string(in.Source) + " " + in.URL
		if in.Ref != "" {
			described += "@" + in.Ref
		}
		if in.Subdirectory != "" {
			described += " (" + in.Subdirectory + ")"
		}
		return described
	}
}

// upsertPublisher creates the namespace on first use. `verified` is left alone:
// it is a catalog admin's decision and is never inferred from a registration
// (data-model.md).
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

// resolveCategory looks up an admin-curated category by name or slug (FR-049). An
// unknown one is refused rather than created: the vocabulary is curated, so a
// registration that could add to it would not be.
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

// upsertPackage finds or creates the named package.
//
// The kind written here is provisional for a URL source and authoritative for an
// upload, and either way the fetcher is the one that settles it: kind is decided
// by which manifest sits at the tree root, which is knowable only once the bytes
// are in hand. An EXISTING package keeps its kind — a package does not change
// from a plugin into a skill between versions.
func upsertPackage(ctx context.Context, tx bun.IDB, publisherID uuid.UUID, categoryID *uuid.UUID, in Registration) (*models.Package, error) {
	// Looked up by (namespace, name), which is what `unique (namespace, name)`
	// keys on — not by (publisher_id, name). Two teams in one namespace cannot both
	// own a name, so a lookup scoped to the publisher would miss a package owned by
	// a sibling team and turn a nameable conflict into a 23505 from the insert.
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
	if _, err := tx.NewInsert().Model(pkg).Exec(ctx); err != nil {
		return nil, fmt.Errorf("create package %s: %w", in.Name, err)
	}
	return pkg, nil
}

// isUniqueViolation reports whether err is Postgres 23505 on the named
// constraint. The sqlstate is checked and not the message: a message is
// localised and reworded between releases, and a check on the wrong constraint
// would turn some other collision into a false immutability refusal.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}
