package fetcher

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"

	"agent-manager/internal/blob"
	"agent-manager/internal/fetch"
	"agent-manager/internal/outbox"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

var (
	ErrRegistration = errors.New("registration refused")
	// ErrImmutable is FR-007's refusal. Which state blocked it is
	// conflictMessage's job: the row can be held by a version still being
	// fetched, or one whose fetch failed, and "published" would be a lie in
	// both.
	ErrImmutable = errors.New("this publisher/name@version cannot be registered again")
)

// uniqueVersionConstraint is named here because Postgres reports the
// constraint, not the requirement: translating 23505-on-this-index into
// ErrImmutable is what tells a publisher why the hub refused.
const uniqueVersionConstraint = "version_package_semver"

// Registrar is who a registration is attributed to in the audit log: a
// person through the api, or this role's upstream check.
type Registrar struct {
	Actor     string
	ActorKind models.ActorKind
	Source    string
	// Trigger names what started a registration nobody typed.
	Trigger string
}

// NewVersion is one version to register against a package row that exists.
type NewVersion struct {
	Semver string
	// Tags are already normalised (VersionTags).
	Tags   []string
	Source JobSource
}

// Register is the transactional half of a registration, shared by the api's
// registerPackage and the upstream check so neither can drift from the
// other: it moves the package's recorded source, inserts the invisible
// version row, enqueues its fetch and writes the audit rows, all on tx.
func Register(ctx context.Context, tx bun.IDB, by Registrar, pkg *models.Package, nv NewVersion) (uuid.UUID, error) {
	source := fetch.ProvenanceOf(fetch.SourceRef{
		Kind: nv.Source.Kind, URL: nv.Source.URL, Ref: nv.Source.Ref, Subdirectory: nv.Source.Subdirectory,
	})
	if err := recordSource(ctx, tx, by, pkg, source); err != nil {
		return uuid.Nil, err
	}

	ref := blob.VersionRef{Namespace: pkg.Namespace, Name: pkg.Name, Semver: nv.Semver}
	if err := ref.Validate(); err != nil {
		return uuid.Nil, fmt.Errorf("%w: %w", ErrRegistration, err)
	}
	sortKey, err := models.SemverSort(nv.Semver)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %w", ErrRegistration, err)
	}

	// Only so the refusal can name the state. The unique index below is
	// what enforces FR-007, and it catches the race this SELECT loses.
	existing := new(models.Version)
	switch selErr := tx.NewSelect().Model(existing).
		Where("package_id = ? and semver = ?", pkg.ID, nv.Semver).
		Scan(ctx); {
	case selErr == nil:
		return uuid.Nil, fmt.Errorf("%w: %s", ErrImmutable, conflictMessage(ref, existing))
	case !errors.Is(selErr, sql.ErrNoRows):
		return uuid.Nil, fmt.Errorf("check for an existing version of %s: %w", ref, selErr)
	}

	version := &models.Version{
		ID:         models.NewID(),
		PackageID:  pkg.ID,
		Semver:     nv.Semver,
		SemverSort: sortKey,
		ObjectKey:  ref.BundleKey(),
		// manifest starts empty (NOT NULL) since the authoritative one isn't
		// fetched yet; digest stays null, which the schema's scanning-check
		// permits.
		Manifest: json.RawMessage(`{}`),
		Tags:     nv.Tags,
		DistTag:  models.DistTagNone,
		Verdict:  models.VerdictScanning,
		Visible:  false,
	}
	if version.Tags == nil {
		version.Tags = []string{}
	}
	if source.Kind == fetch.SourceGit {
		version.SourceRef = source.Ref
	}
	if _, insertErr := tx.NewInsert().Model(version).Returning("NULL").Exec(ctx); insertErr != nil {
		if isUniqueViolation(insertErr, uniqueVersionConstraint) {
			// The SELECT above lost the race, and this transaction is already
			// aborted, so the winning row cannot be re-read for a
			// state-specific message. The rollback leaves what it stored
			// untouched: no object key rewritten, no digest cleared, no
			// fetch job enqueued over its bytes.
			return uuid.Nil, fmt.Errorf("%w: %s", ErrImmutable, conflictMessage(ref, nil))
		}
		return uuid.Nil, fmt.Errorf("create version %s: %w", ref, insertErr)
	}

	job := Job{
		VersionID: version.ID,
		PackageID: pkg.ID,
		Namespace: pkg.Namespace,
		Name:      pkg.Name,
		Semver:    nv.Semver,
		Source:    nv.Source,
	}
	outboxJob, err := job.OutboxJob()
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %w", ErrRegistration, err)
	}
	if _, enqueueErr := (outbox.Writer{}).Enqueue(ctx, tx, outboxJob); enqueueErr != nil {
		return uuid.Nil, fmt.Errorf("enqueue the fetch of %s: %w", ref, enqueueErr)
	}

	text := fmt.Sprintf("registered %s from %s", ref, describeSource(nv.Source))
	data := map[string]any{"source": string(nv.Source.Kind)}
	if by.Trigger != "" {
		text += " (" + by.Trigger + ")"
		data["trigger"] = by.Trigger
	}
	if err := writeAudit(ctx, tx, by, "registered", text, audit.Version(pkg.Namespace, pkg.Name, nv.Semver), data); err != nil {
		return uuid.Nil, err
	}
	return version.ID, nil
}

// recordSource moves the package's recorded source to this registration's.
// A new ref from the same place is the normal course of releases and is
// carried by the registration's own audit row; a different kind, URL or
// subdirectory is a change of where the package comes from and is audited.
// Moving off git ends upstream tracking, which only a git source can do.
func recordSource(ctx context.Context, tx bun.IDB, by Registrar, pkg *models.Package, source fetch.Provenance) error {
	kind := models.FetchSourceKind(source.Kind)
	moved := pkg.SourceKind != kind || pkg.SourceURL != source.URL || pkg.SourceSubdirectory != source.Subdirectory
	if !moved && pkg.SourceRef == source.Ref {
		return nil
	}

	previousKind, previousURL := pkg.SourceKind, pkg.SourceURL
	previous := describeProvenance(fetch.Provenance{
		Kind: fetch.SourceKind(pkg.SourceKind), URL: pkg.SourceURL, Subdirectory: pkg.SourceSubdirectory,
	})
	wasTracking := pkg.TrackUpstream
	pkg.SourceKind, pkg.SourceURL, pkg.SourceRef, pkg.SourceSubdirectory =
		kind, source.URL, source.Ref, source.Subdirectory
	pkg.TrackUpstream = pkg.TrackUpstream && source.Kind == fetch.SourceGit
	if _, err := tx.NewUpdate().Model(pkg).
		Column("source_kind", "source_url", "source_ref", "source_subdirectory", "track_upstream").
		Set("updated_at = now()").
		WherePK().Exec(ctx); err != nil {
		return fmt.Errorf("record the source of %s/%s: %w", pkg.Namespace, pkg.Name, err)
	}
	if !moved {
		return nil
	}

	text := fmt.Sprintf("changed the source of %s/%s from %s to %s", pkg.Namespace, pkg.Name, previous,
		describeProvenance(fetch.Provenance{Kind: source.Kind, URL: source.URL, Subdirectory: source.Subdirectory}))
	if wasTracking && !pkg.TrackUpstream {
		text += ", which ends upstream tracking"
	}
	return writeAudit(ctx, tx, by, "source-changed", text, audit.Package(pkg.Namespace, pkg.Name), map[string]any{
		"sourceKind":         string(source.Kind),
		"sourceUrl":          source.URL,
		"sourceSubdirectory": source.Subdirectory,
		"previousSourceKind": string(previousKind),
		"previousSourceUrl":  previousURL,
	})
}

func writeAudit(ctx context.Context, tx bun.IDB, by Registrar, action, text string, subject audit.Subject, data map[string]any) error {
	event, err := audit.New(audit.Entry{
		Kind:      models.AuditKindFetch,
		Action:    action,
		Actor:     by.Actor,
		ActorKind: by.ActorKind,
		Text:      text,
		Source:    by.Source,
		Subject:   subject,
		Data:      data,
	})
	if err != nil {
		return err
	}
	// am_fetcher holds INSERT-only on audit_event, so no RETURNING.
	if _, err := tx.NewInsert().Model(event).Returning("NULL").Exec(ctx); err != nil {
		return fmt.Errorf("write the %s audit row: %w", action, err)
	}
	return nil
}

func describeProvenance(source fetch.Provenance) string {
	if source.Kind == "" {
		return "no recorded source"
	}
	described := string(source.Kind)
	if source.URL != "" {
		described += " " + source.URL
	}
	if source.Subdirectory != "" {
		described += " (" + source.Subdirectory + ")"
	}
	return described
}

// conflictMessage names the state that blocks a re-registration, since FR-007
// is only actionable if it says what happened instead of asserting
// "published" for a version that never got that far. existing is nil for the
// race the insert-time catch lost, where the winning row cannot be re-read.
func conflictMessage(ref blob.VersionRef, existing *models.Version) string {
	subject := ref.String()
	switch {
	case existing == nil:
		return subject + " was just registered by another request; its bytes are immutable"
	case existing.Digest == nil:
		return subject + " is already registered; its fetch has not finished, or it failed — " +
			"check the audit log for the outcome before registering it again"
	case existing.Verdict == models.VerdictFlagged:
		return subject + " is published and was flagged by the scanner; its bytes are immutable"
	case existing.Verdict == models.VerdictRejected:
		return subject + " is published and was rejected by the scanner; its bytes are immutable"
	default:
		return subject + " is already published and its bytes are immutable"
	}
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
