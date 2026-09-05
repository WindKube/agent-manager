package fetcher

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"agent-manager/internal/blob"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/store/models"
)

// auditActor and auditSource are what a background role writes into the
// audit log: actor_kind `system` separates a role's action from a person's.
const (
	auditActor  = RoleName
	auditSource = "system"
)

// writeFetchAudit inserts the one audit row a fetch is accountable for. It
// takes a transaction rather than a pool: on the success path that is the
// publish transaction, so the record cannot survive a rolled back publish or
// go missing after a committed one.
func writeFetchAudit(ctx context.Context, tx bun.IDB, text string) error {
	event := &models.AuditEvent{
		ID:        models.NewID(),
		Actor:     auditActor,
		ActorKind: models.ActorKindSystem,
		Kind:      models.AuditKindFetch,
		Text:      text,
		Source:    auditSource,
	}
	// am_fetcher holds INSERT-only on audit_event — no SELECT — and bun appends
	// RETURNING for OccurredAt's `default:` tag unless told not to.
	if _, err := tx.NewInsert().Model(event).Returning("NULL").Exec(ctx); err != nil {
		return fmt.Errorf("write the fetch audit row: %w", err)
	}
	return nil
}

// auditFailure records a fetch that produced no bytes. It runs on its own
// statement rather than inside a transaction, since the transaction it would
// have belonged to is the one that did not happen.
func (w *Worker) auditFailure(ctx context.Context, job Job, reason Reason, cause error) error {
	text := fmt.Sprintf("failed to fetch %s from %s: %s", job, describeSource(job.Source), reason)
	detail := ""
	if cause != nil {
		detail = firstLine(cause.Error())
		text += " (" + detail + ")"
	}
	if err := writeFetchAudit(ctx, w.deps.DB, text); err != nil {
		return err
	}
	if outcome, ok := outcomeOf(reason); ok {
		return writeFetchAttempt(ctx, w.deps.DB, job, outcome, detail)
	}
	return nil
}

func writeFetchAttempt(ctx context.Context, tx bun.IDB, job Job, outcome models.FetchOutcome, detail string) error {
	attempt := &models.FetchAttempt{
		ID:           models.NewID(),
		SourceKind:   models.FetchSourceKind(job.Source.Kind),
		RequestedRef: describeSource(job.Source),
		Outcome:      outcome,
		Detail:       detail,
	}
	if _, err := tx.NewInsert().Model(attempt).Returning("NULL").Exec(ctx); err != nil {
		return fmt.Errorf("write the fetch attempt row: %w", err)
	}
	return nil
}

// outcomeOf maps a failure to the outcome the storage screen reports; an
// internal failure is not a fetch outcome and records nothing.
func outcomeOf(reason Reason) (models.FetchOutcome, bool) {
	switch reason {
	case ReasonRefused:
		return models.FetchOutcomeBlocked, true
	case ReasonRefNotFound:
		return models.FetchOutcomeInvalidRef, true
	case ReasonCredentials, ReasonRemote:
		return models.FetchOutcomeUnreachable, true
	case ReasonUnsupported, ReasonArchiveMalformed, ReasonManifestInvalid, ReasonVersionMismatch:
		return models.FetchOutcomeMalformed, true
	case ReasonArchiveTooLarge:
		return models.FetchOutcomeTooLarge, true
	case ReasonArchiveMemberRejected:
		return models.FetchOutcomeRejectedMember, true
	case ReasonArchiveTimeout:
		return models.FetchOutcomeExtractTimeout, true
	}
	return "", false
}

// storedText is the audit line: what was stored, from where, and what it
// turned out to contain.
func storedText(job Job, pkg *pkgspec.Package, commit blob.Commit) string {
	text := fmt.Sprintf("stored %s (%s) from %s, digest sha256:%s, %d bytes",
		job, pkg.Kind, describeSource(job.Source),
		hex.EncodeToString(commit.Bundle.Digest[:]), commit.Bundle.Size)

	if n := len(pkg.Components); n > 0 {
		text += fmt.Sprintf(", %d %s", n, plural(n, "component"))
	}
	if n := len(pkg.Layout.Dropped); n > 0 {
		text += fmt.Sprintf(", %d %s dropped as outside the spec layout", n, plural(n, "path"))
	}
	return text
}

// describeSource names where a fetch went without reproducing a credential.
func describeSource(source JobSource) string {
	switch {
	case source.URL != "":
		described := string(source.Kind) + " " + redactCredentials(source.URL)
		if source.Ref != "" {
			described += "@" + source.Ref
		}
		if source.Subdirectory != "" {
			described += " (" + source.Subdirectory + ")"
		}
		return described
	case source.ArchiveName != "":
		return "upload " + source.ArchiveName
	default:
		return string(source.Kind)
	}
}

// redactCredentials strips userinfo from a URL. It is a string operation
// rather than a parse: a URL that will not parse must still be redacted.
func redactCredentials(raw string) string {
	scheme := ""
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme, raw = raw[:i+3], raw[i+3:]
	}
	host := raw
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		host = raw[:i]
	}
	if i := strings.LastIndex(host, "@"); i >= 0 {
		raw = "redacted@" + raw[i+1:]
	}
	return scheme + raw
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func plural(n int, singular string) string {
	if n == 1 {
		return singular
	}
	return singular + "s"
}
