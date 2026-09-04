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

// auditActor and auditSource are what a background role writes into the audit
// log. actor_kind `system` is what separates a role's action from a person's
// (FR-050), and the actor is the role name rather than a hostname or a container
// id so the row still reads the same after a redeploy.
const (
	auditActor  = RoleName
	auditSource = "system"
)

// writeFetchAudit inserts the one audit row a fetch is accountable for.
//
// It takes a transaction rather than a pool. On the success path that is the
// publish transaction, so the record of what was stored cannot survive a rolled
// back publish or go missing after a committed one (FR-050, principle IV).
//
// audit_event is append-only and nothing here enforces that: UPDATE, DELETE and
// TRUNCATE are revoked from am_fetcher in the migration layer (FR-052).
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

// auditFailure records a fetch that produced no bytes.
//
// It runs on its own statement rather than inside a transaction, because the
// transaction it would have belonged to is the one that did not happen. The
// reason is in the text and the row's kind is `fetch`: a failed fetch is an
// ingestion event, never a `finding` row, because a finding is a statement about
// what a package does and nothing here ever read the package.
func (w *Worker) auditFailure(ctx context.Context, job Job, reason Reason, cause error) error {
	text := fmt.Sprintf("failed to fetch %s from %s: %s", job, describeSource(job.Source), reason)
	if cause != nil {
		text += " (" + firstLine(cause.Error()) + ")"
	}
	return writeFetchAudit(ctx, w.deps.DB, text)
}

// storedText is US1 scenario 6's audit line: what was stored, from where, and
// what it turned out to contain.
func storedText(job Job, pkg *pkgspec.Package, commit blob.Commit) string {
	text := fmt.Sprintf("stored %s (%s) from %s, digest sha256:%s, %d bytes",
		job, pkg.Kind, describeSource(job.Source),
		hex.EncodeToString(commit.Bundle.Digest[:]), commit.Bundle.Size)

	if n := len(pkg.Components); n > 0 {
		text += fmt.Sprintf(", %d %s", n, plural(n, "component"))
	}
	// FR-005: what the layout filter discarded is part of the record of what was
	// ingested, not a detail of the pre-submit preview.
	if n := len(pkg.Layout.Dropped); n > 0 {
		text += fmt.Sprintf(", %d %s dropped as outside the spec layout", n, plural(n, "path"))
	}
	return text
}

// describeSource names where a fetch went without reproducing a credential. A
// URL is redacted by internal/fetch on the way out; this is the same rule applied
// to the audit log, which is the copy that is kept.
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

// redactCredentials strips userinfo from a URL. It is deliberately a string
// operation on the raw value rather than a parse: a URL that will not parse must
// still be redacted, and the failure mode of a parse error here is a secret in
// the audit log forever.
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
