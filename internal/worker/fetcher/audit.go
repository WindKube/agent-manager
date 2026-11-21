package fetcher

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"agent-manager/internal/blob"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/signing"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

// auditActor and auditSource mark a background role's audit rows as `system`.
const (
	auditActor  = RoleName
	auditSource = "system"
)

// writeFetchAudit inserts a fetch's audit row. On success tx is the publish
// transaction, so the record commits or rolls back with it.
func writeFetchAudit(ctx context.Context, tx bun.IDB, job Job, action, text string, data map[string]any) error {
	event, err := audit.New(audit.Entry{
		Kind:      models.AuditKindFetch,
		Action:    action,
		Actor:     auditActor,
		ActorKind: models.ActorKindSystem,
		Text:      text,
		Source:    auditSource,
		Subject:   audit.Version(job.Namespace, job.Name, job.Semver),
		Data:      data,
	})
	if err != nil {
		return err
	}
	// am_fetcher holds INSERT-only on audit_event, and bun would otherwise add RETURNING.
	if _, err := tx.NewInsert().Model(event).Returning("NULL").Exec(ctx); err != nil {
		return fmt.Errorf("write the fetch audit row: %w", err)
	}
	return nil
}

// auditFailure records a fetch that produced no bytes, outside any transaction.
func (w *Worker) auditFailure(ctx context.Context, job Job, reason Reason, cause error) error {
	text := fmt.Sprintf("failed to fetch %s from %s: %s", job, describeSource(job.Source), reason)
	detail := ""
	if cause != nil {
		detail = firstLine(cause.Error())
		text += " (" + detail + ")"
	}
	data := map[string]any{"reason": string(reason)}
	var moved *TagMovedError
	if errors.As(cause, &moved) {
		data["sourceRef"], data["previousCommit"], data["commit"] = moved.Tag, moved.From, moved.To
	}
	if err := writeFetchAudit(ctx, w.deps.DB, job, "fetch-failed", text, data); err != nil {
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
	case ReasonRefNotFound, ReasonTagMoved:
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

// storedText is the audit line for a stored version.
func storedText(job Job, pkg *pkgspec.Package, commit blob.Commit, sig signing.Result) string {
	text := fmt.Sprintf("stored %s (%s) from %s, digest sha256:%s, %d bytes",
		job, pkg.Kind, describeSource(job.Source),
		hex.EncodeToString(commit.Bundle.Digest[:]), commit.Bundle.Size)

	if n := len(pkg.Components); n > 0 {
		text += fmt.Sprintf(", %d %s", n, plural(n, "component"))
	}
	if n := len(pkg.Layout.Dropped); n > 0 {
		text += fmt.Sprintf(", %d %s dropped as outside the spec layout", n, plural(n, "path"))
	}
	if n := len(pkg.Layout.Links); n > 0 {
		text += fmt.Sprintf(", %d %s not stored", n, plural(n, "link"))
	}
	return text + ", " + signatureText(sig)
}

func signatureText(sig signing.Result) string {
	switch sig.Status {
	case signing.StatusVerified:
		return fmt.Sprintf("signature verified: %s via %s", sig.Identity, sig.Issuer)
	case signing.StatusInvalid:
		return "signature invalid: " + firstLine(sig.Reason)
	default:
		return "unsigned"
	}
}

func storedData(pkg *pkgspec.Package, commit blob.Commit, sig signing.Result) map[string]any {
	data := map[string]any{
		"digest":     "sha256:" + hex.EncodeToString(commit.Bundle.Digest[:]),
		"sizeBytes":  commit.Bundle.Size,
		"kind":       string(pkg.Kind),
		"components": len(pkg.Components),
		"signature":  string(sig.Status),
	}
	if sig.Status == signing.StatusVerified {
		data["signerIssuer"], data["signerIdentity"] = sig.Issuer, sig.Identity
	}
	return data
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

// redactCredentials strips userinfo from a URL without parsing it, so an
// unparseable URL is still redacted.
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
