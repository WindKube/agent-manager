package commands

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

// Both finding decisions write an audit row of kind `approve`, since
// `audit_kind` has no `reject` value.

var ErrFindingNotFound = errors.New("no such finding")

// ErrFindingRejected: rejection is terminal.
var ErrFindingRejected = errors.New("this finding was rejected, which is terminal")

var ErrNoReviewer = errors.New("accepting a finding needs an identity to record as the reviewer")

var ErrDecisionIncomplete = errors.New("the decision is incomplete")

// Override lifetimes: an acceptance is bounded, never open-ended.
const (
	DefaultOverrideDays = 30
	MaxOverrideDays     = 365
	maxDecisionNote     = 2000
)

// Decision is one adjudication request.
type Decision struct {
	FindingID uuid.UUID
	// Note is required on an accept, optional on a reject; a long note is
	// truncated rather than refused so the decision isn't lost.
	Note string
	// Days is ignored by Reject, which has no expiry to set.
	Days int
}

func (d Decision) normalise() Decision {
	d.Note = strings.TrimSpace(d.Note)
	if len(d.Note) > maxDecisionNote {
		d.Note = d.Note[:maxDecisionNote]
	}
	if d.Days < 1 {
		d.Days = DefaultOverrideDays
	}
	if d.Days > MaxOverrideDays {
		d.Days = MaxOverrideDays
	}
	return d
}

// subject is the finding and what it's about, read once under a row lock
// so every branch below decides against the same state.
type subject struct {
	state     models.FindingState
	ruleID    string
	versionID uuid.UUID
	hasBytes  bool
	namespace string
	name      string
	semver    string
	verdict   models.Verdict
}

func (s subject) ref() string { return s.namespace + "/" + s.name + "@" + s.semver }

func (s subject) auditSubject(findingID uuid.UUID) audit.Subject {
	return audit.Finding(findingID, s.namespace, s.name, s.semver, s.ruleID)
}

// lockSubjectSQL locks only the finding row so two concurrent reviewers can't
// both read `open`, without serialising every decision about the package.
const lockSubjectSQL = `
select
  fnd.state::text,
  fnd.rule_id,
  fnd.version_id,
  ver.digest is not null,
  pkg.namespace,
  pkg.name,
  ver.semver,
  ver.verdict::text
from finding as fnd
join version as ver on ver.id = fnd.version_id
join package as pkg on pkg.id = ver.package_id
where fnd.id = ?
for update of fnd`

func lockSubject(ctx context.Context, tx bun.IDB, id uuid.UUID) (subject, error) {
	var out subject
	err := tx.QueryRowContext(ctx, lockSubjectSQL, id).Scan(&out.state, &out.ruleID,
		&out.versionID, &out.hasBytes, &out.namespace, &out.name, &out.semver, &out.verdict)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return subject{}, ErrFindingNotFound
	case err != nil:
		return subject{}, fmt.Errorf("read finding %s for a decision: %w", id, err)
	}
	return out, nil
}

// AcceptFinding approves a finding and records its bounded override. The
// version's verdict is left alone: the gate reads the override, and rewriting
// the verdict to `clean` would erase the finding.
func AcceptFinding(ctx context.Context, db bun.IDB, p auth.Principal, in Decision) (contract.FindingDecision, error) {
	in = in.normalise()
	if p.IdentityID == uuid.Nil {
		return contract.FindingDecision{}, ErrNoReviewer
	}
	if in.Note == "" {
		return contract.FindingDecision{}, fmt.Errorf("%w: an override needs a recorded reason",
			ErrDecisionIncomplete)
	}

	expires := time.Now().UTC().Add(time.Duration(in.Days) * 24 * time.Hour)
	var out contract.FindingDecision

	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		found, txErr := lockSubject(ctx, tx, in.FindingID)
		if txErr != nil {
			return txErr
		}
		if found.state == models.FindingStateRejected {
			return ErrFindingRejected
		}

		res, txErr := tx.NewUpdate().Model((*models.Finding)(nil)).
			Set("state = ?", models.FindingStateApproved).
			Set("updated_at = now()").
			// Belt and braces over the row lock.
			Where("id = ? and state <> ?", in.FindingID, models.FindingStateRejected).
			Exec(ctx)
		if txErr != nil {
			return fmt.Errorf("approve finding %s: %w", in.FindingID, txErr)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return ErrFindingRejected
		}

		// Re-approving replaces the whole decision, reviewer included, so it
		// is never attributed to the previous reviewer.
		if _, txErr = tx.NewInsert().Model(&models.Override{
			FindingID:          in.FindingID,
			ReviewerIdentityID: p.IdentityID,
			Note:               in.Note,
			ExpiresAt:          &expires,
		}).On("conflict (finding_id) do update").
			Set("reviewer_identity_id = excluded.reviewer_identity_id").
			Set("note = excluded.note").
			Set("expires_at = excluded.expires_at").
			Set("created_at = now()").
			// A new expiry earns its own notices.
			Set("expiring_notified_at = NULL").
			Set("expired_notified_at = NULL").
			Exec(ctx); txErr != nil {
			return fmt.Errorf("record the override on finding %s: %w", in.FindingID, txErr)
		}

		out = contract.FindingDecision{
			ID:        in.FindingID.String(),
			State:     string(models.FindingStateApproved),
			Verdict:   string(found.verdict),
			ExpiresAt: &expires,
		}
		audit := identityAudit(p, models.AuditKindApprove, "accepted",
			fmt.Sprintf("override granted for %s — %s", found.ref(), found.ruleID), found.auditSubject(in.FindingID))
		audit.Data = map[string]any{"expiresAt": expires.Format(time.RFC3339)}
		return writeAudit(ctx, tx, audit)
	})
	if err != nil {
		return contract.FindingDecision{}, err
	}
	return out, nil
}

// RejectFinding rejects a finding and quarantines its version for good. An
// existing override row is kept as a record; it stops counting because the
// summary counts only `state = 'approved'`.
func RejectFinding(ctx context.Context, db bun.IDB, p auth.Principal, in Decision) (contract.FindingDecision, error) {
	in = in.normalise()

	var out contract.FindingDecision
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		found, txErr := lockSubject(ctx, tx, in.FindingID)
		if txErr != nil {
			return txErr
		}
		if !found.hasBytes {
			// Unreachable per a schema constraint, so this is corruption, not a
			// client error.
			return fmt.Errorf("version %s carries a finding but no digest, so it cannot be rejected",
				found.ref())
		}
		if found.state == models.FindingStateRejected {
			// Without this, a double-click would log two rejections.
			return ErrFindingRejected
		}

		res, txErr := tx.NewUpdate().Model((*models.Finding)(nil)).
			Set("state = ?", models.FindingStateRejected).
			Set("updated_at = now()").
			Where("id = ? and state <> ?", in.FindingID, models.FindingStateRejected).
			Exec(ctx)
		if txErr != nil {
			return fmt.Errorf("reject finding %s: %w", in.FindingID, txErr)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return ErrFindingRejected
		}

		// `version` has no updated_at: it is append-only apart from verdict.
		if _, txErr = tx.NewUpdate().Model((*models.Version)(nil)).
			Set("verdict = ?", models.VerdictRejected).
			Where("id = ?", found.versionID).
			Exec(ctx); txErr != nil {
			return fmt.Errorf("quarantine version %s: %w", found.ref(), txErr)
		}

		out = contract.FindingDecision{
			ID:      in.FindingID.String(),
			State:   string(models.FindingStateRejected),
			Verdict: string(models.VerdictRejected),
		}

		text := fmt.Sprintf("rejected %s — %s", found.ref(), found.ruleID)
		if in.Note != "" {
			text += ": " + in.Note
		}
		return writeAudit(ctx, tx, identityAudit(p, models.AuditKindApprove, "rejected", text,
			found.auditSubject(in.FindingID)))
	})
	if err != nil {
		return contract.FindingDecision{}, err
	}
	return out, nil
}
