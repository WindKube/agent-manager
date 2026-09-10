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
	"agent-manager/internal/store/models"
)

// Adjudicating a scanner finding: two commands, not one with a flag.
// Accept records a bounded exception (the version stays flagged, so the
// org gate still governs it); Reject is terminal, setting the version's
// verdict to `rejected`, which no gate can let through. Both write one
// audit row of kind `approve` — `audit_kind` has no `reject` value.

var ErrFindingNotFound = errors.New("no such finding")

// ErrFindingRejected: rejection is terminal; an "un-reject" is a real
// operation with its own audit trail, not something to fall into silently.
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
	// Note is required on an accept, optional on a reject; both are
	// truncated rather than refused, so a long note doesn't lose the
	// reviewer's decision along with the text.
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
	packageID string
	semver    string
	verdict   models.Verdict
}

func (s subject) ref() string { return s.packageID + "@" + s.semver }

// lockSubjectSQL reads the finding and its subject version, locking only
// the finding row: two reviewers deciding at once would otherwise both
// read `open` and both write. Locking `fnd` alone, not the package, avoids
// serialising every decision about every version of it.
const lockSubjectSQL = `
select
  fnd.state::text,
  fnd.rule_id,
  fnd.version_id,
  ver.digest is not null,
  pkg.namespace || '/' || pkg.name,
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
		&out.versionID, &out.hasBytes, &out.packageID, &out.semver, &out.verdict)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return subject{}, ErrFindingNotFound
	case err != nil:
		return subject{}, fmt.Errorf("read finding %s for a decision: %w", id, err)
	}
	return out, nil
}

// AcceptFinding approves a finding and records the override that permits
// it — state, override row and audit row in one transaction. The
// version's verdict is deliberately not touched: the override is what the
// gate reads, and rewriting it to `clean` would erase the finding.
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
			// Belt and braces over the row lock above: the terminal state
			// stays refused by the database even if a refactor loses the lock.
			Where("id = ? and state <> ?", in.FindingID, models.FindingStateRejected).
			Exec(ctx)
		if txErr != nil {
			return fmt.Errorf("approve finding %s: %w", in.FindingID, txErr)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return ErrFindingRejected
		}

		// Upsert: re-approving extends an expiring override, keyed by
		// finding_id. The whole decision is replaced, since attributing a
		// new decision to the previous reviewer would be a false record.
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
			Exec(ctx); txErr != nil {
			return fmt.Errorf("record the override on finding %s: %w", in.FindingID, txErr)
		}

		out = contract.FindingDecision{
			ID:        in.FindingID.String(),
			State:     string(models.FindingStateApproved),
			Verdict:   string(found.verdict),
			ExpiresAt: &expires,
		}
		return writeDecisionAudit(ctx, tx, p,
			fmt.Sprintf("override granted for %s — %s", found.ref(), found.ruleID))
	})
	if err != nil {
		return contract.FindingDecision{}, err
	}
	return out, nil
}

// RejectFinding rejects a finding and quarantines its version for good:
// verdict becomes `rejected`, which no gate can override. No override row
// is written or removed — an existing one stays as the record of a
// decision really taken, and stops counting since the summary only counts
// `state = 'approved'`.
func RejectFinding(ctx context.Context, db bun.IDB, p auth.Principal, in Decision) (contract.FindingDecision, error) {
	in = in.normalise()

	var out contract.FindingDecision
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		found, txErr := lockSubject(ctx, tx, in.FindingID)
		if txErr != nil {
			return txErr
		}
		if !found.hasBytes {
			// A schema constraint requires a version with no bytes stay
			// `scanning`; unreachable in practice, so this is corruption
			// rather than a client error, named instead of surfacing as one.
			return fmt.Errorf("version %s carries a finding but no digest, so it cannot be rejected",
				found.ref())
		}
		if found.state == models.FindingStateRejected {
			// Rejection is terminal: without this guard, a double-click
			// would re-run both updates and log two rejections of one
			// finding, and an audit log that invents decisions is worse
			// than one that misses them.
			return ErrFindingRejected
		}

		res, txErr := tx.NewUpdate().Model((*models.Finding)(nil)).
			Set("state = ?", models.FindingStateRejected).
			Set("updated_at = now()").
			// Belt and braces over the row lock, as in Accept.
			Where("id = ? and state <> ?", in.FindingID, models.FindingStateRejected).
			Exec(ctx)
		if txErr != nil {
			return fmt.Errorf("reject finding %s: %w", in.FindingID, txErr)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return ErrFindingRejected
		}

		// `verdict` alone: `version` has no updated_at, since the row is
		// append-only apart from this one field.
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
		return writeDecisionAudit(ctx, tx, p, text)
	})
	if err != nil {
		return contract.FindingDecision{}, err
	}
	return out, nil
}

// writeDecisionAudit writes the one row both decisions are accountable
// for, so the two call sites can't disagree about kind or actor.
func writeDecisionAudit(ctx context.Context, tx bun.IDB, p auth.Principal, text string) error {
	actor := p.Email
	if actor == "" {
		actor = p.Subject
	}
	return writeAudit(ctx, tx, models.AuditKindApprove, actor, string(models.ActorKindIdentity),
		text, p.Source)
}
