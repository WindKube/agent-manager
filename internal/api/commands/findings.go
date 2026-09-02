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

// Adjudicating a scanner finding (001 FR-028, FR-029, US4 scenarios 3 and 4).
//
// Two commands that are NOT one command with a flag. Accept records a bounded
// human exception: the finding is approved, an override carries the reviewer, the
// note and an expiry, and the version stays flagged so the org gate still governs
// whether it resolves. Reject is terminal: the version's verdict becomes
// `rejected`, which no gate can let through and which is never served at all
// (FR-029). One function with a boolean would put those two sentences in the same
// body and invite exactly the shared code path that lets an accept set a verdict
// or a reject grow an expiry.
//
// Both write ONE audit row of kind `approve`, and reject's reuse of that kind is
// a schema fact rather than a preference: `audit_kind` has no `reject` value,
// adding one is `alter type ... add value` — a migration this feature does not
// carry (data-model.md: no schema change) — and models_test asserts the Go value
// set against pg_enum. `approve` is the adjudication kind here, and the row's
// text is what separates the two halves of it, which is what the audit screen
// renders anyway. device.go refused to add a `deny` kind for the same reason.

// ErrFindingNotFound is returned when there is no such finding.
var ErrFindingNotFound = errors.New("no such finding")

// ErrFindingRejected is returned when a decision is asked of a finding that has
// already been rejected.
//
// Rejection is terminal, so this is not a state an accept may move out of. An
// "un-reject" is a real operation with real consequences — it would make a
// version resolvable again — and it belongs to whoever designs the reversal, with
// its own audit trail. Silently treating an accept as one is the failure this
// sentinel exists to prevent.
var ErrFindingRejected = errors.New("this finding was rejected, which is terminal")

// ErrNoReviewer is returned when the caller carries no identity row to record as
// the reviewer. `override.reviewer_identity_id` is NOT NULL and points at
// `identity` on purpose: an override recorded against nobody is an exception with
// no one accountable for it.
var ErrNoReviewer = errors.New("accepting a finding needs an identity to record as the reviewer")

// ErrDecisionIncomplete is returned when the request cannot be acted on as
// submitted — today, an accept with no note.
var ErrDecisionIncomplete = errors.New("the decision is incomplete")

// Override lifetimes. An acceptance is bounded rather than open-ended: FR-028
// asks for an expiry, and `expires_at` is nullable only because the column
// predates the requirement. Nothing here writes a null one.
//
// The default is 30 days and lives here rather than in `org_policy` because that
// table has no column for it and this feature adds no migration. When it grows
// one, this constant is what the policy replaces — and until then a caller that
// wants the design's twelve days says so.
const (
	DefaultOverrideDays = 30
	MaxOverrideDays     = 365
	maxDecisionNote     = 2000
)

// Decision is one adjudication request.
type Decision struct {
	FindingID uuid.UUID
	// Note is why. Required on an accept and optional on a reject; both are
	// truncated rather than refused, because a note that fails a length check
	// after a reviewer has typed it loses the decision along with the text.
	Note string
	// Days is how long an acceptance lasts. Ignored by Reject, which has no
	// expiry to set.
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

// subject is the finding and what it is a finding about, read once under a row
// lock so every branch below decides against the same state.
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

// lockSubjectSQL reads the finding and its subject version, locking the FINDING
// row and nothing else.
//
// `for update of fnd` closes the gap between deciding and writing: two reviewers
// acting on the same finding at the same instant would otherwise both read `open`
// and both write, producing two audit rows for one transition and breaking
// SC-111's exactly-one. The second one now waits, re-reads `approved` or
// `rejected`, and is answered accordingly. Same pattern as the fetcher's publish
// lock, and it locks only `fnd` because locking the package would serialise every
// decision about every version of it.
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

// AcceptFinding approves a finding and records the override that permits it
// (T065, 001 US4 scenario 3).
//
// The finding's state, the override row and one audit row, in ONE transaction.
// Not a tidiness preference: an override that committed without its finding state
// would permit a version nothing shows as accepted, a state change that committed
// without its override would permit it with nobody accountable, and an audit row
// that committed without either would say a decision was taken that was not.
//
// The version's verdict is deliberately NOT touched. US4 scenario 3 says the
// version "becomes distributable SUBJECT TO THE GATE", and the override is what
// the gate reads — rewriting the verdict to `clean` would make an accepted
// version indistinguishable from one that never had a finding, under every gate,
// for ever.
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
			// Belt and braces over the row lock above: if the lock is ever lost in a
			// refactor, the terminal state is still refused by the database rather
			// than by a Go branch a concurrent decision could have raced past.
			Where("id = ? and state <> ?", in.FindingID, models.FindingStateRejected).
			Exec(ctx)
		if txErr != nil {
			return fmt.Errorf("approve finding %s: %w", in.FindingID, txErr)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return ErrFindingRejected
		}

		// An upsert, because re-approving is what a reviewer extending an expiring
		// override does, and `override` is keyed by finding_id so there is exactly
		// one row to extend. The whole decision is replaced — reviewer, note and
		// expiry — because it is a new decision and attributing it to whoever made
		// the previous one would be a false record.
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

// RejectFinding rejects a finding and quarantines its version for good (T066,
// 001 US4 scenario 4).
//
// The version's verdict becomes `rejected`, and that column is the whole
// mechanism: FR-029 says a rejected version must not be resolvable by any profile
// REGARDLESS OF GATE, and the gate is org-wide policy read at resolution time, so
// nothing a gate could say may be able to override this. `queries.BundleRef`
// already refuses to serve such a version for the same reason, independently of
// the gate.
//
// The finding's state and the version's verdict are one transaction with the
// audit row for the same reason accept's three writes are: a rejected finding
// beside a still-flagged version is a version a profile can adopt while the
// screen says it was refused.
//
// No override row is written and none is removed. A finding that was accepted and
// is now rejected keeps its override row, and that is deliberate twice over:
// `am_api` holds no DELETE on the table — the grants are the argument — and the
// row is the record of a decision that really was taken. It stops counting as
// active because the summary's count is guarded on `finding.state = 'approved'`,
// and it can permit nothing because the verdict is terminal.
func RejectFinding(ctx context.Context, db bun.IDB, p auth.Principal, in Decision) (contract.FindingDecision, error) {
	in = in.normalise()

	var out contract.FindingDecision
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		found, txErr := lockSubject(ctx, tx, in.FindingID)
		if txErr != nil {
			return txErr
		}
		if !found.hasBytes {
			// `check (digest is not null or verdict = 'scanning')` is FR-008's
			// commit-last rule in the schema: a version with no bytes may only be
			// `scanning`, so moving this one to `rejected` would be refused by the
			// constraint. It is unreachable — a finding belongs to a scan and a scan
			// reads the bundle — so this is corruption rather than a client error,
			// and it is named rather than left to surface as a constraint violation.
			return fmt.Errorf("version %s carries a finding but no digest, so it cannot be rejected",
				found.ref())
		}
		if found.state == models.FindingStateRejected {
			// The same refusal Accept makes, for the same reason and with the same
			// sentinel. Rejection is terminal, so a second one is not a second
			// decision — and without this the state stayed right while the record
			// went wrong: both updates re-ran and a second `approve`-domain audit row
			// landed, so the log showed two rejections of one finding by whoever
			// double-clicked. An audit log that invents decisions is worse than one
			// that misses them, because the extra row is indistinguishable from a
			// real one.
			return ErrFindingRejected
		}

		res, txErr := tx.NewUpdate().Model((*models.Finding)(nil)).
			Set("state = ?", models.FindingStateRejected).
			Set("updated_at = now()").
			// Belt and braces over the row lock, exactly as Accept does it: the
			// terminal state is refused by the database and not only by the branch
			// above, so a lost lock in some later refactor cannot let two concurrent
			// rejections both write.
			Where("id = ? and state <> ?", in.FindingID, models.FindingStateRejected).
			Exec(ctx)
		if txErr != nil {
			return fmt.Errorf("reject finding %s: %w", in.FindingID, txErr)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return ErrFindingRejected
		}

		// `verdict` alone. `version` carries no updated_at column and deliberately
		// does not: the row is append-only apart from this one field, which is why
		// the scanner's grant on the table is column-scoped to it.
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

// writeDecisionAudit writes the one row both decisions are accountable for. One
// helper rather than two call sites so the two can never come to disagree about
// the kind or the actor (SC-111).
func writeDecisionAudit(ctx context.Context, tx bun.IDB, p auth.Principal, text string) error {
	actor := p.Email
	if actor == "" {
		actor = p.Subject
	}
	return writeAudit(ctx, tx, models.AuditKindApprove, actor, string(models.ActorKindIdentity),
		text, p.Source)
}
