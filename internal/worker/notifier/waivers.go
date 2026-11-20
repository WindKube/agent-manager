package notifier

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/uptrace/bun"

	"agent-manager/internal/outbox"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

// WaiverCheck is the periodic job that raises the waiver notices.
type WaiverCheck struct{}

func (WaiverCheck) Kind() string { return "waiver-check" }

func (WaiverCheck) InsertOpts() river.InsertOpts { return river.InsertOpts{Queue: outbox.QueueNotify} }

// WaiverChecker works the `waiver-check` job.
type WaiverChecker struct {
	river.WorkerDefaults[WaiverCheck]

	db     bun.IDB
	notice time.Duration
}

func (w *WaiverChecker) Work(ctx context.Context, _ *river.Job[WaiverCheck]) error {
	_, err := CheckWaivers(ctx, w.db, w.notice)
	return err
}

type waiver struct {
	FindingID uuid.UUID `bun:"finding_id"`
	ExpiresAt time.Time `bun:"expires_at"`
	Expired   bool      `bun:"expired"`
	RuleID    string    `bun:"rule_id"`
	Namespace string    `bun:"namespace"`
	Name      string    `bun:"name"`
	Semver    string    `bun:"semver"`
}

// CheckWaivers writes one waiver-expiring audit row for each accepted finding
// whose override lapses within notice, and one waiver-expired row for each
// that has lapsed, marking each override in the same transaction so neither
// notice is raised twice for one expiry. An expired override already stops
// counting in the gate; this only says so. It returns how many rows it wrote.
func CheckWaivers(ctx context.Context, db bun.IDB, notice time.Duration) (int, error) {
	written := 0
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var due []waiver
		if err := tx.NewRaw(`select ovr.finding_id, ovr.expires_at, ovr.expires_at <= now() as expired,
				fnd.rule_id, pkg.namespace, pkg.name, ver.semver
			from override as ovr
			join finding as fnd on fnd.id = ovr.finding_id
			join version as ver on ver.id = fnd.version_id
			join package as pkg on pkg.id = ver.package_id
			where fnd.state = 'approved' and ovr.expires_at is not null
			  and ((ovr.expires_at <= now() and ovr.expired_notified_at is null)
			    or (ovr.expires_at > now() and ovr.expires_at <= now() + make_interval(secs => ?)
			        and ovr.expiring_notified_at is null))
			order by ovr.expires_at
			for update of ovr skip locked`, notice.Seconds()).Scan(ctx, &due); err != nil {
			return fmt.Errorf("find waivers due a notice: %w", err)
		}

		for _, w := range due {
			action, column := "waiver-expiring", "expiring_notified_at"
			text := fmt.Sprintf("override on %s/%s@%s — %s expires %s", w.Namespace, w.Name, w.Semver, w.RuleID,
				w.ExpiresAt.UTC().Format(time.DateOnly))
			if w.Expired {
				action, column = "waiver-expired", "expired_notified_at"
				text = fmt.Sprintf("override on %s/%s@%s — %s expired; the finding counts against the version again",
					w.Namespace, w.Name, w.Semver, w.RuleID)
			}
			event, err := audit.New(audit.Entry{
				Kind: models.AuditKindApprove, Action: action, Actor: RoleName, ActorKind: models.ActorKindSystem,
				Text: text, Source: "system",
				Subject: audit.Finding(w.FindingID, w.Namespace, w.Name, w.Semver, w.RuleID),
				Data:    map[string]any{"expiresAt": w.ExpiresAt.UTC().Format(time.RFC3339)},
			})
			if err != nil {
				return err
			}
			if _, err := tx.NewInsert().Model(event).Returning("NULL").Exec(ctx); err != nil {
				return fmt.Errorf("write the %s audit row: %w", action, err)
			}
			if _, err := tx.NewUpdate().Model((*models.Override)(nil)).
				Set("? = now()", bun.Ident(column)).
				Where("finding_id = ?", w.FindingID).Exec(ctx); err != nil {
				return fmt.Errorf("mark the %s notice on finding %s: %w", action, w.FindingID, err)
			}
			written++
		}
		return nil
	})
	return written, err
}
