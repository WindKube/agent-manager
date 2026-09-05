package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// ReportSync records one completed sync: one sync_event and one audit row
// of kind `sync`, in one transaction. One call per sync, not per package —
// install counts are aggregated server-side by the nightly job. Reported
// targets are not stored, only named in the audit text, so they can't be
// mistaken for server state.
func ReportSync(ctx context.Context, db bun.IDB, p auth.Principal, in contract.SyncReport) error {
	if in.Profile == "" || in.Host == "" {
		return fmt.Errorf("sync report needs a profile and a host")
	}

	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// Resolved under the same readability predicate as every read: a
		// sync can't be reported against a profile the caller couldn't read.
		ref, err := queries.ReadableRevisionRef(ctx, tx, p, in.Profile, in.Revision)
		if err != nil {
			return err
		}

		event := &models.SyncEvent{
			ID:         models.NewID(),
			IdentityID: p.IdentityID,
			ProfileID:  ref.ProfileID,
			RevisionID: ref.RevisionID,
			Host:       in.Host,
		}
		if _, err := tx.NewInsert().Model(event).Exec(ctx); err != nil {
			return fmt.Errorf("record sync event: %w", err)
		}

		actor := p.Email
		if actor == "" {
			actor = p.Subject
		}
		text := fmt.Sprintf("synced %s r%d to %s", in.Profile, ref.Seq, in.Host)
		if len(in.Targets) > 0 {
			text += " (" + strings.Join(in.Targets, ", ") + ")"
		}
		if n := len(in.Skipped); n > 0 {
			text += fmt.Sprintf(", %d entr%s skipped locally", n, plural(n))
		}
		return writeAudit(ctx, tx, models.AuditKindSync, actor, string(models.ActorKindIdentity),
			text, auth.CLISource(in.Host))
	})
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
