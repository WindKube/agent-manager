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

// ReportSync records one completed sync: one sync_event and one audit row of
// kind `sync`, in one transaction (FR-050, R8).
//
// One call per sync and not per package. Install counts are aggregated
// server-side from the revision's contents by the nightly job, so a catalog read
// never writes.
//
// The reported targets are not stored: FR-039 makes targets a client-side
// concern, so they land in the audit text where they explain the event and
// nowhere else where they could be mistaken for server state.
func ReportSync(ctx context.Context, db bun.IDB, p auth.Principal, in contract.SyncReport) error {
	if in.Profile == "" || in.Host == "" {
		return fmt.Errorf("sync report needs a profile and a host")
	}

	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// Resolved inside the transaction and under the same FR-044 predicate as
		// every read: a sync cannot be reported against a profile the caller
		// could not have read in the first place.
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
