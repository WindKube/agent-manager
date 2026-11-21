package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

// ReportSync records one completed sync: one sync_event and one audit row
// of kind `sync`, in one transaction. A report naming its machine also
// replaces that machine's inventory for the profile, in the same transaction.
func ReportSync(ctx context.Context, db bun.IDB, p auth.Principal, in contract.SyncReport) error {
	if in.Profile == "" || in.Host == "" {
		return fmt.Errorf("sync report needs a profile and a host")
	}

	var machineID uuid.UUID
	if in.MachineID != "" {
		id, err := uuid.Parse(in.MachineID)
		if err != nil || id == uuid.Nil {
			return fmt.Errorf("%w: machineId %q is not a uuid", ErrValidation, in.MachineID)
		}
		machineID = id
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
		if p.IsServiceToken() {
			event.IdentityID = p.ServiceToken.Creator.IdentityID
			event.ServiceTokenID = &p.ServiceToken.ID
		}
		if _, err := tx.NewInsert().Model(event).Exec(ctx); err != nil {
			return fmt.Errorf("record sync event: %w", err)
		}
		if machineID != uuid.Nil {
			by := reporter{identityID: event.IdentityID, serviceToken: event.ServiceTokenID}
			if err := recordMachine(ctx, tx, machineID, by, ref, in); err != nil {
				return err
			}
		}

		text := fmt.Sprintf("synced %s r%d to %s", in.Profile, ref.Seq, in.Host)
		if len(in.Targets) > 0 {
			text += " (" + strings.Join(in.Targets, ", ") + ")"
		}
		if n := len(in.Skipped); n > 0 {
			text += fmt.Sprintf(", %d entr%s skipped locally", n, plural(n))
		}
		audit := identityAudit(p, models.AuditKindSync, "synced", text,
			audit.Revision(ref.RevisionID, ref.ProfileID, in.Profile, ref.Seq))
		audit.Source = auth.CLISource(in.Host)
		audit.Data = map[string]any{"host": in.Host, "targets": append([]string{}, in.Targets...)}
		if machineID != uuid.Nil {
			audit.Data["machineId"] = machineID.String()
		}
		if p.IsServiceToken() {
			audit.Data["serviceTokenId"] = p.ServiceToken.ID.String()
		}
		return writeAudit(ctx, tx, audit)
	})
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
