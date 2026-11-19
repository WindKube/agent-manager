// Package commands is the write side of the api role. A command runs its
// domain logic and writes its audit row inside one transaction, so a state
// change and the record of who caused it commit together or not at all.
package commands

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"agent-manager/internal/auth"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

// writeAudit inserts the one audit row a command is accountable for. It
// takes the transaction rather than a pool, so the write can't outlive or
// outlast the command's own commit/rollback.
func writeAudit(ctx context.Context, tx bun.IDB, a audit.Entry) error {
	event, err := audit.New(a)
	if err != nil {
		return err
	}
	if _, err := tx.NewInsert().Model(event).Exec(ctx); err != nil {
		return fmt.Errorf("write %s audit row: %w", a.Kind, err)
	}
	return nil
}

// identityAudit is the row a person's command writes: the email where the
// principal has one, the subject otherwise.
func identityAudit(p auth.Principal, kind models.AuditKind, action, text string, subject audit.Subject) audit.Entry {
	return audit.Entry{
		Kind: kind, Action: action, Actor: memberRef(p), ActorKind: models.ActorKindIdentity,
		Text: text, Source: p.Source, Subject: subject,
	}
}
