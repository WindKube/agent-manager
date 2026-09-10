// Package commands is the write side of the api role. A command runs its
// domain logic and writes its audit row inside one transaction, so a state
// change and the record of who caused it commit together or not at all.
package commands

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"agent-manager/internal/store/models"
)

// writeAudit inserts the one audit row a command is accountable for. It
// takes the transaction rather than a pool, so the write can't outlive or
// outlast the command's own commit/rollback.
//
// actorKind stays a parameter rather than a hard-coded `identity`: a future
// system-triggered row (a scheduled expiry, a policy default) must be able
// to say so instead of silently being mislabelled as a person's act.
//
//nolint:unparam // actorKind is always identity at today's call sites, not the contract.
func writeAudit(ctx context.Context, tx bun.IDB, kind models.AuditKind, actor, actorKind, text, source string) error {
	if !kind.Valid() {
		return fmt.Errorf("audit kind %q is not a value the schema allows", kind)
	}
	event := &models.AuditEvent{
		ID:        models.NewID(),
		Actor:     actor,
		ActorKind: models.ActorKind(actorKind),
		Kind:      kind,
		Text:      text,
		Source:    source,
	}
	if _, err := tx.NewInsert().Model(event).Exec(ctx); err != nil {
		return fmt.Errorf("write %s audit row: %w", kind, err)
	}
	return nil
}
