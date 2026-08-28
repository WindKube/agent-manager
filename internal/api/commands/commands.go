// Package commands is the write side of the api role (constitution principle
// VIII). A command runs its domain logic inside ONE transaction and writes its
// audit row inside that same transaction, so a state change and the record of
// who caused it commit together or not at all (principle IV, FR-050).
//
// Command/query separation here is a code boundary and nothing more: no command
// bus, no event sourcing, no separate write database. The constitution rejects
// CQRS-as-architecture, so nothing in this package builds toward one.
package commands

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"agent-manager/internal/store/models"
)

// writeAudit inserts the one audit row a command is accountable for.
//
// It takes the transaction rather than a pool: an audit write that could happen
// outside the command's transaction is an audit row that can survive a rolled
// back mutation, or go missing after a committed one.
//
// T042 introduces internal/audit and this becomes its Writer. Until then the
// insert lives beside the commands that must not commit without it.
//
// actorKind is `identity` at every call site in this package today, because every
// command here runs on behalf of a person. It stays a parameter rather than
// becoming a constant: actor_kind's other value is `system`, which
// internal/worker/fetcher already writes, and the first request-path row with no
// person behind it — a scheduled expiry, a policy default — must be able to say
// so. A hard-coded `identity` would silently label it as somebody's act, which is
// the one thing an audit log must not do.
//
//nolint:unparam // see above: the constant argument is today's call sites, not the contract.
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
