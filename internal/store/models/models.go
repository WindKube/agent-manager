// Package models holds the Bun structs that are the source of truth for the
// `agent_manager` schema. Atlas diffs them into versioned SQL via
// ariga.io/atlas-provider-bun, so a struct change is a migration.
//
// Two rules this package lives by:
//
//   - Every exported struct here is a table. The Atlas loader treats every
//     exported struct in this package as a Bun model, so a helper struct would
//     silently become a table. Helpers are unexported or are functions.
//   - Bun emits columns, primary keys, unique constraints and foreign keys, and
//     nothing else. Enum types, check constraints, partial and GIN indexes,
//     generated columns and grants have no struct-tag representation; they come
//     from the migration layer (T015-T017). EnumDDL is exported so at least the
//     enum values cannot drift from the Go const sets.
package models

import (
	"fmt"

	"github.com/google/uuid"
)

// NewID returns a uuid v7: time-ordered, so index locality is free and rows sort
// by creation without a separate column.
//
// uuid.NewV7 fails only if crypto/rand fails, which is not a condition this
// layer can sensibly report or recover from.
func NewID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		panic(fmt.Errorf("generate uuid v7: %w", err))
	}
	return id
}

// All returns one zero pointer per table, in dependency-friendly order. Both
// store.Open and the Atlas loader register exactly this list, so a table that is
// missing here is missing from the schema.
func All() []any {
	return []any{
		// Catalog
		(*Publisher)(nil),
		(*Category)(nil),
		(*Package)(nil),
		(*Version)(nil),
		(*VersionTag)(nil),
		(*Component)(nil),
		(*Capability)(nil),
		(*Signature)(nil),

		// Scanning
		(*Scan)(nil),
		(*ScanCheck)(nil),
		(*Finding)(nil),
		(*Override)(nil),

		// Profiles
		(*Profile)(nil),
		(*ProfileEntry)(nil),
		(*Revision)(nil),
		(*Membership)(nil),
		(*SyncTarget)(nil),

		// Identity
		(*Identity)(nil),
		(*GroupRoleMap)(nil),
		(*DeviceAuthorization)(nil),
		(*Session)(nil),

		// Governance
		(*OrgPolicy)(nil),
		(*AuditEvent)(nil),
		(*SyncEvent)(nil),

		// Job hand-off
		(*Outbox)(nil),
	}
}
