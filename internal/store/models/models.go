// Package models holds the Bun structs that are the source of truth for the
// `agent_manager` schema. Atlas diffs them into versioned SQL, so a struct
// change is a migration. Every exported struct here is a table — the Atlas
// loader treats every one as a Bun model, so a helper struct would silently
// become a table. Enum types, check constraints and indexes have no
// struct-tag representation; they come from the migration layer.
package models

import (
	"fmt"

	"github.com/google/uuid"
)

// NewID returns a uuid v7: time-ordered, so index locality is free and rows
// sort by creation without a separate column.
func NewID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		panic(fmt.Errorf("generate uuid v7: %w", err))
	}
	return id
}

// All returns one zero pointer per table, in dependency-friendly order.
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
		(*FindingEvidence)(nil),
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
		(*FetchAttempt)(nil),

		// Job hand-off
		(*Outbox)(nil),
	}
}
