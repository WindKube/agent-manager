// Package models holds the Bun structs that are the source of truth for the
// `agent_manager` schema; Atlas diffs them into versioned SQL.
//
// The Atlas loader treats every exported struct here as a table, so never add
// a helper struct to this package.
package models

import (
	"fmt"

	"github.com/google/uuid"
)

// NewID returns a time-ordered uuid v7, for index locality and creation-order sorting.
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
		(*ServiceToken)(nil),

		// Governance
		(*OrgPolicy)(nil),
		(*AuditEvent)(nil),
		(*SyncEvent)(nil),
		(*FetchAttempt)(nil),

		// Fleet inventory
		(*Machine)(nil),
		(*MachineInstall)(nil),
		(*MachineSkip)(nil),

		// Webhooks
		(*WebhookSubscription)(nil),
		(*WebhookDelivery)(nil),
		(*WebhookDispatch)(nil),

		// Job hand-off
		(*Outbox)(nil),
	}
}
