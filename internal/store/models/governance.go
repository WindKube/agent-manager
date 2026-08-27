package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// OrgPolicySingletonID is the only id org_policy may hold.
const OrgPolicySingletonID int32 = 1

// OrgPolicy is a singleton: one organisation per deployment. The migration layer
// carries `check (id = 1)`, which is what makes it a singleton at the schema
// level rather than by convention.
type OrgPolicy struct {
	bun.BaseModel `bun:"table:org_policy,alias:pol"`

	ID                    int32         `bun:"id,pk,type:integer,notnull"`
	ScanGate              ScanGate      `bun:"scan_gate,type:scan_gate,notnull"`
	DefaultVersionPolicy  VersionPolicy `bun:"default_version_policy,type:version_policy,notnull"`
	RequireSignedBundles  bool          `bun:"require_signed_bundles,type:boolean,notnull"`
	CommunityNeedsReview  bool          `bun:"community_needs_review,type:boolean,notnull"`
	RescanOnNewVersion    bool          `bun:"rescan_on_new_version,type:boolean,notnull"`
	AllowPersonalProfiles bool          `bun:"allow_personal_profiles,type:boolean,notnull"`
	CreatedAt             time.Time     `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt             time.Time     `bun:"updated_at,type:timestamptz,notnull,default:now()"`
}

// AuditEvent is append-only. Nothing in Go enforces that: UPDATE and DELETE are
// revoked from every database role (FR-052, constitution principle IV), because
// an ORM hook or a convention is bypassed by the first person who needs to fix a
// typo. OccurredAt is the row's creation instant, which is why there is no
// separate created_at.
type AuditEvent struct {
	bun.BaseModel `bun:"table:audit_event,alias:aud"`

	ID         uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	OccurredAt time.Time `bun:"occurred_at,type:timestamptz,notnull,default:now()"`
	Actor      string    `bun:"actor,type:text,notnull"`
	ActorKind  ActorKind `bun:"actor_kind,type:actor_kind,notnull"`
	Kind       AuditKind `bun:"kind,type:audit_kind,notnull"`
	Text       string    `bun:"text,type:text,notnull"`
	Source     string    `bun:"source,type:text,nullzero"`
}

// SyncEvent is one row per sync, not per package (R8). The per-package fan-out
// for install counts happens in the nightly aggregation job, so a catalog read
// never writes.
type SyncEvent struct {
	bun.BaseModel `bun:"table:sync_event,alias:sev"`

	ID         uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	IdentityID uuid.UUID `bun:"identity_id,type:uuid,notnull"`
	ProfileID  uuid.UUID `bun:"profile_id,type:uuid,notnull"`
	RevisionID uuid.UUID `bun:"revision_id,type:uuid,notnull"`
	Host       string    `bun:"host,type:text,notnull"`
	OccurredAt time.Time `bun:"occurred_at,type:timestamptz,notnull,default:now()"`

	Identity *Identity `bun:"rel:belongs-to,join:identity_id=id"`
	Profile  *Profile  `bun:"rel:belongs-to,join:profile_id=id"`
	Revision *Revision `bun:"rel:belongs-to,join:revision_id=id"`
}
