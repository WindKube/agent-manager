package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// OrgPolicySingletonID is the only id org_policy may hold.
const OrgPolicySingletonID int32 = 1

// OrgPolicy is a singleton: one organisation per deployment.
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

// AuditEvent is append-only, enforced by revoking UPDATE and DELETE from every
// database role rather than by convention.
type AuditEvent struct {
	bun.BaseModel `bun:"table:audit_event,alias:aud"`

	ID         uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	OccurredAt time.Time `bun:"occurred_at,type:timestamptz,notnull,default:now()"`
	Actor      string    `bun:"actor,type:text,notnull"`
	ActorKind  ActorKind `bun:"actor_kind,type:actor_kind,notnull"`
	Kind       AuditKind `bun:"kind,type:audit_kind,notnull"`
	Text       string    `bun:"text,type:text,notnull"`
	Source     string    `bun:"source,type:text,nullzero"`
	// Subject columns are null only on legacy rows; build rows with audit.New.
	SubjectKind AuditSubjectKind `bun:"subject_kind,type:audit_subject_kind,nullzero"`
	SubjectID   string           `bun:"subject_id,type:text,nullzero"`
	// Namespace is the package namespace of a package, version or finding
	// subject, so a consumer can filter by it without a join.
	Namespace string         `bun:"namespace,type:text,nullzero"`
	Data      map[string]any `bun:"data,type:jsonb,notnull,default:'{}'"`
}

// FetchAttempt is one ingestion fetch and its outcome; a refused fetch (SSRF,
// zip bomb) produces no version row, so this is the only record of it.
type FetchAttempt struct {
	bun.BaseModel `bun:"table:fetch_attempt,alias:fat"`

	ID         uuid.UUID       `bun:"id,pk,type:uuid,notnull"`
	OccurredAt time.Time       `bun:"occurred_at,type:timestamptz,notnull,default:now()"`
	SourceKind FetchSourceKind `bun:"source_kind,type:fetch_source_kind,notnull"`
	// RequestedRef is user-supplied: stored with credentials redacted, rendered escaped.
	RequestedRef string       `bun:"requested_ref,type:text,notnull"`
	Outcome      FetchOutcome `bun:"outcome,type:fetch_outcome,notnull"`
	// Detail is the redacted error message, null when Outcome is `ok`.
	Detail string `bun:"detail,type:text,nullzero"`
}

// SyncEvent is one row per sync, not per package.
type SyncEvent struct {
	bun.BaseModel `bun:"table:sync_event,alias:sev"`

	ID         uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	IdentityID uuid.UUID `bun:"identity_id,type:uuid,notnull"`
	// ServiceTokenID is set when a service token reported the sync; IdentityID
	// is then the token's creator.
	ServiceTokenID *uuid.UUID `bun:"service_token_id,type:uuid,nullzero"`
	ProfileID      uuid.UUID  `bun:"profile_id,type:uuid,notnull"`
	RevisionID     uuid.UUID  `bun:"revision_id,type:uuid,notnull"`
	Host           string     `bun:"host,type:text,notnull"`
	OccurredAt     time.Time  `bun:"occurred_at,type:timestamptz,notnull,default:now()"`

	Identity     *Identity     `bun:"rel:belongs-to,join:identity_id=id"`
	ServiceToken *ServiceToken `bun:"rel:belongs-to,join:service_token_id=id"`
	Profile      *Profile      `bun:"rel:belongs-to,join:profile_id=id"`
	Revision     *Revision     `bun:"rel:belongs-to,join:revision_id=id"`
}
