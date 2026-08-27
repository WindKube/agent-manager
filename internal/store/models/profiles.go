package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Profile is a named set of packages a team consumes.
type Profile struct {
	bun.BaseModel `bun:"table:profile,alias:prf"`

	ID            uuid.UUID         `bun:"id,pk,type:uuid,notnull"`
	Slug          string            `bun:"slug,type:text,notnull,unique"`
	Name          string            `bun:"name,type:text,notnull"`
	Description   string            `bun:"description,type:text,nullzero"`
	Visibility    ProfileVisibility `bun:"visibility,type:profile_visibility,notnull"`
	OwnerTeam     string            `bun:"owner_team,type:text,nullzero"`
	DefaultPolicy VersionPolicy     `bun:"default_policy,type:version_policy,notnull"`
	// ForkedFromID records lineage only. A fork does not subscribe to upstream
	// revisions (FR-038) and there is deliberately no mechanism that could.
	ForkedFromID *uuid.UUID `bun:"forked_from_id,type:uuid,nullzero"`
	CreatedAt    time.Time  `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt    time.Time  `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	ForkedFrom  *Profile        `bun:"rel:belongs-to,join:forked_from_id=id"`
	Entries     []*ProfileEntry `bun:"rel:has-many,join:id=profile_id"`
	Revisions   []*Revision     `bun:"rel:has-many,join:id=profile_id"`
	Memberships []*Membership   `bun:"rel:has-many,join:id=profile_id"`
	SyncTargets []*SyncTarget   `bun:"rel:has-many,join:id=profile_id"`
}

// ProfileEntry is one package in a profile and how it tracks versions. The
// migration layer carries `check (mode <> 'pinned' or pinned_version_id is not
// null)`: a pinned entry with nothing pinned is not a state the schema allows.
type ProfileEntry struct {
	bun.BaseModel `bun:"table:profile_entry,alias:pent"`

	ProfileID       uuid.UUID  `bun:"profile_id,pk,type:uuid,notnull"`
	PackageID       uuid.UUID  `bun:"package_id,pk,type:uuid,notnull"`
	Mode            EntryMode  `bun:"mode,type:entry_mode,notnull"`
	PinnedVersionID *uuid.UUID `bun:"pinned_version_id,type:uuid,nullzero"`
	RangeExpr       string     `bun:"range_expr,type:text,nullzero"`
	Position        int32      `bun:"position,type:integer,notnull"`
	CreatedAt       time.Time  `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt       time.Time  `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Profile       *Profile `bun:"rel:belongs-to,join:profile_id=id"`
	Package       *Package `bun:"rel:belongs-to,join:package_id=id"`
	PinnedVersion *Version `bun:"rel:belongs-to,join:pinned_version_id=id"`
}

// Revision is an immutable published snapshot of a profile. Previous revisions
// are never deleted (FR-034).
//
// Seq is allocated inside the publish transaction by
// `select coalesce(max(seq),0)+1 ... for update` on the parent profile row, so two
// racing publishes serialise into r15 and r16 with no gap and no overwrite. An
// application counter or a Postgres sequence would leave gaps on rollback, which
// is why `unique (profile_id, seq)` is the constraint and not a nicety.
type Revision struct {
	bun.BaseModel `bun:"table:revision,alias:rev"`

	ID        uuid.UUID       `bun:"id,pk,type:uuid,notnull"`
	ProfileID uuid.UUID       `bun:"profile_id,type:uuid,notnull,unique:revision_profile_seq"`
	Seq       int32           `bun:"seq,type:integer,notnull,unique:revision_profile_seq"`
	Note      string          `bun:"note,type:text,nullzero"`
	Lockfile  json.RawMessage `bun:"lockfile,type:jsonb,notnull"`
	ObjectKey string          `bun:"object_key,type:text,notnull"`
	CreatedAt time.Time       `bun:"created_at,type:timestamptz,notnull,default:now()"`
	CreatedBy string          `bun:"created_by,type:text,notnull"`

	Profile *Profile `bun:"rel:belongs-to,join:profile_id=id"`
}

// Membership grants a subject a role on a profile. A person in several mapped
// groups holds the union of those permissions (FR-042), resolved at query time
// rather than stored.
type Membership struct {
	bun.BaseModel `bun:"table:membership,alias:mem"`

	ProfileID   uuid.UUID      `bun:"profile_id,pk,type:uuid,notnull"`
	SubjectKind SubjectKind    `bun:"subject_kind,pk,type:subject_kind,notnull"`
	SubjectRef  string         `bun:"subject_ref,pk,type:text,notnull"`
	Role        MembershipRole `bun:"role,type:membership_role,notnull"`
	CreatedAt   time.Time      `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt   time.Time      `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Profile *Profile `bun:"rel:belongs-to,join:profile_id=id"`
}

// SyncTarget is a client-side output format a profile is written to. It affects
// only what a client writes locally, never server state (FR-039).
type SyncTarget struct {
	bun.BaseModel `bun:"table:sync_target,alias:stgt"`

	ProfileID uuid.UUID      `bun:"profile_id,pk,type:uuid,notnull"`
	Target    SyncTargetKind `bun:"target,pk,type:sync_target_kind,notnull"`
	Enabled   bool           `bun:"enabled,type:boolean,notnull"`
	CreatedAt time.Time      `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt time.Time      `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Profile *Profile `bun:"rel:belongs-to,join:profile_id=id"`
}
