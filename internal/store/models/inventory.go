package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Machine is one amctl installation, keyed by the random id the CLI generated
// for itself. It is current state, overwritten by every report it files.
type Machine struct {
	bun.BaseModel `bun:"table:machine,alias:mch"`

	ID           uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	Hostname     string    `bun:"hostname,type:text,notnull"`
	OS           string    `bun:"os,type:text,nullzero"`
	Arch         string    `bun:"arch,type:text,nullzero"`
	AmctlVersion string    `bun:"amctl_version,type:text,nullzero"`
	// LastIdentityID is the person behind the last report: the reporter, or
	// the creator of the service token that reported.
	LastIdentityID     uuid.UUID  `bun:"last_identity_id,type:uuid,notnull"`
	LastServiceTokenID *uuid.UUID `bun:"last_service_token_id,type:uuid,nullzero"`
	LastProfileID      uuid.UUID  `bun:"last_profile_id,type:uuid,notnull"`
	LastRevisionID     uuid.UUID  `bun:"last_revision_id,type:uuid,notnull"`
	FirstSeenAt        time.Time  `bun:"first_seen_at,type:timestamptz,notnull,default:now()"`
	LastSeenAt         time.Time  `bun:"last_seen_at,type:timestamptz,notnull,default:now()"`

	LastIdentity     *Identity     `bun:"rel:belongs-to,join:last_identity_id=id"`
	LastServiceToken *ServiceToken `bun:"rel:belongs-to,join:last_service_token_id=id"`
	LastProfile      *Profile      `bun:"rel:belongs-to,join:last_profile_id=id"`
	LastRevision     *Revision     `bun:"rel:belongs-to,join:last_revision_id=id"`
}

// MachineInstall is one package version a machine reported installed for one
// profile and target. A report replaces its profile's rows.
type MachineInstall struct {
	bun.BaseModel `bun:"table:machine_install,alias:mins"`

	MachineID uuid.UUID      `bun:"machine_id,pk,type:uuid,notnull"`
	ProfileID uuid.UUID      `bun:"profile_id,pk,type:uuid,notnull"`
	Target    SyncTargetKind `bun:"target,pk,type:sync_target_kind,notnull"`
	PackageID uuid.UUID      `bun:"package_id,pk,type:uuid,notnull"`
	VersionID uuid.UUID      `bun:"version_id,type:uuid,notnull"`

	Machine *Machine `bun:"rel:belongs-to,join:machine_id=id"`
	Profile *Profile `bun:"rel:belongs-to,join:profile_id=id"`
	Package *Package `bun:"rel:belongs-to,join:package_id=id"`
	Version *Version `bun:"rel:belongs-to,join:version_id=id"`
}

// MachineSkip is something a machine did not install for one profile: a
// whole entry (no component), or one component of an installed plugin.
type MachineSkip struct {
	bun.BaseModel `bun:"table:machine_skip,alias:mskp"`

	ID        uuid.UUID      `bun:"id,pk,type:uuid,notnull"`
	MachineID uuid.UUID      `bun:"machine_id,type:uuid,notnull"`
	ProfileID uuid.UUID      `bun:"profile_id,type:uuid,notnull"`
	Entry     string         `bun:"entry,type:text,notnull"`
	Target    SyncTargetKind `bun:"target,type:sync_target_kind,nullzero"`
	Component string         `bun:"component,type:text,nullzero"`
	Reason    string         `bun:"reason,type:text,nullzero"`

	Machine *Machine `bun:"rel:belongs-to,join:machine_id=id"`
	Profile *Profile `bun:"rel:belongs-to,join:profile_id=id"`
}
