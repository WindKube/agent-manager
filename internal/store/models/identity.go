package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Identity is a person as the IdP describes them.
type Identity struct {
	bun.BaseModel `bun:"table:identity,alias:idt"`

	ID          uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	Subject     string    `bun:"subject,type:text,notnull,unique"`
	Email       string    `bun:"email,type:text,nullzero"`
	DisplayName string    `bun:"display_name,type:text,nullzero"`
	// Groups is refreshed on every token issue, so losing a group takes effect at
	// the next refresh rather than immediately (FR-045).
	Groups     []string   `bun:"groups,array,type:text[],notnull,default:'{}'"`
	LastSeenAt *time.Time `bun:"last_seen_at,type:timestamptz,nullzero"`
	CreatedAt  time.Time  `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt  time.Time  `bun:"updated_at,type:timestamptz,notnull,default:now()"`
}

// GroupRoleMap maps an IdP group name onto an organisation role.
type GroupRoleMap struct {
	bun.BaseModel `bun:"table:group_role_map,alias:grm"`

	GroupName string    `bun:"group_name,pk,type:text,notnull"`
	Role      OrgRole   `bun:"role,type:org_role,notnull"`
	CreatedAt time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt time.Time `bun:"updated_at,type:timestamptz,notnull,default:now()"`
}

// DeviceAuthorization is one in-flight device flow.
//
// Single use is the pending -> approved -> consumed transition inside one
// transaction (FR-042), which is why there is no consumed boolean.
type DeviceAuthorization struct {
	bun.BaseModel `bun:"table:device_authorization,alias:dauth"`

	ID uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	// DeviceCodeHash is hashed at rest: the plaintext device code is a bearer
	// credential, and a database read must not yield one.
	DeviceCodeHash []byte `bun:"device_code_hash,type:bytea,notnull,unique"`
	// UserCode is Crockford base32 in the HKQ2-9FTL shape, ambiguous glyphs
	// excluded, and is shown to a person rather than stored as a secret.
	UserCode string `bun:"user_code,type:text,notnull,unique"`
	// RequestingHost is bound at issue (FR-041).
	RequestingHost       string          `bun:"requesting_host,type:text,notnull"`
	State                DeviceAuthState `bun:"state,type:device_auth_state,notnull"`
	ApprovedByIdentityID *uuid.UUID      `bun:"approved_by_identity_id,type:uuid,nullzero"`
	ExpiresAt            time.Time       `bun:"expires_at,type:timestamptz,notnull"`
	CreatedAt            time.Time       `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt            time.Time       `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	ApprovedBy *Identity `bun:"rel:belongs-to,join:approved_by_identity_id=id"`
}

// Session is an opaque server-side session for the web role. The token is hashed
// at rest for the same reason the device code is: the plaintext is a bearer
// credential.
type Session struct {
	bun.BaseModel `bun:"table:session,alias:ses"`

	ID         uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	TokenHash  []byte    `bun:"token_hash,type:bytea,notnull,unique"`
	IdentityID uuid.UUID `bun:"identity_id,type:uuid,notnull"`
	ExpiresAt  time.Time `bun:"expires_at,type:timestamptz,notnull"`
	CreatedAt  time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt  time.Time `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Identity *Identity `bun:"rel:belongs-to,join:identity_id=id"`
}
