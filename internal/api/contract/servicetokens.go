package contract

import "time"

// CreateServiceTokenRequest asks for a new service token.
type CreateServiceTokenRequest struct {
	Name      string    `json:"name" minLength:"1" maxLength:"100" doc:"What the token is for, shown in the list and the audit log." example:"release pipeline"`
	Scopes    []string  `json:"scopes" minItems:"1" maxItems:"50" doc:"sync:profile/<slug> to resolve, download and report syncs of one profile the creator can read, or read:catalog for read-only catalog, package and scan reads. There are no write scopes." example:"[\"sync:profile/example/platform-engineer\"]"`
	ExpiresAt time.Time `json:"expiresAt" doc:"Required, and at most one year from now. There is no token that never expires."`
}

// ServiceToken is one token as listed. It never carries the secret or its hash.
type ServiceToken struct {
	ID         string     `json:"id" format:"uuid"`
	Name       string     `json:"name" example:"release pipeline"`
	Scopes     []string   `json:"scopes" example:"[\"sync:profile/example/platform-engineer\"]"`
	CreatedBy  string     `json:"createdBy" doc:"The email or subject of the person who created it." example:"kwiatrzyk@example.com"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty" doc:"Accurate to about a minute. Absent until first use."`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	Status     string     `json:"status" enum:"active,expired,revoked" example:"active"`
}

// ServiceTokenCreated is the only response that ever carries the secret.
type ServiceTokenCreated struct {
	Token  ServiceToken `json:"token"`
	Secret string       `json:"secret" doc:"The bearer secret, prefixed amst_. Returned once; the hub stores only its hash." example:"amst_3q2-7wEXAMPLEonlyEXAMPLEonlyEXAMPLEonly"`
}

// ServiceTokenList is the tokens the caller may manage: their own, or every
// token for a catalog-admin.
type ServiceTokenList struct {
	Tokens []ServiceToken `json:"tokens" doc:"Most recently created first."`
}
