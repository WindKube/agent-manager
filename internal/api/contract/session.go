package contract

import "time"

// SessionMintRequest carries the raw ID token rather than parsed claims, so
// the api verifies identity itself and the shared mint secret is only
// defence in depth.
type SessionMintRequest struct {
	IDToken string `json:"idToken" minLength:"1" doc:"The provider's ID token, exactly as issued. Verified here against the configured issuer, audience and signing keys; the caller's own parsing is not trusted and is not accepted."`
}

// Session is a minted browser session. The token is returned once and never
// stored or logged; the row holds only its sha256 (auth.HashToken).
type Session struct {
	Token string `json:"token" doc:"The opaque session token. Returned once; the hub stores only its hash. Sent back as an Authorization bearer credential on every later request."`
	// Both an instant and a duration on purpose: computing one from the other
	// across two containers' clocks lets a cookie outlive its row.
	ExpiresAt time.Time `json:"expiresAt" doc:"When the session row expires. This is the value stored, and what a cookie's expiry must match."`
	ExpiresIn int       `json:"expiresIn" doc:"Seconds until the session expires, measured on this hub's clock. Use this for a cookie's Max-Age rather than subtracting expiresAt from a local clock." example:"43200"`
}

// Viewer is who the request acts as, re-resolved from the identity row and
// group_role_map on every request; nothing is cached or read from a cookie.
type Viewer struct {
	Subject     string `json:"subject" doc:"The provider's stable subject identifier for this identity." example:"CgVrd2lhdHISBGxvY2Fs"`
	DisplayName string `json:"displayName" doc:"The name a screen shows. Derived by the hub from whichever of name, preferred_username or email the provider populated." example:"Krzysztof Wiatrzyk"`
	Email       string `json:"email" doc:"May be empty: a provider is not obliged to release an email address, and a screen must cope rather than invent one." example:"kwiatrzyk@example.dev"`
	// HasRole is separate because "signed in, no role" is a state a screen
	// must render deliberately.
	Role    string   `json:"role,omitempty" enum:"catalog-admin,scanner-reviewer,profile-consumer,read-only" doc:"The most privileged role this identity's groups map to. Absent when none of them maps to anything." example:"catalog-admin"`
	HasRole bool     `json:"hasRole" doc:"Whether any group this identity holds maps to a role at all. False is a screen state, not an error."`
	Groups  []string `json:"groups" doc:"The groups claim as the provider sent it, unfiltered. Shown on the no-role screen so a person can say which groups they hold when asking for access."`
}
