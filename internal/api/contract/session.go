package contract

import "time"

// SessionMintRequest asks the api to open a browser session for the identity
// an ID token names. It carries the raw ID token rather than the claims the
// caller parsed out of it: verification happens in the role that owns
// identity, so the api trusts nothing the web role decoded and the shared
// mint secret degrades from THE control to defence in depth.
type SessionMintRequest struct {
	IDToken string `json:"idToken" minLength:"1" doc:"The provider's ID token, exactly as issued. Verified here against the configured issuer, audience and signing keys; the caller's own parsing is not trusted and is not accepted."`
}

// Session is a minted browser session. The token is returned exactly once and is
// never stored or logged — what the row holds is its sha256 (auth.HashToken), so
// this response is the only place the plaintext ever exists on this side.
type Session struct {
	Token string `json:"token" doc:"The opaque session token. Returned once; the hub stores only its hash. Sent back as an Authorization bearer credential on every later request."`
	// Both an instant and a duration, which is redundant on purpose: computing
	// one from the other across two containers' clocks is how a cookie comes
	// to outlive the row behind it.
	ExpiresAt time.Time `json:"expiresAt" doc:"When the session row expires. This is the value stored, and what a cookie's expiry must match."`
	ExpiresIn int       `json:"expiresIn" doc:"Seconds until the session expires, measured on this hub's clock. Use this for a cookie's Max-Age rather than subtracting expiresAt from a local clock." example:"43200"`
}

// Viewer is who the request is acting as, resolved on THIS request. Nothing
// here is cached and nothing is read back from a cookie:
// auth.Sessions.Resolve re-reads the identity row and re-derives the role
// from group_role_map on every request, so there is no cache to invalidate.
type Viewer struct {
	Subject     string `json:"subject" doc:"The provider's stable subject identifier for this identity." example:"CgVrd2lhdHISBGxvY2Fs"`
	DisplayName string `json:"displayName" doc:"The name a screen shows. Derived by the hub from whichever of name, preferred_username or email the provider populated." example:"Krzysztof Wiatrzyk"`
	Email       string `json:"email" doc:"May be empty: a provider is not obliged to release an email address, and a screen must cope rather than invent one." example:"kwiatrzyk@example.dev"`
	// Role and HasRole are two fields rather than one because an empty role
	// is a state a screen must render deliberately: signed in, holding no
	// role, told what to ask for.
	Role    string   `json:"role,omitempty" enum:"catalog-admin,scanner-reviewer,profile-consumer,read-only" doc:"The most privileged role this identity's groups map to. Absent when none of them maps to anything." example:"catalog-admin"`
	HasRole bool     `json:"hasRole" doc:"Whether any group this identity holds maps to a role at all (FR-117). False is a screen state, not an error."`
	Groups  []string `json:"groups" doc:"The groups claim as the provider sent it, unfiltered. Shown on the no-role screen so a person can say which groups they hold when asking for access."`
}
