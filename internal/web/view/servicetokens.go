package view

import (
	"strings"
	"time"
)

// The api's scope vocabulary and lifetime bounds (internal/auth), restated
// because the web role may not link that package.
const (
	ScopeReadCatalog            = "read:catalog"
	ServiceTokenDefaultLifetime = 90 * 24 * time.Hour
	ServiceTokenMaxLifetime     = 365 * 24 * time.Hour
	syncProfileScopePrefix      = "sync:profile/"
)

// SyncProfileScope is the scope that lets a token sync one profile.
func SyncProfileScope(slug string) string { return syncProfileScopePrefix + slug }

// ServiceToken is one token as the Service tokens screen lists it.
type ServiceToken struct {
	ID         string
	Name       string
	Scopes     []string
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	Status     string
}

// Revocable reports whether a revoke button means anything for this token.
func (t ServiceToken) Revocable() bool { return t.Status == "active" }

// LastUsed is the last-use date, or "never".
func (t ServiceToken) LastUsed() string {
	if t.LastUsedAt == nil {
		return "never"
	}
	return t.LastUsedAt.UTC().Format(time.DateOnly)
}

// StatusLine is the token's state with the date that matters for it.
func (t ServiceToken) StatusLine() string {
	if t.Status == "active" {
		return "expires " + t.ExpiresAt.UTC().Format(time.DateOnly)
	}
	return t.Status
}

// ScopeList is the scopes joined for a table cell.
func (t ServiceToken) ScopeList() string { return strings.Join(t.Scopes, ", ") }

// RevokeHref is the revoke form's action.
func (t ServiceToken) RevokeHref() string { return "/tokens/" + t.ID + "/revoke" }

// CreatedServiceToken is the one response that carries a secret; the screen
// shows it once and never again.
type CreatedServiceToken struct {
	Name   string
	Secret string
}

// ServiceTokenForm is the create form's values, echoed back after a refusal.
type ServiceTokenForm struct {
	Name        string
	Profiles    []string
	ReadCatalog bool
	Expires     string
}

// Selected reports whether slug was ticked.
func (f ServiceTokenForm) Selected(slug string) bool {
	for _, s := range f.Profiles {
		if s == slug {
			return true
		}
	}
	return false
}

// ServiceTokens is the Service tokens screen.
type ServiceTokens struct {
	Tokens []ServiceToken
	// Profiles is what a sync scope may name: the profiles this viewer can read.
	Profiles []ProfileRow
	Created  *CreatedServiceToken
	Form     ServiceTokenForm
	// MinExpires and MaxExpires bound the expiry date picker.
	MinExpires string
	MaxExpires string

	Notice      *Notice
	SignedOut   bool
	Unavailable bool
}
