package view

import (
	"strings"
	"time"
)

// Mirrored from internal/auth, which the web role may not import.
const (
	ScopeReadCatalog            = "read:catalog"
	ServiceTokenDefaultLifetime = 90 * 24 * time.Hour
	ServiceTokenMaxLifetime     = 365 * 24 * time.Hour
	syncProfileScopePrefix      = "sync:profile/"
)

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

func (t ServiceToken) Revocable() bool { return t.Status == "active" }

func (t ServiceToken) LastUsed() string {
	if t.LastUsedAt == nil {
		return "never"
	}
	return t.LastUsedAt.UTC().Format(time.DateOnly)
}

func (t ServiceToken) StatusLine() string {
	if t.Status == "active" {
		return "expires " + t.ExpiresAt.UTC().Format(time.DateOnly)
	}
	return t.Status
}

func (t ServiceToken) ScopeList() string { return strings.Join(t.Scopes, ", ") }

func (t ServiceToken) RevokeHref() string { return "/tokens/" + t.ID + "/revoke" }

// CreatedServiceToken is the one response that carries a secret; it is shown once.
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

func (f ServiceTokenForm) Selected(slug string) bool {
	for _, s := range f.Profiles {
		if s == slug {
			return true
		}
	}
	return false
}

type ServiceTokens struct {
	Tokens []ServiceToken
	// Profiles is what a sync scope may name: the profiles this viewer can read.
	Profiles   []ProfileRow
	Created    *CreatedServiceToken
	Form       ServiceTokenForm
	MinExpires string
	MaxExpires string

	Notice      *Notice
	SignedOut   bool
	Unavailable bool
}
