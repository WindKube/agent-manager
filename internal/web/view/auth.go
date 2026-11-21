package view

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Viewer is who a request is acting as, as the api resolved it on that request; it is the only source a
// screen may render an identity from. The zero value is signed out, with no fallback like "Guest".
// SignedIn is explicit because a provider can produce a signed-in identity with an empty display name.
type Viewer struct {
	SignedIn    bool
	Subject     string
	DisplayName string
	Email       string
	Role        string
	// HasRole is what to branch on, never Role == "".
	HasRole bool
	Groups  []string
}

// Initials is derived from the display name rather than stored, so it cannot disagree with the session.
func (v Viewer) Initials() string {
	if !v.SignedIn {
		return ""
	}
	source := v.DisplayName
	if strings.TrimSpace(source) == "" {
		source = v.Email
	}

	initials := make([]rune, 0, 2)
	for _, word := range strings.Fields(source) {
		// By rune, not byte, so a multi-byte first character survives.
		first, _ := utf8.DecodeRuneInString(word)
		if !unicode.IsLetter(first) && !unicode.IsDigit(first) {
			continue
		}
		initials = append(initials, unicode.ToUpper(first))
		if len(initials) == 2 {
			break
		}
	}
	return string(initials)
}

// roleLabels labels each role the api can resolve; an unknown role renders as its own name.
var roleLabels = map[string]string{
	"catalog-admin":    "Catalog admin",
	"scanner-reviewer": "Scanner reviewer",
	"profile-consumer": "Profile consumer",
	"read-only":        "Read only",
}

func (v Viewer) RoleLabel() string {
	if !v.HasRole {
		return ""
	}
	if label, ok := roleLabels[v.Role]; ok {
		return label
	}
	return v.Role
}

// SignIn is the sign-in screen's props, the shape every sign-in failure renders through.
type SignIn struct {
	Provider string
	// Return has already passed the return-target validator.
	Return string
	Notice string
	// Detail is provider-supplied text.
	Detail string
	// Tone is "", "warn" or "dan".
	Tone string
	// Unavailable is stated negatively so the zero value is a screen that can still sign in.
	Unavailable bool
	// DevCredentialHint is explicit rather than inferred from Credentials, so a refactor cannot make a
	// production screen print passwords.
	DevCredentialHint bool
	// Credentials are never compiled into internal/web: a built-in identity would reach every visitor.
	Credentials []Credential
}

// Credential is one account the development hint names.
type Credential struct {
	Username string
	Password string
	Role     string
}

func (s SignIn) LoginHref() string {
	if s.Return == "" || s.Return == "/" {
		return "/auth/login"
	}
	return "/auth/login?return=" + url.QueryEscape(s.Return)
}

// ShowCredentials requires both the flag and something to print.
func (s SignIn) ShowCredentials() bool {
	return s.DevCredentialHint && len(s.Credentials) > 0
}

func (s SignIn) Action() string {
	if s.Provider == "" {
		return "Continue to sign in"
	}
	return "Continue with " + s.Provider
}

func (s SignIn) ProviderName() string {
	if s.Provider == "" {
		return "your organisation's identity provider"
	}
	return s.Provider
}

// NoRole is the screen for a signed-in identity holding no role; deliberately not an empty catalog.
type NoRole struct {
	Viewer Viewer
	// Groups is what an administrator needs to map this person to a role.
	Groups []string
}
