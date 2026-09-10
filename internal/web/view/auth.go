package view

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The view models of the browser session.

// Viewer is who a request is acting as, as the api resolved it on THAT
// request. It is the only source a screen may render an identity from.
// There is no default and no fallback — the zero value is the signed-out
// state, rendering no chip at all rather than a placeholder or "Guest".
//
// SignedIn is a field rather than derived from the others: "signed in with
// an empty display name" is a state a provider can legitimately produce.
type Viewer struct {
	SignedIn    bool
	Subject     string
	DisplayName string
	Email       string
	// Role is the group_role_map value this identity resolved to, and "" when it maps to none.
	Role string
	// HasRole is a distinct state. Branch on this, never on Role == "": a
	// role the resolve did not report is not a state to invent copy for.
	HasRole bool
	// Groups are the person's own groups, which the no-role screen needs to
	// say what to ask for.
	Groups []string
}

// Initials is the chip's avatar text, derived from the resolved display name
// rather than carried beside it, so a field of its own can't disagree with
// the session. Empty when there is nobody to render.
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
		// By rune, not byte: word[0] on a multi-byte first character renders
		// as U+FFFD.
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

// roleLabels is the display text of each role the api can resolve, a table
// rather than a generic transformation of the value. A missing role renders
// as its own name rather than nothing.
var roleLabels = map[string]string{
	"catalog-admin":    "Catalog admin",
	"scanner-reviewer": "Scanner reviewer",
	"profile-consumer": "Profile consumer",
	"read-only":        "Read only",
}

// RoleLabel is the role as a person reads it, and "" when they hold none.
func (v Viewer) RoleLabel() string {
	if !v.HasRole {
		return ""
	}
	if label, ok := roleLabels[v.Role]; ok {
		return label
	}
	return v.Role
}

// SignIn is the sign-in screen's props, the shape every sign-in failure
// renders through.
type SignIn struct {
	// Provider is what the operator calls the identity provider. Empty
	// renders neutral wording rather than a dangling "Continue with".
	Provider string
	// Return is the local path sign-in completes to, already through the
	// return-target validator.
	Return string
	// Notice is why this screen is showing, in the hub's own words. Empty on
	// a first visit.
	Notice string
	// Detail is text the provider supplied, escaped by templ on the way out.
	Detail string
	// Tone is "", "warn" or "dan" — the notice's colour.
	Tone string
	// Unavailable is the provider being unreachable, offering NO action.
	// Stated negatively so the zero value is a screen that WORKS: every
	// failure rendering constructs this struct fresh, and a forgotten field
	// would render a sign-in screen with no way to sign in.
	Unavailable bool
	// DevCredentialHint is a field of its own rather than inferred from
	// Credentials being non-empty: that switch is one refactor from a
	// production screen printing passwords.
	DevCredentialHint bool
	// Credentials are the local stack's accounts. Not spelled anywhere under
	// internal/web: a compiled-in identity would reach every visitor.
	Credentials []Credential
}

// Credential is one account the development hint names, with the role it
// resolves to so a reader can pick the one they want.
type Credential struct {
	Username string
	Password string
	Role     string
}

// LoginHref is the one action the screen offers.
func (s SignIn) LoginHref() string {
	if s.Return == "" || s.Return == "/" {
		return "/auth/login"
	}
	return "/auth/login?return=" + url.QueryEscape(s.Return)
}

// ShowCredentials is two gates: the flag AND something to print. Checked
// here as well as at the call site, since a hint that switches itself on is
// exactly what must not happen.
func (s SignIn) ShowCredentials() bool {
	return s.DevCredentialHint && len(s.Credentials) > 0
}

// Action is the action's text. Naming the provider tells a person which
// password-manager entry to reach for.
func (s SignIn) Action() string {
	if s.Provider == "" {
		return "Continue to sign in"
	}
	return "Continue with " + s.Provider
}

// ProviderName is the provider wherever the copy needs a noun for it. This
// hub cannot guess which provider it is in front of, so an unset name gets
// a neutral noun.
func (s SignIn) ProviderName() string {
	if s.Provider == "" {
		return "your organisation's identity provider"
	}
	return s.Provider
}

// NoRole is the screen for signed in, holding no role: told so plainly and
// told what to ask for. Deliberately not an empty catalog.
type NoRole struct {
	Viewer Viewer
	// Groups is what the provider said this person is a member of, which an
	// administrator needs to map them.
	Groups []string
}
