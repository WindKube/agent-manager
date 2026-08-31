package view

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The view models of the browser session (US2). contracts/auth.md is
// authoritative for what each of them renders.

// Viewer is who a request is acting as, as the api resolved it on THAT request.
//
// FR-116: it is the only source a screen may render an identity from. There is no
// default and no fallback — the zero value is the signed-out state, which renders
// no chip at all rather than a placeholder, initials or "Guest" (SC-106).
//
// SignedIn is a field rather than something derived from the others, because
// "signed in with an empty display name" is a state a provider can legitimately
// produce and inferring the boolean from the strings would render that person as
// signed out.
type Viewer struct {
	SignedIn    bool
	Subject     string
	DisplayName string
	Email       string
	// Role is the group_role_map value this identity resolved to, hyphenated as
	// the enum spells it, and "" when it maps to none.
	Role string
	// HasRole is FR-117's distinct state. Branch on this, never on Role == "": a
	// role the resolve did not report is not a state a screen may invent copy for.
	HasRole bool
	// Groups are the person's own groups, which the no-role screen needs in order
	// to say what to ask for.
	Groups []string
}

// Initials is the chip's avatar text, derived from the resolved display name
// rather than carried beside it: an avatar IS an identity (FR-116), so a field of
// its own would be a second place a name could disagree with the session.
//
// Empty when there is nobody to render, which is what keeps a signed-out shell
// from growing a placeholder.
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
		// By rune, not by byte: a display name is whatever the provider sent
		// (principle III), and word[0] on a multi-byte first character renders as
		// U+FFFD.
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

// roleLabels is the display text of each role the api can resolve.
//
// A table rather than a transformation of the value: "read-only" reads as "Read
// Only" through anything generic, and these four names are a closed set the api
// owns. A role missing from the table renders as its own name rather than as
// nothing — showing somebody a role they hold under an unfamiliar spelling beats
// showing them none.
var roleLabels = map[string]string{
	"catalog-admin":    "Catalog admin",
	"scanner-reviewer": "Scanner reviewer",
	"profile-consumer": "Profile consumer",
	"read-only":        "Read only",
}

// RoleLabel is the role as a person reads it, and "" when they hold none. What
// the chip puts in that empty space is the chip's decision, not this model's.
func (v Viewer) RoleLabel() string {
	if !v.HasRole {
		return ""
	}
	if label, ok := roleLabels[v.Role]; ok {
		return label
	}
	return v.Role
}

// SignIn is the sign-in screen's props, and the shape every one of
// contracts/auth.md's sign-in failures renders through.
type SignIn struct {
	// Provider is what the operator calls the identity provider. Empty renders the
	// neutral wording rather than a dangling "Continue with".
	Provider string
	// Return is the local path sign-in completes to. It has been through the
	// return-target validator before it reaches here (FR-113).
	Return string
	// Notice is why this screen is showing, in the hub's own words. Empty on a
	// first visit.
	Notice string
	// Detail is text the provider supplied. templ escapes it on the way out and
	// nothing under internal/web may call templ.Raw (001 FR-055), which is what
	// makes rendering an upstream string safe at all.
	Detail string
	// Tone is "", "warn" or "dan" — the notice's colour.
	Tone string
	// Unavailable is the provider being unreachable. The screen then says so and
	// offers NO action: contracts/auth.md is explicit that a button known to fail
	// is worse than no button.
	//
	// Stated negatively so the zero value is a screen that WORKS. An `Available`
	// field reads better and is the wrong way round: every one of the eleven
	// failure renderings constructs this struct fresh, and one that forgot the
	// field would render a sign-in screen with no way to sign in.
	Unavailable bool
	// DevCredentialHint is FR-119's flag, and it is a field of its own rather than
	// inferred from Credentials being non-empty. "The list happened to be
	// populated" is exactly the switch that requirement forbids — one refactor from
	// a production sign-in screen printing passwords.
	DevCredentialHint bool
	// Credentials are the local stack's accounts, handed in by the role's
	// bootstrap. Not spelled anywhere under internal/web: a username or an address
	// written into the product would be the compiled-in identity FR-116 forbids.
	Credentials []Credential
}

// Credential is one account the development hint names, with the role it resolves
// to so a reader can pick the one the screen they want needs.
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

// ShowCredentials is FR-119's two gates: the flag AND something to print. The
// flag is checked here as well as at the call site, because a hint that switches
// itself on is the thing that requirement forbids.
func (s SignIn) ShowCredentials() bool {
	return s.DevCredentialHint && len(s.Credentials) > 0
}

// Action is the action's text. Naming the provider tells a person which
// password-manager entry to reach for; a bare "Sign in" tells them nothing about
// where they are about to be sent.
func (s SignIn) Action() string {
	if s.Provider == "" {
		return "Continue to sign in"
	}
	return "Continue with " + s.Provider
}

// ProviderName is the provider wherever the copy needs a noun for it. This hub
// does not know which provider it is in front of and must not grow a way to
// guess (FR-105), so an unset name gets a neutral noun rather than a default.
func (s SignIn) ProviderName() string {
	if s.Provider == "" {
		return "your organisation's identity provider"
	}
	return s.Provider
}

// NoRole is FR-117's screen: signed in, holding no role, told so plainly and told
// what to ask for. It is deliberately not an empty catalog.
type NoRole struct {
	Viewer Viewer
	// Groups is what the provider said this person is a member of. It is what an
	// administrator needs in order to map them, so it belongs on the screen and not
	// only in a log.
	Groups []string
}
