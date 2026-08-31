package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The browser's half of sign-in (US2). contracts/auth.md is authoritative for the
// flow, both cookies, the state and PKCE rules, and what each failure renders.
//
// Two properties are worth stating before the code, because both are invisible
// once it works:
//
//   - Constitution principle II. This role owns the browser's origin and
//     therefore the cookie, and it holds no datastore credential, so the session
//     row is opened by the api and reached only through the hub client. Nothing
//     here creates a session; it asks for one and carries the answer to the
//     browser.
//   - The browser and this process do not reach the provider at the same address
//     (research R2). Exactly one function rewrites anything for the browser's
//     benefit, and it rewrites one component of one URL.

// AuthProvider is this role's door to the identity provider.
//
// An interface rather than the concrete type below, because the failure paths are
// the interesting half of this file: a stand-in that records whether a code was
// exchanged is how "no session issued and no code exchanged" becomes a test
// rather than a claim.
type AuthProvider interface {
	// Reachable reports whether a sign-in can be started at all. The endpoints
	// have to be discovered before a redirect can be built, and a screen that
	// offers an action it already knows will fail is worse than one that says the
	// provider cannot be reached (contracts/auth.md).
	Reachable(ctx context.Context) error
	// AuthorizationURL is where the BROWSER is sent. The challenge is the S256
	// hash of the verifier held in the round-trip cookie.
	AuthorizationURL(ctx context.Context, state, codeChallenge string) (string, error)
	// Exchange trades an authorization code for a raw ID token over the back
	// channel, at the endpoints the provider published, and returns the token
	// exactly as it arrived: the api verifies the same bytes again.
	Exchange(ctx context.Context, code, codeVerifier string) (string, error)
	// VerifyIDToken verifies the token this role received, before it asks for a
	// session to be minted for it.
	VerifyIDToken(ctx context.Context, idToken string) error
}

// ViewerSource resolves who a request is acting as.
//
// A separate interface from SessionMinter for the reason Registrar is separate
// from CatalogSource: internal/web/fixture can honestly answer this one and must
// not be able to mint a session, and an interface a stand-in cannot honestly
// satisfy is one every screen test then exercises as a claim.
//
// Called on EVERY protected request and never cached. FR-118 is discharged in the
// api — auth.Sessions.Resolve joins the group-to-role map per request — and a
// cache here is the only way left to break it.
type ViewerSource interface {
	Viewer(ctx context.Context) (hub.Viewer, error)
}

// SessionMinter is the api's two session operations: the one that opens a session
// for a verified ID token, and the one that expires it server-side.
type SessionMinter interface {
	MintSession(ctx context.Context, idToken string) (hub.Session, error)
	SignOut(ctx context.Context) error
}

// ---- the identity provider ----------------------------------------------------

// Discovery is the provider's metadata, discovered on demand: the endpoints it
// published, and the ability to verify a token against its keys.
//
// It is an interface here because the package that performs discovery is also the
// package that resolves sessions from the database, and internal/archcheck forbids
// this role from importing it — a role that must hold no datastore credential may
// not link the code that needs one, not even for one accessor. So what crosses
// the boundary is an endpoint pair and a verification call, and the browser flow
// built on them lives here.
//
// Both methods take a context because both may have to reach the provider. A
// hub whose provider is slow to start must not need restarting once it answers.
type Discovery interface {
	Endpoint(ctx context.Context) (oauth2.Endpoint, error)
	VerifyIDToken(ctx context.Context, idToken string) error
}

// AuthOptions is what NewAuthProvider needs.
type AuthOptions struct {
	Discovery    Discovery
	ClientID     string
	ClientSecret string
	// RedirectURL is this role's own callback, as the provider has it registered.
	RedirectURL string
	Scopes      []string
	// BrowserBaseURL is the base a BROWSER must use to reach the provider, when
	// that is not the address this process reaches it at. Empty means one address
	// serves both, which is the production case.
	//
	// This is the only field that value reaches, and AuthorizationURL is the one
	// place it is read (research R2).
	BrowserBaseURL string
}

type authProvider struct {
	discovery    Discovery
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
	// browserHost is the authority a browser reaches the authorization endpoint
	// at, or "" when the published one already works from there.
	browserHost string
}

// NewAuthProvider assembles the browser flow over a provider it may not have
// reached yet. It performs no I/O.
//
// It returns the interface rather than the concrete type on purpose. A caller
// that stored a typed nil pointer in Deps.Auth would hand this role an
// AuthProvider that is not nil and panics on first use, and "there is no provider
// wired" is a state the sign-in screen has to be able to render.
func NewAuthProvider(opts AuthOptions) (AuthProvider, error) {
	switch {
	case opts.Discovery == nil:
		return nil, errors.New("web auth: no provider metadata source")
	case opts.ClientID == "":
		return nil, errors.New("web auth: no client id")
	case opts.RedirectURL == "":
		return nil, errors.New("web auth: no redirect url")
	}

	browserHost, err := browserAuthority(opts.BrowserBaseURL)
	if err != nil {
		return nil, err
	}

	return &authProvider{
		discovery:    opts.Discovery,
		clientID:     opts.ClientID,
		clientSecret: opts.ClientSecret,
		redirectURL:  opts.RedirectURL,
		scopes:       opts.Scopes,
		browserHost:  browserHost,
	}, nil
}

func (p *authProvider) Reachable(ctx context.Context) error {
	_, err := p.discovery.Endpoint(ctx)
	return err
}

// AuthorizationURL builds the redirect the browser follows.
//
// PKCE is not optional (contracts/auth.md): the redirect URI is public by
// definition, so the challenge travels here and the verifier stays in a cookie
// this role signed.
func (p *authProvider) AuthorizationURL(ctx context.Context, state, codeChallenge string) (string, error) {
	config, err := p.config(ctx)
	if err != nil {
		return "", err
	}

	raw := config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	if p.browserHost == "" {
		return raw, nil
	}

	target, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse the authorization url: %w", err)
	}
	// The AUTHORITY, and nothing else. Not the scheme, not the path, not a prefix,
	// and no other endpoint: the token and key endpoints are used exactly as
	// published, which is what keeps this override off the backchannel. Everything
	// the provider decided about the shape of its own URL survives, because the
	// only thing a browser cannot do with the published URL is resolve its host.
	target.Host = p.browserHost
	return target.String(), nil
}

func (p *authProvider) Exchange(ctx context.Context, code, codeVerifier string) (string, error) {
	config, err := p.config(ctx)
	if err != nil {
		return "", err
	}

	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return "", fmt.Errorf("exchange the authorization code: %w", err)
	}
	idToken, _ := token.Extra("id_token").(string)
	if idToken == "" {
		return "", errors.New("the token response carried no id token")
	}
	return idToken, nil
}

func (p *authProvider) VerifyIDToken(ctx context.Context, idToken string) error {
	return p.discovery.VerifyIDToken(ctx, idToken)
}

// config is the oauth2 configuration for one call.
//
// Built per call rather than stored, because the endpoints are discovered rather
// than configured: a config held from construction would be a config built before
// the provider was reachable, and the first sign-in after a late start would use
// two empty URLs.
func (p *authProvider) config(ctx context.Context) (*oauth2.Config, error) {
	endpoint, err := p.discovery.Endpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("reach the identity provider: %w", err)
	}
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint:     endpoint,
		RedirectURL:  p.redirectURL,
		Scopes:       p.scopes,
	}, nil
}

// browserAuthority is the host and port of a base URL, or "" when there is none.
//
// Validated at construction rather than per redirect: a value naming no host
// would otherwise fail as a redirect to a URL nobody can explain — once, in a
// browser, at sign-in.
func browserAuthority(base string) (string, error) {
	if base == "" {
		return "", nil
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("web auth: the browser base url %q does not parse: %w", base, err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("web auth: the browser base url %q names no host", base)
	}
	return parsed.Host, nil
}

// ---- the return target --------------------------------------------------------

// maxReturnTarget bounds the value. It arrives in a query string and travels in a
// cookie and a Location header; an unbounded one is a cookie the browser silently
// drops and a header nobody wants to read.
const maxReturnTarget = 2048

// returnTarget is the validator FR-113 requires: a local path, or nothing.
//
// Without it /auth/login is an open redirect with a login button on it — the most
// credible phishing surface a hub can have, because the redirect is served by the
// real origin after a real sign-in.
//
// The rule is deliberately whole-string rather than a parse alone: `//evil.example`
// is a scheme-relative URL that every "starts with a slash" check lets through, and
// `/\evil.example` is the same trick against a browser that normalises the
// backslash. What survives those is a path, and it is returned verbatim so a query
// and a fragment come back too.
func returnTarget(raw string) string {
	const fallback = "/"

	if raw == "" || len(raw) > maxReturnTarget || raw[0] != '/' {
		return fallback
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, `/\`) {
		return fallback
	}
	for i := range len(raw) {
		// A control byte in a Location header is response splitting; one in a page is
		// a target nobody typed.
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return fallback
		}
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || parsed.Opaque != "" || parsed.Host != "" || parsed.User != nil {
		return fallback
	}
	return raw
}

// ---- the round-trip cookie ----------------------------------------------------

const (
	// oidcCookie carries the state, the PKCE verifier and the return target across
	// the provider round trip.
	oidcCookie = "am_oidc"
	// oidcCookiePath is the one route the value is needed at, so it is the only
	// route a browser sends it to.
	oidcCookiePath = "/auth/callback"
	// oidcCookieTTL is the whole life of a sign-in attempt. Signed rather than
	// stored because this role has no table and the value lives for one redirect
	// (research R3).
	oidcCookieTTL = 90 * time.Second
	// maxSealedRound bounds what is parsed. The cookie is this role's own, but it
	// arrives from a client.
	maxSealedRound = 4096
)

// oidcRound is what the cookie carries. Short keys because the whole value is
// base64 inside a cookie; Issued because the server has to be able to refuse a
// stale round trip on its own — Max-Age is enforced by the browser, and the
// browser is the one party in this flow that cannot be relied on.
type oidcRound struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Issued   int64  `json:"t"`
}

// oidcSigningKey is the key the round-trip cookie is signed with: the configured
// one, or 256 bits drawn at construction.
//
// crypto/rand.Read does not return an error on any platform this runs on — the
// runtime panics if the operating system's entropy source is unavailable — so
// there is no second boot failure mode to design for here.
func oidcSigningKey(configured []byte) []byte {
	if len(configured) > 0 {
		return configured
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

func (s *Server) sealRound(round oidcRound) (string, error) {
	payload, err := json.Marshal(round)
	if err != nil {
		return "", fmt.Errorf("encode the sign-in round trip: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + base64.RawURLEncoding.EncodeToString(s.signRound(body)), nil
}

// openRound verifies and decodes the cookie. The boolean is the whole result: a
// forged signature, a stale round trip and a value that never existed are one
// outcome, because they render one screen and telling them apart in a log would
// eventually mean telling them apart to whoever caused it.
func (s *Server) openRound(sealed string) (oidcRound, bool) {
	if sealed == "" || len(sealed) > maxSealedRound {
		return oidcRound{}, false
	}
	body, signature, split := strings.Cut(sealed, ".")
	if !split {
		return oidcRound{}, false
	}
	sent, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || !hmac.Equal(sent, s.signRound(body)) {
		return oidcRound{}, false
	}

	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return oidcRound{}, false
	}
	var round oidcRound
	if err := json.Unmarshal(payload, &round); err != nil {
		return oidcRound{}, false
	}
	if round.State == "" || round.Verifier == "" {
		return oidcRound{}, false
	}
	if age := time.Now().Unix() - round.Issued; age < 0 || age > int64(oidcCookieTTL.Seconds()) {
		return oidcRound{}, false
	}
	return round, true
}

func (s *Server) signRound(body string) []byte {
	mac := hmac.New(sha256.New, s.oidcKey)
	mac.Write([]byte(body))
	return mac.Sum(nil)
}

func (s *Server) setRoundCookie(c *gin.Context, sealed string) {
	// gosec G124 wants a literal `Secure: true` and cannot see that the value comes
	// from configuration. Hardcoding it would make the quickstart's http origin drop
	// this cookie, which presents as a sign-in that silently never completes.
	http.SetCookie(c.Writer, &http.Cookie{ //nolint:gosec // Secure comes from the configured public base URL.
		Name:     oidcCookie,
		Value:    sealed,
		Path:     oidcCookiePath,
		MaxAge:   int(oidcCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookie,
		// Lax, not Strict: the callback is a top-level navigation the provider
		// caused, and Strict would drop the cookie on exactly that hop.
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) dropRoundCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{ //nolint:gosec // Secure comes from the configured public base URL.
		Name:     oidcCookie,
		Value:    "",
		Path:     oidcCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

// ---- the screens --------------------------------------------------------------

// The notices are the sign-in failures contracts/auth.md names, in the hub's own
// words. They are constants because the copy IS the contract: a person landing
// here has to be able to tell "you are not signed in" from "the hub is broken"
// from "the provider said no", and a caller inventing a sentence is how those
// three collapse into one.
const (
	noticeProviderUnreachable = "The identity provider cannot be reached from this hub, so signing in cannot " +
		"be started. This is the hub's problem rather than your credentials."
	noticeStaleRound = "That sign-in attempt is no longer valid. It may have been left open too long, " +
		"or finished in another tab. Starting again is safe."
	noticeProviderRefused = "The identity provider did not complete sign-in."
	noticeIncomplete      = "Sign-in did not complete. Trying again is safe; if it keeps failing, the hub's " +
		"log carries this page's correlation id."
	noticeHubFailed = "The hub could not complete sign-in. The failure is recorded with this page's " +
		"correlation id, and nothing about your account changed."
	noticeAPIUnavailable = "The hub's api is unavailable, so this screen cannot show what it does not know. " +
		"You are still signed in — this is an outage, not an empty hub."
)

// maxProviderDetail bounds text the provider supplied before it is rendered.
// templ escapes it, and nothing under internal/web may call templ.Raw, so this is
// not the escaping: it is the difference between a reason and a paragraph of
// someone else's making on this origin's page.
const maxProviderDetail = 240

// signin is the only screen a signed-out visitor may render.
func (s *Server) signin(c *gin.Context) {
	target := returnTarget(c.Query("return"))
	if s.deps.Auth != nil {
		// Asked rather than assumed, so the screen does not offer an action it
		// already knows cannot start (contracts/auth.md's second failure row). After
		// the first success this costs nothing: the metadata is discovered once.
		if err := s.deps.Auth.Reachable(c.Request.Context()); err != nil {
			logFrom(c).Error().Err(err).Msg("reach the identity provider")
			s.providerUnreachable(c, target)
			return
		}
	}
	s.renderSignIn(c, view.SignIn{Return: target})
}

// renderSignIn is the only place the sign-in screen is built, so the provider's
// name, the development hint and Unavailable cannot be forgotten on one of the
// seven paths that reach it.
//
// Always a 200: the screen rendered, and what failed is stated on it. A status
// code would be read by nobody — this is a page a person is looking at, and
// /healthz is what a probe reads.
//
// SignInScreen is a whole document rather than a screen inside Layout, so it is
// rendered here rather than through s.render: the shell's sidebar is navigation
// to screens a signed-out visitor may not have, and offering it would be a page
// of links that all bounce back to this one.
func (s *Server) renderSignIn(c *gin.Context, screen view.SignIn) {
	// The action is offered when there is something behind it, and the provider
	// having been reachable a moment ago is the strongest claim this role can make.
	screen.Unavailable = s.deps.Auth == nil
	s.writeSignIn(c, screen)
}

// providerUnreachable is contracts/auth.md's second failure: say that the
// provider cannot be reached, and offer nothing. Unavailable is set explicitly,
// so the screen renders no action at all rather than one known to fail. Note this
// goes through writeSignIn rather than renderSignIn: the latter would recompute
// Unavailable from deps.Auth, which is non-nil here — the provider is configured,
// it just did not answer.
func (s *Server) providerUnreachable(c *gin.Context, target string) {
	s.writeSignIn(c, view.SignIn{
		Return:      target,
		Notice:      noticeProviderUnreachable,
		Tone:        "dan",
		Unavailable: true,
	})
}

// writeSignIn is the only place the screen is written, so the provider's name and
// the development hint's two gates cannot be forgotten on one of the eight paths
// that reach it.
func (s *Server) writeSignIn(c *gin.Context, screen view.SignIn) {
	screen.Provider = s.opts.ProviderName
	// Both gates, here as well as in the component (FR-119). The list is not even
	// carried into the props unless the flag is set, so a component that forgot to
	// check would still have nothing to print.
	if s.opts.DevCredentialHint {
		screen.DevCredentialHint = true
		screen.Credentials = s.opts.DevCredentials
	}

	// A sign-in screen is the one page whose staleness is dangerous: a cached copy
	// is a cached failure notice, and one served after a successful sign-in tells a
	// person they are signed out when they are not.
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	page := components.SignInScreen(s.shell(c, "Sign in", ""), screen)
	if err := page.Render(c.Request.Context(), c.Writer); err != nil {
		logFrom(c).Error().Err(err).Str("screen", "Sign in").Msg("render page")
	}
}

// login mints the round trip and sends the browser to the provider.
func (s *Server) login(c *gin.Context) {
	target := returnTarget(c.Query("return"))
	if s.deps.Auth == nil {
		// FR-108's other half: a screen that tells someone to sign in must provide
		// the means, and an action that cannot work is not the means.
		s.providerUnreachable(c, target)
		return
	}

	state, err := randomState()
	if err != nil {
		logFrom(c).Error().Err(err).Msg("mint sign-in state")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeHubFailed, Tone: "dan"})
		return
	}
	verifier := oauth2.GenerateVerifier()

	// Built before the cookie is set, because a redirect this role cannot build is
	// a round trip nobody should be holding a cookie for.
	authorizationURL, err := s.deps.Auth.AuthorizationURL(c.Request.Context(), state,
		oauth2.S256ChallengeFromVerifier(verifier))
	if err != nil {
		logFrom(c).Error().Err(err).Msg("build the authorization redirect")
		s.providerUnreachable(c, target)
		return
	}

	sealed, err := s.sealRound(oidcRound{
		State:    state,
		Verifier: verifier,
		Return:   target,
		Issued:   time.Now().Unix(),
	})
	if err != nil {
		logFrom(c).Error().Err(err).Msg("seal the sign-in round trip")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeHubFailed, Tone: "dan"})
		return
	}

	s.setRoundCookie(c, sealed)
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, authorizationURL)
}

// callback is the return leg: state, then the exchange, then the mint, then the
// cookie, then back to where they were going.
func (s *Server) callback(c *gin.Context) {
	// The cookie is read and dropped before anything else can happen, whatever
	// happens next (FR-112). Single use is the whole property: with the cookie
	// gone, a callback replayed with the same code finds no verifier and no state
	// to compare against, so it cannot reach the exchange.
	sealed, cookieErr := c.Cookie(oidcCookie)
	s.dropRoundCookie(c)
	c.Header("Cache-Control", "no-store")

	round, opened := s.openRound(sealed)
	// Constant time, and only once the cookie has verified: comparing a state
	// against the zero value of a round trip that failed to open would compare ""
	// to "" and call it a match.
	if cookieErr != nil || !opened ||
		subtle.ConstantTimeCompare([]byte(round.State), []byte(c.Query("state"))) != 1 {
		logFrom(c).Warn().Bool("cookie", cookieErr == nil).Bool("sealed", opened).
			Msg("sign-in callback with no usable round trip")
		s.renderSignIn(c, view.SignIn{Notice: noticeStaleRound, Tone: "warn"})
		return
	}

	// Validated a second time. The cookie is signed, so this value is the one this
	// role put in it — but it arrived in a query string once, and a validator that
	// runs only on the way in is one refactor away from not running.
	target := returnTarget(round.Return)

	// Read AFTER the state check, deliberately. This is the one thing on this route
	// whose text reaches the page, and reflecting it before the round trip proved to
	// be ours would make /auth/callback a way to publish arbitrary copy on this
	// origin under a sign-in heading.
	if refusal := c.Query("error"); refusal != "" {
		logFrom(c).Warn().Msg("the identity provider refused the sign-in")
		s.renderSignIn(c, view.SignIn{
			Return: target,
			Notice: noticeProviderRefused,
			// The provider's own words, in their own field: the component keeps them
			// in an element of their own so an upstream sentence cannot run into the
			// hub's, and templ escapes them like every other value.
			Detail: providerDetail(c),
			Tone:   "dan",
		})
		return
	}

	code := c.Query("code")
	if code == "" {
		logFrom(c).Warn().Msg("sign-in callback carried neither a code nor an error")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeIncomplete, Tone: "dan"})
		return
	}

	ctx := c.Request.Context()
	idToken, err := s.deps.Auth.Exchange(ctx, code, round.Verifier)
	if err != nil {
		// Generic to the browser, specific to the log: the underlying error names the
		// token endpoint and sometimes the client, and neither is the person's
		// business.
		logFrom(c).Error().Err(err).Msg("exchange the authorization code")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeIncomplete, Tone: "dan"})
		return
	}
	if verifyErr := s.deps.Auth.VerifyIDToken(ctx, idToken); verifyErr != nil {
		// The one failure never explained to the browser in any detail
		// (contracts/auth.md): the reasons a token fails verification are a map of
		// what this role checks.
		logFrom(c).Error().Err(verifyErr).Msg("verify the id token")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeIncomplete, Tone: "dan"})
		return
	}

	if s.deps.Sessions == nil {
		logFrom(c).Error().Msg("no session mint is wired, so sign-in cannot complete")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeHubFailed, Tone: "dan"})
		return
	}
	minted, err := s.deps.Sessions.MintSession(ctx, idToken)
	if err != nil {
		// A refusal and an unreachable api render the same screen and log at the same
		// level, because they are the same thing to the person in front of it: their
		// credentials were fine and the hub could not finish. `refused` is for the
		// operator — true means the two roles disagree about a secret, or the api
		// declined the token; false means the api was not reached at all.
		logFrom(c).Error().Err(err).Bool("refused", errors.Is(err, hub.ErrMintRefused)).
			Msg("mint a session")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeHubFailed, Tone: "dan"})
		return
	}

	s.issueSession(c, minted)
	// No token and no subject in this line. The plaintext exists in the cookie and
	// nowhere else, and the identity is the api's to log — it wrote the audit row.
	logFrom(c).Info().Time("expires_at", minted.ExpiresAt).Msg("signed in")
	c.Redirect(http.StatusFound, target)
}

// logout expires the session server-side and then clears the cookie. POST, and
// registered as POST only: a sign-out on GET is triggerable by any image tag on
// any page anyone can get in front of a signed-in viewer.
func (s *Server) logout(c *gin.Context) {
	if s.deps.Sessions != nil {
		switch err := s.deps.Sessions.SignOut(session(c)); {
		case err == nil:
		case errors.Is(err, view.ErrSignedOut):
			// The one error to swallow: the session was already gone, which is the
			// state the person asked for.
		default:
			// The row may still be live. Clearing the cookie is still right — it is
			// this browser's copy — but a cleared cookie over a live session is a
			// credential still valid to whoever else holds it, so it is logged.
			logFrom(c).Error().Err(err).Msg("expire the session server-side")
		}
	}

	s.clearSession(c)
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, "/auth/signin")
}

// ---- the guard ----------------------------------------------------------------

// viewerContextKey is where the guard leaves the viewer it resolved, for the one
// request it resolved it on. FR-116: it is the only place a screen may read an
// identity from, and there is nothing there on any unauthenticated route.
const viewerContextKey = "am_viewer"

// viewerFor is the viewer this request resolved, or nil when it resolved nobody.
// nil is the signed-out shell, which renders no chip at all.
func viewerFor(c *gin.Context) *view.Viewer {
	stored, ok := c.Get(viewerContextKey)
	if !ok {
		return nil
	}
	viewer, ok := stored.(view.Viewer)
	if !ok {
		return nil
	}
	return &viewer
}

// viewerOf maps what the api resolved onto what a component may render.
//
// The two types stay separate deliberately: hub.Viewer is a wire shape, and a
// component able to name it would be a component able to reach the client. This
// is also the only place SignedIn becomes true — it means "the api resolved this
// request", which is the only thing that may make a chip appear.
func viewerOf(resolved hub.Viewer) view.Viewer {
	groups := resolved.Groups
	if groups == nil {
		groups = []string{}
	}
	return view.Viewer{
		SignedIn:    true,
		Subject:     resolved.Subject,
		DisplayName: resolved.DisplayName,
		Email:       resolved.Email,
		Role:        resolved.Role,
		HasRole:     resolved.HasRole,
		Groups:      groups,
	}
}

// unauthenticatedPath is the COMPLETE set of routes reachable without a session
// (contracts/auth.md). Everything else needs one — including a route that does not
// exist, so a 404 cannot be used to enumerate screens.
//
// The path is cleaned first: `/auth/../catalog` is a request for the catalog, and
// a prefix match on the raw path would hand it the exemption.
func unauthenticatedPath(raw string) bool {
	clean := path.Clean(raw)
	switch {
	case clean == "/healthz":
		return true
	case clean == "/static" || strings.HasPrefix(clean, "/static/"):
		return true
	case clean == "/auth" || strings.HasPrefix(clean, "/auth/"):
		return true
	default:
		return false
	}
}

// guard is FR-108 and SC-105: every protected route resolves a session or sends
// the person to sign in, carrying where they were going.
//
// It FAILS CLOSED, including on a missing ViewerSource — the opposite of how the
// other optional dependencies here behave, and deliberately so. A nil Registrar
// means a modal that will not submit, which is a screen test's business; a guard
// that read a nil source as "let everyone through" is one wiring mistake away
// from a hub with no sign-in at all.
func (s *Server) guard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if unauthenticatedPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		token, err := c.Cookie(sessionCookie)
		if err != nil || token == "" || s.deps.Viewers == nil {
			s.toSignIn(c)
			return
		}

		// Every request, no cache. FR-118 is true because the api re-resolves the
		// role from the group-to-role map on each call; a viewer cached here for the
		// length of a visit is the one thing that would make a mapping change take
		// an hour to land.
		viewer, err := s.deps.Viewers.Viewer(session(c))
		switch {
		case errors.Is(err, view.ErrSignedOut):
			// A session that expired mid-visit. Not an error to log at error level and
			// not a failure to explain: it is a redirect to sign-in holding the path
			// they were on.
			logFrom(c).Debug().Msg("request with no usable session")
			s.toSignIn(c)
			return
		case err != nil:
			// FR-122: never an empty result set, and never a sign-out. Being unable to
			// reach the api says nothing about whether this person is signed in, and
			// signing them out here would turn an outage into a lost session.
			logFrom(c).Error().Err(err).Msg("resolve the viewer")
			c.Header("Cache-Control", "no-store")
			s.render(c, http.StatusBadGateway, "Unavailable", "",
				components.Placeholder("The hub's api is unavailable", noticeAPIUnavailable))
			c.Abort()
			return
		}

		resolved := viewerOf(viewer)
		c.Set(viewerContextKey, resolved)

		// FR-117. Signed in, holding no role: a distinct screen saying so and what to
		// ask for. Enforced here rather than screen by screen, because the failure
		// mode is a screen rendering its own empty state, which reads as a hub with
		// nothing in it.
		if !viewer.HasRole {
			s.render(c, http.StatusOK, "No role", "", components.NoRoleScreen(view.NoRole{
				Viewer: resolved,
				Groups: resolved.Groups,
			}))
			c.Abort()
			return
		}

		c.Next()
	}
}

// toSignIn is the signed-out redirect, carrying the requested path (FR-113).
func (s *Server) toSignIn(c *gin.Context) {
	// A GET is a route worth coming back to. Anything else is not: returning
	// someone to a path that only answers POST is a 404 with their work gone, so
	// they land on the hub's front door instead.
	target := "/"
	status := http.StatusSeeOther
	if c.Request.Method == http.MethodGet {
		target = returnTarget(c.Request.URL.RequestURI())
		status = http.StatusFound
	}

	c.Header("Cache-Control", "no-store")
	c.Redirect(status, signInHref(target))
	c.Abort()
}

// signInHref is the sign-in screen carrying a return target. It escapes the
// target the same way the screen's own action does, so a path with a query
// survives one round trip through this page.
func signInHref(target string) string {
	if target == "" || target == "/" {
		return "/auth/signin"
	}
	return "/auth/signin?return=" + url.QueryEscape(target)
}

// ---- odds and ends ------------------------------------------------------------

// randomState is the value that binds one callback to one browser: 256 bits from
// crypto/rand, so it is unguessable rather than merely unique.
func randomState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// providerDetail is the provider's own account of a refusal, bounded and stripped
// of control bytes.
func providerDetail(c *gin.Context) string {
	detail := strings.TrimSpace(c.Query("error_description"))
	if detail == "" {
		detail = strings.TrimSpace(c.Query("error"))
	}

	var out strings.Builder
	for _, r := range detail {
		if out.Len() >= maxProviderDetail {
			out.WriteString("…")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		out.WriteRune(r)
	}
	return strings.TrimSpace(out.String())
}
