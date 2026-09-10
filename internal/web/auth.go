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

// The browser's half of sign-in. This role holds no datastore credential:
// the session row is opened by the api and reached only through the hub client.

// AuthProvider is this role's door to the identity provider.
type AuthProvider interface {
	// Reachable reports whether a sign-in can be started at all.
	Reachable(ctx context.Context) error
	// AuthorizationURL is where the BROWSER is sent, its challenge the S256
	// hash of the verifier held in the round-trip cookie.
	AuthorizationURL(ctx context.Context, state, codeChallenge string) (string, error)
	// Exchange trades an authorization code for a raw ID token, returned
	// exactly as it arrived: the api verifies the same bytes again.
	Exchange(ctx context.Context, code, codeVerifier string) (string, error)
	VerifyIDToken(ctx context.Context, idToken string) error
}

// ViewerSource resolves who a request is acting as. Called on EVERY protected
// request and never cached, since the api re-joins the group-to-role map per request.
type ViewerSource interface {
	Viewer(ctx context.Context) (hub.Viewer, error)
}

// SessionMinter is the api's two session operations: opening one for a
// verified ID token, and expiring it server-side.
type SessionMinter interface {
	MintSession(ctx context.Context, idToken string) (hub.Session, error)
	SignOut(ctx context.Context) error
}

// ---- the identity provider ----------------------------------------------------

// Discovery is the provider's metadata: its published endpoints, and the
// ability to verify a token against its keys. It is an interface because
// internal/archcheck forbids this role from importing the session package.
type Discovery interface {
	Endpoint(ctx context.Context) (oauth2.Endpoint, error)
	VerifyIDToken(ctx context.Context, idToken string) error
}

// AuthOptions is what NewAuthProvider needs.
type AuthOptions struct {
	Discovery    Discovery
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// BrowserBaseURL is the base a BROWSER must use to reach the provider,
	// when it differs from this process's address. Empty means one address
	// serves both.
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
// reached yet. It returns the interface rather than the concrete type: a
// typed nil pointer stored in Deps.Auth would panic on first use instead of
// rendering as "no provider wired".
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

// AuthorizationURL builds the redirect the browser follows. PKCE is not
// optional: the redirect URI is public by definition, so the challenge
// travels here and the verifier stays in a cookie this role signed.
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
	// The AUTHORITY only — the token and key endpoints stay exactly as published.
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

// config is built per call rather than stored: a config from construction
// could be built before the provider was reachable, leaving empty URLs.
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

// browserAuthority is the host and port of a base URL, or "" when there is
// none. Validated at construction so a bad value fails at boot, not sign-in.
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

// maxReturnTarget bounds the value: an unbounded one is a cookie the browser
// silently drops.
const maxReturnTarget = 2048

// returnTarget validates that raw is a local path, or nothing — without it
// /auth/login is an open redirect with a login button on it. Whole-string,
// not a parse alone: `//evil.example` and `/\evil.example` both slip past a
// naive "starts with a slash" check.
func returnTarget(raw string) string {
	const fallback = "/"

	if raw == "" || len(raw) > maxReturnTarget || raw[0] != '/' {
		return fallback
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, `/\`) {
		return fallback
	}
	for i := range len(raw) {
		// A control byte in a Location header is response splitting.
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
	// oidcCookie carries the state, PKCE verifier and return target across
	// the provider round trip.
	oidcCookie     = "am_oidc"
	oidcCookiePath = "/auth/callback"
	// oidcCookieTTL is the whole life of a sign-in attempt.
	oidcCookieTTL = 90 * time.Second
	// maxSealedRound bounds what is parsed: it arrives from a client.
	maxSealedRound = 4096
)

// oidcRound is what the cookie carries. Issued lets the server refuse a
// stale round trip on its own, since Max-Age is enforced by the browser.
type oidcRound struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Issued   int64  `json:"t"`
}

// oidcSigningKey is the key the round-trip cookie is signed with: the
// configured one, or 256 bits drawn at construction.
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

// openRound verifies and decodes the cookie. A forged signature, a stale
// round trip and a value that never existed all collapse to the same bool.
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
	http.SetCookie(c.Writer, &http.Cookie{ //nolint:gosec // Secure comes from the configured public base URL.
		Name:     oidcCookie,
		Value:    sealed,
		Path:     oidcCookiePath,
		MaxAge:   int(oidcCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookie,
		// Lax, not Strict: the callback is a top-level navigation the
		// provider caused, and Strict would drop the cookie on that hop.
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

// The notices are the sign-in failures, in the hub's own words, as constants
// so a caller cannot invent a sentence that collapses them into one.
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

// maxProviderDetail bounds text the provider supplied before it is rendered:
// the difference between a reason and a paragraph of someone else's making.
const maxProviderDetail = 240

// signin is the only screen a signed-out visitor may render.
func (s *Server) signin(c *gin.Context) {
	target := returnTarget(c.Query("return"))
	if s.deps.Auth != nil {
		if err := s.deps.Auth.Reachable(c.Request.Context()); err != nil {
			logFrom(c).Error().Err(err).Msg("reach the identity provider")
			s.providerUnreachable(c, target)
			return
		}
	}
	s.renderSignIn(c, view.SignIn{Return: target})
}

// renderSignIn is the only place the sign-in screen is built. Always a 200:
// the screen rendered, and what failed is stated on it. Rendered directly
// rather than through s.render because it is a whole document, not a screen
// inside Layout — a signed-out visitor has no sidebar to offer.
func (s *Server) renderSignIn(c *gin.Context, screen view.SignIn) {
	screen.Unavailable = s.deps.Auth == nil
	s.writeSignIn(c, screen)
}

// providerUnreachable says the provider cannot be reached and offers nothing.
// Goes through writeSignIn, not renderSignIn: the latter would recompute
// Unavailable from deps.Auth, which is non-nil here.
func (s *Server) providerUnreachable(c *gin.Context, target string) {
	s.writeSignIn(c, view.SignIn{
		Return:      target,
		Notice:      noticeProviderUnreachable,
		Tone:        "dan",
		Unavailable: true,
	})
}

// writeSignIn is the only place the screen is written, so the provider's name
// and the development hint's two gates cannot be forgotten.
func (s *Server) writeSignIn(c *gin.Context, screen view.SignIn) {
	screen.Provider = s.opts.ProviderName
	if s.opts.DevCredentialHint {
		screen.DevCredentialHint = true
		screen.Credentials = s.opts.DevCredentials
	}

	// A cached sign-in page is a cached failure notice.
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
	// Read and dropped before anything else happens: single use means a
	// replayed callback finds no verifier and no state to compare against.
	sealed, cookieErr := c.Cookie(oidcCookie)
	s.dropRoundCookie(c)
	c.Header("Cache-Control", "no-store")

	round, opened := s.openRound(sealed)
	// Constant time, and only once the cookie has verified — otherwise the
	// zero value of a failed-to-open round trip would compare "" to "".
	if cookieErr != nil || !opened ||
		subtle.ConstantTimeCompare([]byte(round.State), []byte(c.Query("state"))) != 1 {
		logFrom(c).Warn().Bool("cookie", cookieErr == nil).Bool("sealed", opened).
			Msg("sign-in callback with no usable round trip")
		s.renderSignIn(c, view.SignIn{Notice: noticeStaleRound, Tone: "warn"})
		return
	}

	// Validated again even though the cookie is signed: it arrived in a query
	// string once too.
	target := returnTarget(round.Return)

	// Read AFTER the state check: reflecting it earlier would make
	// /auth/callback a way to publish arbitrary copy on this origin.
	if refusal := c.Query("error"); refusal != "" {
		logFrom(c).Warn().Msg("the identity provider refused the sign-in")
		s.renderSignIn(c, view.SignIn{
			Return: target,
			Notice: noticeProviderRefused,
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
		// Generic to the browser, specific to the log.
		logFrom(c).Error().Err(err).Msg("exchange the authorization code")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeIncomplete, Tone: "dan"})
		return
	}
	if verifyErr := s.deps.Auth.VerifyIDToken(ctx, idToken); verifyErr != nil {
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
		// `refused` is for the operator only: both cases render the same screen.
		logFrom(c).Error().Err(err).Bool("refused", errors.Is(err, hub.ErrMintRefused)).
			Msg("mint a session")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeHubFailed, Tone: "dan"})
		return
	}

	s.issueSession(c, minted)
	// No token and no subject here: the identity is the api's to log.
	logFrom(c).Info().Time("expires_at", minted.ExpiresAt).Msg("signed in")
	c.Redirect(http.StatusFound, target)
}

// logout expires the session server-side and then clears the cookie. POST
// only: a sign-out on GET is triggerable by any image tag on any page.
func (s *Server) logout(c *gin.Context) {
	if s.deps.Sessions != nil {
		switch err := s.deps.Sessions.SignOut(session(c)); {
		case err == nil:
		case errors.Is(err, view.ErrSignedOut):
			// Already gone, which is the state asked for.
		default:
			// The row may still be live and valid to whoever else holds it.
			logFrom(c).Error().Err(err).Msg("expire the session server-side")
		}
	}

	s.clearSession(c)
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, "/auth/signin")
}

// ---- the guard ----------------------------------------------------------------

// viewerContextKey is where the guard leaves the viewer it resolved. The
// only place a screen may read an identity from.
const viewerContextKey = "am_viewer"

// viewerFor is the viewer this request resolved, or nil when it resolved
// nobody — the signed-out shell, which renders no chip.
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

// viewerOf maps what the api resolved onto what a component may render. The
// two types stay separate so a component can never name hub.Viewer's wire
// shape. This is also the only place SignedIn becomes true.
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

// unauthenticatedPath is the COMPLETE set of routes reachable without a
// session, including a nonexistent one, so a 404 cannot enumerate screens.
// The path is cleaned first, since `/auth/../catalog` names the catalog.
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

// guard resolves a session on every protected route, or sends the person to
// sign in. It FAILS CLOSED, including on a missing ViewerSource: reading a
// nil source as "let everyone through" is one wiring mistake from no sign-in at all.
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

		// Every request, no cache: a cached viewer would make a mapping
		// change take an hour to land.
		viewer, err := s.deps.Viewers.Viewer(session(c))
		switch {
		case errors.Is(err, view.ErrSignedOut):
			logFrom(c).Debug().Msg("request with no usable session")
			s.toSignIn(c)
			return
		case err != nil:
			// Never a sign-out: an outage says nothing about whether this
			// person is signed in.
			logFrom(c).Error().Err(err).Msg("resolve the viewer")
			c.Header("Cache-Control", "no-store")
			s.render(c, http.StatusBadGateway, "Unavailable", "",
				components.Placeholder("The hub's api is unavailable", noticeAPIUnavailable))
			c.Abort()
			return
		}

		resolved := viewerOf(viewer)
		c.Set(viewerContextKey, resolved)

		// Signed in, holding no role: enforced here rather than screen by
		// screen, or the failure mode reads as an empty hub.
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

// toSignIn is the signed-out redirect, carrying the requested path.
func (s *Server) toSignIn(c *gin.Context) {
	// A GET is worth coming back to; a path answering only POST is not.
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

// signInHref is the sign-in screen carrying a return target, escaped so a
// path with a query survives the round trip.
func signInHref(target string) string {
	if target == "" || target == "/" {
		return "/auth/signin"
	}
	return "/auth/signin?return=" + url.QueryEscape(target)
}

// ---- odds and ends ------------------------------------------------------------

// randomState binds one callback to one browser: 256 bits from crypto/rand,
// unguessable rather than merely unique.
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
