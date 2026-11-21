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

// AuthProvider is this role's door to the identity provider.
type AuthProvider interface {
	// Reachable reports whether a sign-in can be started at all.
	Reachable(ctx context.Context) error
	// AuthorizationURL is where the browser is sent; codeChallenge is the S256
	// hash of the verifier held in the round-trip cookie.
	AuthorizationURL(ctx context.Context, state, codeChallenge string) (string, error)
	// Exchange returns the raw ID token unchanged: the api verifies the same bytes again.
	Exchange(ctx context.Context, code, codeVerifier string) (string, error)
	VerifyIDToken(ctx context.Context, idToken string) error
}

// Discovery is the provider's metadata and token verifier. It is an interface
// because internal/archcheck forbids this role from importing the session package.
type Discovery interface {
	Endpoint(ctx context.Context) (oauth2.Endpoint, error)
	VerifyIDToken(ctx context.Context, idToken string) error
}

// AuthOptions configures NewAuthProvider.
type AuthOptions struct {
	Discovery    Discovery
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// BrowserBaseURL is the provider base a browser must use when it differs
	// from the address this process uses. Empty means one address serves both.
	BrowserBaseURL string
}

type authProvider struct {
	discovery    Discovery
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
	browserHost  string
}

// NewAuthProvider assembles the browser flow over a provider it may not have
// reached yet. It returns the interface so a typed nil never lands in Deps.Auth.
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

// AuthorizationURL always uses PKCE: the redirect URI is public, so the
// verifier stays in a cookie this role signed.
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
	// Only the authority: token and key endpoints stay as published.
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

// config is built per call: one built at construction could predate the
// provider being reachable and carry empty URLs.
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

// browserAuthority is validated at construction so a bad value fails at boot, not sign-in.
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

// maxReturnTarget keeps the round-trip cookie under what browsers silently drop.
const maxReturnTarget = 2048

// returnTarget accepts only a local path, otherwise /auth/login is an open
// redirect. `//evil.example` and `/\evil.example` slip past a naive prefix check.
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

const (
	oidcCookie     = "am_oidc"
	oidcCookiePath = "/auth/callback"
	oidcCookieTTL  = 90 * time.Second
	maxSealedRound = 4096
)

// oidcRound is the cookie payload. Issued lets the server refuse a stale round
// trip itself, since Max-Age is only enforced by the browser.
type oidcRound struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Issued   int64  `json:"t"`
}

// oidcSigningKey falls back to a random key drawn at construction.
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

// openRound collapses forged, stale and missing cookies into the same false.
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
		// Strict would drop the cookie on the provider's redirect back.
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

const maxProviderDetail = 240

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

// renderSignIn always answers 200 and states the failure on the screen. It
// bypasses s.render because sign-in is a whole document without the Layout sidebar.
func (s *Server) renderSignIn(c *gin.Context, screen view.SignIn) {
	screen.Unavailable = s.deps.Auth == nil
	s.writeSignIn(c, screen)
}

// providerUnreachable uses writeSignIn because renderSignIn would recompute
// Unavailable from a non-nil deps.Auth.
func (s *Server) providerUnreachable(c *gin.Context, target string) {
	s.writeSignIn(c, view.SignIn{
		Return:      target,
		Notice:      noticeProviderUnreachable,
		Tone:        "dan",
		Unavailable: true,
	})
}

func (s *Server) writeSignIn(c *gin.Context, screen view.SignIn) {
	screen.Provider = s.opts.ProviderName
	if s.opts.DevCredentialHint {
		screen.DevCredentialHint = true
		screen.Credentials = s.opts.DevCredentials
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	page := components.SignInScreen(s.shell(c, "Sign in", ""), screen)
	if err := page.Render(c.Request.Context(), c.Writer); err != nil {
		logFrom(c).Error().Err(err).Str("screen", "Sign in").Msg("render page")
	}
}

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

func (s *Server) callback(c *gin.Context) {
	// Dropped before anything else so a replayed callback finds no verifier.
	sealed, cookieErr := c.Cookie(oidcCookie)
	s.dropRoundCookie(c)
	c.Header("Cache-Control", "no-store")

	round, opened := s.openRound(sealed)
	// Compared only once the cookie verified, or a failed open would compare "" to "".
	if cookieErr != nil || !opened ||
		subtle.ConstantTimeCompare([]byte(round.State), []byte(c.Query("state"))) != 1 {
		logFrom(c).Warn().Bool("cookie", cookieErr == nil).Bool("sealed", opened).
			Msg("sign-in callback with no usable round trip")
		s.renderSignIn(c, view.SignIn{Notice: noticeStaleRound, Tone: "warn"})
		return
	}

	// Revalidated: the signed value originally came from a query string.
	target := returnTarget(round.Return)

	// Read only after the state check, or /auth/callback could publish arbitrary text on this origin.
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
		logFrom(c).Error().Err(err).Msg("exchange the authorization code")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeIncomplete, Tone: "dan"})
		return
	}
	if verifyErr := s.deps.Auth.VerifyIDToken(ctx, idToken); verifyErr != nil {
		logFrom(c).Error().Err(verifyErr).Msg("verify the id token")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeIncomplete, Tone: "dan"})
		return
	}

	minted, err := s.deps.Hub.MintSession(ctx, idToken)
	if err != nil {
		logFrom(c).Error().Err(err).Bool("refused", errors.Is(err, hub.ErrMintRefused)).
			Msg("mint a session")
		s.renderSignIn(c, view.SignIn{Return: target, Notice: noticeHubFailed, Tone: "dan"})
		return
	}

	s.issueSession(c, minted)
	// No token or subject: identity is the api's to log.
	logFrom(c).Info().Time("expires_at", minted.ExpiresAt).Msg("signed in")
	c.Redirect(http.StatusFound, target)
}

// logout is POST only: a GET sign-out is triggerable by any image tag.
func (s *Server) logout(c *gin.Context) {
	switch err := s.deps.Hub.SignOut(session(c)); {
	case err == nil:
	case errors.Is(err, view.ErrSignedOut):
	default:
		// The row may still be live for whoever else holds the token.
		logFrom(c).Error().Err(err).Msg("expire the session server-side")
	}

	s.clearSession(c)
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, "/auth/signin")
}

// viewerContextKey is the only place a screen may read an identity from.
const viewerContextKey = "am_viewer"

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

func viewerGroups(c *gin.Context) []string {
	viewer := viewerFor(c)
	if viewer == nil {
		return nil
	}
	return viewer.Groups
}

// viewerOf keeps components off hub.Viewer's wire shape, and is the only place SignedIn becomes true.
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

// unauthenticatedPath is the complete set of routes reachable without a session,
// so a 404 cannot enumerate screens. Cleaned first: `/auth/../catalog` is the catalog.
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

// guard fails closed: an unreachable api lets nobody through.
func (s *Server) guard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if unauthenticatedPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		token, err := c.Cookie(sessionCookie)
		if err != nil || token == "" {
			s.toSignIn(c)
			return
		}

		// Not cached, so a role mapping change lands immediately.
		viewer, err := s.deps.Hub.Viewer(session(c))
		switch {
		case errors.Is(err, view.ErrSignedOut):
			logFrom(c).Debug().Msg("request with no usable session")
			s.toSignIn(c)
			return
		case err != nil:
			// Not a sign-out: an outage says nothing about the session.
			logFrom(c).Error().Err(err).Msg("resolve the viewer")
			c.Header("Cache-Control", "no-store")
			s.render(c, http.StatusBadGateway, "Unavailable", "",
				components.Placeholder("The hub's api is unavailable", noticeAPIUnavailable))
			c.Abort()
			return
		}

		resolved := viewerOf(viewer)
		c.Set(viewerContextKey, resolved)

		// Enforced here rather than per screen, or a roleless viewer sees an empty hub.
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

func (s *Server) toSignIn(c *gin.Context) {
	// Only a GET is worth returning to.
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

func signInHref(target string) string {
	if target == "" || target == "/" {
		return "/auth/signin"
	}
	return "/auth/signin?return=" + url.QueryEscape(target)
}

func randomState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// providerDetail bounds provider-supplied text and strips control bytes before rendering.
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
