package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/logging"
)

// The RFC 8628 device authorisation endpoints (T088, T089).
//
// Both are unauthenticated by definition — a machine with no credential is what
// the flow exists to serve — so everything here is reachable by anyone who can
// reach the hub, and is written on that assumption.

// deviceTokenInterval is the minimum gap between polls the authorize response
// advertises, and the same value slow_down is decided against. A constant rather
// than an Option: it is a term of the contract the CLI implements, not a
// deployment knob, and an operator who lowered it would silently make every
// deployed CLI's polling look compliant when it is not.
const deviceTokenInterval = 5 * time.Second

// devicePath is the page on the hub a human opens to type the user code in. It is
// the web role's route, not this role's, which is why it is a path joined onto the
// configured public base URL rather than a route registered here.
const devicePath = "/device"

// deviceGrantType is fixed by RFC 8628 §3.4 and by the frozen contract's `const`
// on DeviceTokenRequest.grant_type.
const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// maxHostLength is the longest requesting host this hub will bind. 253 is the
// maximum length of a DNS name; anything longer is not a hostname.
const maxHostLength = 253

// deviceTokenError is the RFC 8628 error envelope on its way to the wire.
//
// It is a huma.StatusError so that a refusal travels back through the ordinary
// `return nil, err` path, and it marshals as contract.DeviceTokenError so that
// the emitted schema and the bytes on the wire have one source. It deliberately
// does NOT implement huma.ContentTypeFilter: contract.Error does, which is what
// turns every other failure in this API into application/problem+json, and this
// one response is the single documented exception — a polling client parses these
// field names (see internal/api/contract/error.go).
type deviceTokenError struct{ code string }

func (e deviceTokenError) GetStatus() int { return http.StatusBadRequest }

func (e deviceTokenError) Error() string { return e.code }

func (e deviceTokenError) MarshalJSON() ([]byte, error) {
	return json.Marshal(contract.DeviceTokenError{Error: e.code})
}

// The five values the frozen contract's enum admits, and no sixth. OAuth's
// `invalid_request` is not among them, so a malformed token request is reported as
// invalid_grant — terminal, which is the right instruction for a client whose
// request will not become well-formed by being repeated.
var (
	errAuthorizationPending = deviceTokenError{code: "authorization_pending"}
	errSlowDown             = deviceTokenError{code: "slow_down"}
	errAccessDenied         = deviceTokenError{code: "access_denied"}
	errExpiredToken         = deviceTokenError{code: "expired_token"}
	errInvalidGrant         = deviceTokenError{code: "invalid_grant"}
)

// ---- rate limit --------------------------------------------------------------

// The 429 on POST /v1/device/authorize, which the frozen contract declares and
// which commands.userCodeLength's entropy note requires: 40 bits of user code is
// only enough while the number of LIVE codes stays small, and without a cap an
// attacker can raise that number himself.

const (
	// deviceAuthorizeBurst codes per window per client address. Roomy enough for a
	// team behind one NAT doing first-run installs, small enough that the live-code
	// population an attacker can create stays negligible against 2^40.
	deviceAuthorizeBurst = 30
	// deviceAuthorizeWindow is the fixed window the burst is counted in.
	deviceAuthorizeWindow = time.Minute
	// deviceAuthorizeMaxKeys bounds the limiter's memory. This endpoint is
	// unauthenticated, so the key space is whatever addresses reach the hub.
	deviceAuthorizeMaxKeys = 4096
)

// rateLimiter is a fixed-window counter per key.
//
// In-process, and therefore per replica: two api replicas each allow the burst,
// so the effective cap is the burst times the replica count. That is stated
// rather than hidden, and it is acceptable here because the limit exists to bound
// a population by orders of magnitude, not to meter a quota. A shared limiter
// would be a Redis this project does not run or a table this layer would have to
// migrate.
type rateLimiter struct {
	mu     sync.Mutex
	burst  int
	window time.Duration
	max    int
	seen   map[string]*rateWindow
}

type rateWindow struct {
	started time.Time
	count   int
}

func newRateLimiter(burst int, window time.Duration, maxKeys int) *rateLimiter {
	return &rateLimiter{burst: burst, window: window, max: maxKeys, seen: map[string]*rateWindow{}}
}

// allow reports whether one more request from key fits, and how long the caller
// should be told to wait when it does not.
//
// It fails CLOSED when the key table is full of live entries: an unauthenticated
// endpoint whose limiter can be evicted by flooding it with fresh keys is a
// limiter with an off switch.
func (r *rateLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if window, ok := r.seen[key]; ok {
		if now.Sub(window.started) >= r.window {
			window.started, window.count = now, 1
			return true, 0
		}
		if window.count >= r.burst {
			return false, r.window - now.Sub(window.started)
		}
		window.count++
		return true, 0
	}

	if len(r.seen) >= r.max {
		for k, window := range r.seen {
			if now.Sub(window.started) >= r.window {
				delete(r.seen, k)
			}
		}
		if len(r.seen) >= r.max {
			return false, r.window
		}
	}
	r.seen[key] = &rateWindow{started: now, count: 1}
	return true, 0
}

// limitDeviceAuthorize is the operation's own middleware, so the cap applies to
// this one operation and nothing else.
//
// The key is the peer address and NOT X-Forwarded-For. A client-settable header
// as a rate-limit key is a rate limit with a bypass switch, and this hub has no
// declared trusted-proxy configuration to make the header safe to read. What that
// costs: behind a reverse proxy every caller shares one key, which makes the limit
// hub-wide rather than per client. That is the failure direction that refuses too
// much rather than too little.
//
// It writes the 429 itself rather than returning an error, because the response is
// declared with no body schema and huma's error path would attach one.
func (s *Server) limitDeviceAuthorize(ctx huma.Context, next func(huma.Context)) {
	ok, retryAfter := s.deviceLimiter.allow(peerAddress(ctx.RemoteAddr()), time.Now())
	if ok {
		next(ctx)
		return
	}
	seconds := int(retryAfter.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	ctx.SetHeader("Retry-After", strconv.Itoa(seconds))
	ctx.SetStatus(http.StatusTooManyRequests)
}

// peerAddress strips the port, so a client's many connections share one key.
func peerAddress(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}

// ---- POST /v1/device/authorize ----------------------------------------------

type deviceAuthorizeInput struct {
	Body contract.DeviceAuthorizeRequest
}

type deviceAuthorizeOutput struct {
	Body contract.DeviceAuthorization
}

func (s *Server) deviceAuthorize(ctx context.Context, in *deviceAuthorizeInput) (*deviceAuthorizeOutput, error) {
	log := logging.From(ctx)

	clientID := strings.TrimSpace(in.Body.ClientID)
	host := strings.TrimSpace(in.Body.Host)
	if clientID == "" {
		return nil, huma.Error422UnprocessableEntity("client_id must not be empty")
	}
	if err := validHost(host); err != nil {
		return nil, huma.Error422UnprocessableEntity(err.Error())
	}
	if s.deps.DB == nil {
		return nil, fail(log, fmt.Errorf("no database is configured"))
	}

	result, err := commands.AuthorizeDevice(ctx, s.deps.DB, commands.DeviceAuthorizeInput{
		ClientID: clientID,
		Host:     host,
		Scope:    in.Body.Scope,
		TTL:      s.opts.DeviceCodeTTL,
	})
	if err != nil {
		return nil, fail(log, err)
	}

	// The user code, the host and the expiry — never the device code. The
	// plaintext leaves this process exactly once, in the response body.
	log.Info().
		Str("user_code", result.UserCode).
		Str("requesting_host", host).
		Time("expires_at", result.ExpiresAt).
		Msg("device authorisation opened")

	verification, complete := s.verificationURIs(result.UserCode)
	return &deviceAuthorizeOutput{Body: contract.DeviceAuthorization{
		DeviceCode:              result.DeviceCode,
		UserCode:                result.UserCode,
		VerificationURI:         verification,
		VerificationURIComplete: complete,
		ExpiresIn:               int(s.opts.DeviceCodeTTL.Seconds()),
		Interval:                int(deviceTokenInterval.Seconds()),
	}}, nil
}

// validHost refuses a requesting host rather than sanitising one.
//
// This value is bound to the authorisation, written into an audit row and
// rendered to the approving human so that approval is an informed act (FR-041).
// Anything outside the set a hostname can be made of is refused for the reason
// the correlation-id pattern refuses instead of trimming, and the reason the
// archive extractor refuses hostile entries: a repaired value is a value nobody
// can reason about afterwards. Letters, digits, dot, dash, underscore and colon —
// underscore because Windows and Docker hostnames carry them, colon for a bare
// IPv6 literal.
func validHost(host string) error {
	if host == "" {
		return errors.New("host must not be empty")
	}
	if len(host) > maxHostLength {
		return fmt.Errorf("host must be at most %d characters", maxHostLength)
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_', r == ':':
		default:
			return errors.New("host may contain only letters, digits, '.', '-', '_' and ':'")
		}
	}
	return nil
}

// verificationURIs builds the two URLs the response advertises.
//
// Both are derived from the CONFIGURED public base URL and never from the
// request's Host header. A client-supplied Host would let a caller choose the
// address a human is then told to open, which is a phishing primitive handed out
// by the login endpoint itself. When no base URL is configured the paths are
// returned bare, which is wrong for a deployment and harmless in a test — and it
// is a deployment misconfiguration rather than something to guess around.
func (s *Server) verificationURIs(userCode string) (verification, complete string) {
	verification = strings.TrimSuffix(s.opts.PublicBaseURL, "/") + devicePath
	return verification, verification + "?user_code=" + url.QueryEscape(userCode)
}

// ---- POST /v1/device/token --------------------------------------------------

// deviceTokenInput takes the body as raw bytes because RFC 8628 §3.4 fixes it as
// form-encoded and huma models an object body as JSON. The document still
// declares the real schema — see declareRequestBody in operations.go.
type deviceTokenInput struct {
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

type deviceTokenOutput struct {
	Body contract.DeviceToken
}

func (s *Server) deviceToken(ctx context.Context, in *deviceTokenInput) (*deviceTokenOutput, error) {
	log := logging.From(ctx)

	form, err := url.ParseQuery(string(in.RawBody))
	if err != nil {
		return nil, errInvalidGrant
	}
	// RFC 8628 §3.4 fixes the grant type, and the frozen contract declares it as a
	// `const`. Anything else is not this grant and never becomes it.
	if form.Get("grant_type") != deviceGrantType {
		return nil, errInvalidGrant
	}
	clientID := strings.TrimSpace(form.Get("client_id"))
	deviceCode := strings.TrimSpace(form.Get("device_code"))
	if clientID == "" || deviceCode == "" {
		return nil, errInvalidGrant
	}
	if s.deps.DB == nil {
		return nil, fail(log, fmt.Errorf("no database is configured"))
	}

	result, err := commands.ConsumeDevice(ctx, s.deps.DB, commands.DeviceTokenInput{
		ClientID:   clientID,
		DeviceCode: deviceCode,
		TokenTTL:   s.opts.DeviceTokenTTL,
		Interval:   deviceTokenInterval,
	})
	if err != nil {
		return nil, deviceTokenFailure(log, err)
	}

	// The host and the expiry. Not the token, not the device code (FR-007's rule in
	// the CLI is the same rule here: no credential reaches any output stream).
	log.Info().
		Str("requesting_host", result.Host).
		Time("expires_at", result.ExpiresAt).
		Msg("device token issued")

	return &deviceTokenOutput{Body: contract.DeviceToken{
		AccessToken: result.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.opts.DeviceTokenTTL.Seconds()),
		// refresh_token is omitted, not empty.
		//
		// This build issues none, and the field's own description says it is
		// "present only when the client may refresh without a second human
		// approval" — which this build cannot offer honestly. There is no column to
		// record a refresh grant in, so a refresh token would have to be either a
		// second `session` row that renews itself without any human in the loop, or
		// a self-contained token the middleware does not know how to verify. Both
		// are a second credential system, and FR-045 — group loss takes effect at
		// the next token refresh — is only checkable if a refresh re-reads the
		// identity, which is what a fresh human approval already does.
		//
		// The cost, stated plainly: a CLI must be re-approved by a human once every
		// DEVICE_TOKEN_TTL (one hour by default). An operator who finds that too
		// coarse raises DEVICE_TOKEN_TTL; the honest fix is a refresh grant with a
		// row to record it in, which is a migration.
	}}, nil
}

// deviceTokenFailure maps a command's sentinel onto the one RFC 8628 value that
// tells a polling client what to do next.
//
// Only authorization_pending and slow_down are non-terminal; the other three must
// stop the client. Anything the switch does not recognise is NOT one of the five —
// it is this server having failed — and it becomes a 500 rather than
// invalid_grant. Reporting a database outage as invalid_grant would tell every
// polling CLI to give up and every user to start again, for a fault none of them
// caused.
func deviceTokenFailure(log zerolog.Logger, err error) error {
	switch {
	case errors.Is(err, commands.ErrDeviceCodePending):
		return errAuthorizationPending
	case errors.Is(err, commands.ErrDeviceCodeTooFast):
		return errSlowDown
	case errors.Is(err, commands.ErrDeviceCodeExpired):
		return errExpiredToken
	case errors.Is(err, commands.ErrDeviceCodeDenied):
		return errAccessDenied
	case errors.Is(err, commands.ErrDeviceCodeUnknown), errors.Is(err, commands.ErrDeviceCodeUsed):
		return errInvalidGrant
	default:
		return fail(log, err)
	}
}
