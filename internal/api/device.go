package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
)

// The RFC 8628 device authorisation endpoints. Both are unauthenticated by
// definition, so everything here is written for callers who hold no credential.

// deviceTokenInterval is a constant rather than an option: it is a term of the
// contract the CLI implements, not a deployment knob.
const deviceTokenInterval = 5 * time.Second

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// maxHostLength is the maximum length of a DNS name.
const maxHostLength = 253

// deviceTokenError is the RFC 8628 error envelope. It deliberately does not
// implement huma.ContentTypeFilter, so it is the one response not served as
// application/problem+json: polling clients parse these field names.
type deviceTokenError struct{ code string }

func (e deviceTokenError) GetStatus() int { return http.StatusBadRequest }

func (e deviceTokenError) Error() string { return e.code }

func (e deviceTokenError) MarshalJSON() ([]byte, error) {
	return json.Marshal(contract.DeviceTokenError{Error: e.code})
}

// The five values the contract's enum admits. OAuth's `invalid_request` is not
// among them, so a malformed token request is reported as terminal invalid_grant.
var (
	errAuthorizationPending = deviceTokenError{code: "authorization_pending"}
	errSlowDown             = deviceTokenError{code: "slow_down"}
	errAccessDenied         = deviceTokenError{code: "access_denied"}
	errExpiredToken         = deviceTokenError{code: "expired_token"}
	errInvalidGrant         = deviceTokenError{code: "invalid_grant"}
)

// The 429 cap on device authorisation: 40 bits of user code are only enough while
// the number of live codes stays small.
const (
	// Roomy enough for a team behind one NAT, small against 2^40.
	deviceAuthorizeBurst  = 30
	deviceAuthorizeWindow = time.Minute
	// Bounds the limiter's memory; the endpoint is unauthenticated.
	deviceAuthorizeMaxKeys = 4096
)

// limitDeviceAuthorize keys on the peer address, not X-Forwarded-For, since a
// client-settable key is a bypass and no trusted proxy is configured; behind a proxy
// the limit becomes hub-wide. It writes the 429 itself because the response
// declares no body schema and huma's error path would attach one.
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

	// Never log the device code; its plaintext leaves this process only in the response body.
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

// validHost refuses rather than sanitises: the host is shown to the approving human
// and audited, and a repaired value is one nobody can reason about. Underscore is
// allowed for Windows and Docker hostnames, colon for bare IPv6 literals.
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

// verificationURIs derives both URLs from the configured verification URL, never
// the request's Host header, which would let a caller choose where a human is sent.
func (s *Server) verificationURIs(userCode string) (verification, complete string) {
	verification = strings.TrimSuffix(s.opts.DeviceVerificationURL, "/")
	return verification, verification + "?user_code=" + url.QueryEscape(userCode)
}

// deviceTokenInput takes raw bytes because RFC 8628 fixes the body as form-encoded;
// declareRequestBody in operations.go documents the real schema.
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

	// Never log the token or device code.
	log.Info().
		Str("requesting_host", result.Host).
		Time("expires_at", result.ExpiresAt).
		Msg("device token issued")

	return &deviceTokenOutput{Body: contract.DeviceToken{
		AccessToken: result.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.opts.DeviceTokenTTL.Seconds()),
		// refresh_token is omitted: this build has no refresh grant, so a CLI is
		// re-approved by a human once every DEVICE_TOKEN_TTL.
	}}, nil
}

// Approving a machine's login needs a browser session but no organisation role.

type lookupDeviceCodeInput struct {
	UserCode string `path:"user_code" doc:"The code the CLI printed."`
}

type lookupDeviceCodeOutput struct {
	Body contract.PendingDeviceAuthorization
}

func (s *Server) lookupDeviceCode(ctx context.Context, in *lookupDeviceCodeInput) (*lookupDeviceCodeOutput, error) {
	log := logging.From(ctx)
	if s.deps.DB == nil {
		return nil, fail(log, fmt.Errorf("no database is configured"))
	}

	pending, status, err := queries.LookupDeviceCode(ctx, s.deps.DB, in.UserCode)
	if err != nil {
		return nil, fail(log, err)
	}
	if status != queries.DeviceCodePending {
		return nil, deviceCodeRefusal(status)
	}
	return &lookupDeviceCodeOutput{Body: contract.PendingDeviceAuthorization{
		RequestingHost: pending.RequestingHost,
		ExpiresIn:      int(time.Until(pending.ExpiresAt).Seconds()),
	}}, nil
}

type approveDeviceCodeInput struct {
	UserCode string `path:"user_code"`
}

type approveDeviceCodeOutput struct {
	Body contract.ApprovedDeviceAuthorization
}

func (s *Server) approveDeviceCode(ctx context.Context, in *approveDeviceCodeInput) (*approveDeviceCodeOutput, error) {
	log := logging.From(ctx)
	principal, ok := PrincipalFrom(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("missing, expired or invalid token")
	}
	if s.deps.DB == nil {
		return nil, fail(log, fmt.Errorf("no database is configured"))
	}

	host, err := commands.ApproveDevice(ctx, s.deps.DB, principal, in.UserCode)
	if err != nil {
		if errors.Is(err, commands.ErrUserCodeUndecidable) {
			// Non-authoritative read, only to word the refusal; the approval already failed
			// on the transactional guard.
			_, status, lookupErr := queries.LookupDeviceCode(ctx, s.deps.DB, in.UserCode)
			if lookupErr != nil {
				return nil, fail(log, lookupErr)
			}
			return nil, deviceCodeRefusal(status)
		}
		return nil, fail(log, err)
	}
	return &approveDeviceCodeOutput{Body: contract.ApprovedDeviceAuthorization{RequestingHost: host}}, nil
}

// deviceCodeRefusal renders the three distinguishable device-code refusals.
func deviceCodeRefusal(status queries.DeviceCodeStatus) error {
	switch status {
	case queries.DeviceCodeExpired:
		return huma.Error410Gone("this code has expired")
	case queries.DeviceCodeDecided:
		return huma.Error409Conflict("this code has already been decided")
	default:
		return huma.Error404NotFound("no such device authorisation")
	}
}

// deviceTokenFailure maps a command's sentinel onto an RFC 8628 value. Anything
// unrecognised is a server fault and becomes a 500, not invalid_grant, which would
// tell every polling CLI to give up.
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
