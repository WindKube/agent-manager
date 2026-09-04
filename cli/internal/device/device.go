// Package device runs the client half of RFC 8628's device authorisation
// grant as a state machine over an injected clock and an injected transport,
// so the poll interval, slow_down widening and expiry are provable without
// actually waiting. internal/hub owns the HTTP; this package owns the protocol.
//
// It holds no logger, writer or output stream: the device code and user code
// are credentials that must never reach a log, and having nothing to log with
// is the defence that survives a refactor. It does not import internal/hub,
// so a pure state machine stays pure and testable with no HTTP; the command
// layer wraps *hub.Hub to satisfy Transport instead. It does not retry a
// transport failure, so a dead network surfaces immediately rather than
// hiding behind "waiting for approval" for the whole expiry window. It never
// refreshes or reads an expiry out of a token, since hub tokens are opaque
// and carry no claims to read.
package device

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// defaultInterval is RFC 8628 §3.2's default, and also what a hostile or
// broken hub's zero or negative interval is clamped to, since polling every 0
// seconds is a spin loop against someone else's service.
const defaultInterval = 5 * time.Second

// slowDownIncrement is RFC 8628 §3.5's fixed increase for slow_down.
const slowDownIncrement = 5 * time.Second

// AuthorizeRequest is what opens an authorisation. Host is shown to the
// approving human so approval is informed, and an empty one is refused here
// rather than sent.
type AuthorizeRequest struct {
	ClientID string
	Host     string
	// Scope is space-delimited, or empty for the client's default scope.
	Scope string
}

// PollRequest is one poll of the token endpoint.
type PollRequest struct {
	ClientID   string
	DeviceCode string
}

// Authorization is the authorisation endpoint's answer in this package's
// terms: seconds converted to durations, and no pointers to dereference.
type Authorization struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	// ExpiresIn is how long the device code remains pollable.
	ExpiresIn time.Duration
	// Interval is the minimum gap between polls. Zero means the hub omitted it
	// and defaultInterval applies.
	Interval time.Duration
}

// Issued is the token endpoint's 200 answer.
type Issued struct {
	AccessToken string
	TokenType   string
	// ExpiresIn is the token's lifetime. It is the ONLY statement of that
	// lifetime: the token itself is opaque and carries no expiry to read.
	ExpiresIn    time.Duration
	RefreshToken string
}

// Transport is the narrowest view of the hub this package needs: the two
// unauthenticated device endpoints. Declared here, by the consumer, so the
// state machine can be driven by a fake with no HTTP in it.
type Transport interface {
	// Authorize opens an authorisation (POST /v1/device/authorize).
	Authorize(ctx context.Context, req AuthorizeRequest) (Authorization, error)
	// Poll polls once for the token (POST /v1/device/token). Exactly one of
	// the three returns is meaningful: a token issued (*Issued non-nil, code
	// "", err nil); RFC 8628's 400 error envelope (code set, err nil,
	// including the ordinary authorization_pending/slow_down); or a transport
	// failure (err non-nil). Issued is a pointer so a refusal naming no reason
	// (nil Issued, empty code) stays distinguishable from a successful poll.
	// Wait resolves err first, then code, then the token.
	Poll(ctx context.Context, req PollRequest) (*Issued, ErrorCode, error)
}

// Flow is one authorisation in progress: the codes, the deadline and the
// interval currently in force.
//
// Every field carrying a code is held in a closure rather than a string,
// since fmt prints unexported struct fields under %v/%+v/%#v without calling
// a String method, but a func field prints only as an address. Combined with
// String below, this stops a careless fmt.Sprintf("%+v", flow) anywhere in
// the CLI from leaking the device code or user code (%#v was measured to
// print verificationURIComplete's raw `?user_code=` query before this was a
// closure; see internal/leakscan's TestTheDeviceFlowNeverRendersTheCodesItHolds).
// verificationURI carries no code and is deliberately a plain string.
//
// A Flow is one login and is not safe for concurrent use, and it is not
// resumable: calling Wait again after it returned polls the same device code
// once more, which a hub that already redeemed it answers with invalid_grant.
type Flow struct {
	transport Transport
	clk       Clock

	clientID   string
	deviceCode func() string
	userCode   func() string

	verificationURI         string
	verificationURIComplete func() string

	// expiresAt is the wall-clock deadline fixed at Begin, not a duration, so
	// a slow poll cannot silently extend the window.
	expiresAt time.Time
	// lifetime is kept only so a message can say how long the human had.
	lifetime time.Duration
	// interval is the gap in force now; slow_down widens it, permanently.
	interval time.Duration
	// slowDown is a field, not the constant, so a test can zero it to prove
	// the never-polls-faster-than-told assertion actually fires.
	slowDown time.Duration

	polls int
}

// Begin opens an authorisation and returns the flow to poll. It makes
// exactly one call and does not poll, since the caller must show the user
// code and verification URI to a human before any waiting is worth doing.
func Begin(ctx context.Context, t Transport, clk Clock, req AuthorizeRequest) (*Flow, error) {
	switch {
	case t == nil:
		return nil, ErrNoTransport
	case clk == nil:
		return nil, ErrNoClock
	case req.ClientID == "":
		return nil, fmt.Errorf("%w: no client id given", ErrProtocol)
	case req.Host == "":
		return nil, fmt.Errorf("%w: no hostname given to bind the authorisation to", ErrProtocol)
	}

	auth, err := t.Authorize(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("opening the device authorisation: %w", err)
	}
	if err := validate(auth); err != nil {
		return nil, err
	}

	deviceCode, userCode, complete := auth.DeviceCode, auth.UserCode, auth.VerificationURIComplete
	return &Flow{
		transport:               t,
		clk:                     clk,
		clientID:                req.ClientID,
		deviceCode:              func() string { return deviceCode },
		userCode:                func() string { return userCode },
		verificationURI:         auth.VerificationURI,
		verificationURIComplete: func() string { return complete },
		expiresAt:               clk.Now().Add(auth.ExpiresIn),
		lifetime:                auth.ExpiresIn,
		interval:                normaliseInterval(auth.Interval),
		slowDown:                slowDownIncrement,
	}, nil
}

// validate refuses an authorisation that cannot be polled. It deliberately
// does not check the user code's shape, since that pattern is the hub's
// business. The interval/expiry case is checked here rather than left to
// pause(): a hub advertising an interval at or beyond its own device code's
// lifetime describes a flow that mathematically cannot complete, and catching
// it up front avoids `amctl login` printing a code and then reporting it
// expired on every identical retry.
func validate(a Authorization) error {
	interval := normaliseInterval(a.Interval)
	switch {
	case a.DeviceCode == "":
		return fmt.Errorf("%w: no device code", ErrProtocol)
	case a.UserCode == "":
		return fmt.Errorf("%w: no user code, so nothing to show the human", ErrProtocol)
	case a.VerificationURI == "":
		return fmt.Errorf("%w: no verification URI, so nowhere to send the human", ErrProtocol)
	case a.ExpiresIn <= 0:
		return fmt.Errorf("%w: expires_in is %v, so the authorisation is already dead", ErrProtocol, a.ExpiresIn)
	case interval >= a.ExpiresIn:
		return fmt.Errorf("%w: the hub asks for one poll every %v and expires the code after %v, so there is no window in which it could be approved",
			ErrProtocol, interval, a.ExpiresIn)
	default:
		return nil
	}
}

// normaliseInterval applies the RFC default and clamps a zero or negative
// interval, so a hostile or misbehaving hub cannot force a spin loop.
func normaliseInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultInterval
	}
	return d
}

// UserCode is the code the human types. Show it; never log it.
func (f *Flow) UserCode() string { return f.userCode() }

// VerificationURI is the page the human opens.
func (f *Flow) VerificationURI() string { return f.verificationURI }

// VerificationURIComplete is the same page with the code pre-filled, or "" if
// the hub sent none. Embeds the user code: displayable, never loggable.
func (f *Flow) VerificationURIComplete() string { return f.verificationURIComplete() }

// Interval is the gap between polls currently in force, which slow_down may
// have widened.
func (f *Flow) Interval() time.Duration { return f.interval }

// ExpiresAt is when polling must stop.
func (f *Flow) ExpiresAt() time.Time { return f.expiresAt }

// Polls is how many times the token endpoint has been polled.
func (f *Flow) Polls() int { return f.polls }

// String implements fmt.Stringer so %v/%+v render this and not the struct.
// Neither code appears.
func (f *Flow) String() string {
	return fmt.Sprintf("device authorisation at %s (interval %v, %d polls)",
		f.verificationURI, f.interval, f.polls)
}

// Token is an issued credential and its lifetime. The token is behind a
// method and not an exported field, and the field is a closure rather than a
// string, so no fmt verb (including %#v, which skips String) can render the
// credential itself.
type Token struct {
	access  func() string
	refresh func() string

	// TokenType is "Bearer".
	TokenType string
	// ExpiresIn is the lifetime the hub stated; the token itself is opaque
	// and carries nothing to parse.
	ExpiresIn time.Duration
	// ExpiresAt is measured from the clock at receipt, not the request, so a
	// slow response cannot make the CLI overestimate the token's lifetime.
	ExpiresAt time.Time
}

// AccessToken is the bearer credential.
func (t *Token) AccessToken() string {
	if t.access == nil {
		return ""
	}
	return t.access()
}

// RefreshToken is the refresh credential and whether the hub sent one;
// absence is normal, not an error.
func (t *Token) RefreshToken() (string, bool) {
	if t.refresh == nil {
		return "", false
	}
	v := t.refresh()
	return v, v != ""
}

// String implements fmt.Stringer; a defence, not a nicety (see the type comment).
func (t *Token) String() string {
	return fmt.Sprintf("%s token (expires in %v)", t.TokenType, t.ExpiresIn)
}

// Wait polls until the hub issues a token or the flow ends. It returns the
// token, or one of ErrDenied, ErrExpired, ErrInvalidGrant, ErrUnknownRefusal,
// the transport's own error, or the context's error (always distinguishable
// via errors.Is, never conflated with a refusal). The first poll is
// immediate, and every later gap is at least the interval in force,
// measured from when a poll returned rather than when it was issued.
func (f *Flow) Wait(ctx context.Context) (*Token, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, cancelled(err)
		}
		if !f.clk.Now().Before(f.expiresAt) {
			return nil, fmt.Errorf("%w: the code's %s window closed with no approval",
				ErrExpired, f.window())
		}

		issued, code, err := f.transport.Poll(ctx, PollRequest{
			ClientID:   f.clientID,
			DeviceCode: f.deviceCode(),
		})
		f.polls++
		if err != nil {
			// A context that ended mid-poll surfaces as the transport's
			// error; keep it recognisable as cancellation.
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				return nil, cancelled(err)
			}
			return nil, fmt.Errorf("polling for the device token: %w", err)
		}
		if code == "" && issued != nil {
			return f.issue(*issued)
		}

		if err := f.apply(code); err != nil {
			return nil, err
		}
		if err := f.pause(ctx); err != nil {
			return nil, err
		}
	}
}

// apply is the state transition for one poll answer. Anything that does not
// say "keep polling" stops the loop. slow_down widens the interval
// permanently, per RFC 8628 §3.5.
func (f *Flow) apply(code ErrorCode) error {
	if !code.Continues() {
		return terminalError(code)
	}
	if code == CodeSlowDown {
		f.interval += f.slowDown
	}
	return nil
}

// pause waits out the interval before the next poll, or refuses to start a
// wait that would end after the code has expired, reporting the expiry now
// rather than after a round trip guaranteed to fail. Since validate already
// refuses interval >= ExpiresIn up front, what reaches this is slow_down
// widening the interval past what is left of an already-started window.
func (f *Flow) pause(ctx context.Context) error {
	remaining := f.expiresAt.Sub(f.clk.Now())
	switch {
	case remaining <= 0:
		return fmt.Errorf("%w: the code's %s window closed while polling", ErrExpired, f.window())
	case f.interval > remaining:
		return fmt.Errorf("%w: the next poll is not due for %v and the code expires in %v",
			ErrExpired, f.interval, remaining)
	}
	if err := f.clk.Wait(ctx, f.interval); err != nil {
		return cancelled(err)
	}
	return nil
}

// issue turns the transport's answer into a Token, stamping the lifetime
// against the clock at receipt.
func (f *Flow) issue(i Issued) (*Token, error) {
	if i.AccessToken == "" {
		return nil, fmt.Errorf("%w: the hub reported success with no access token", ErrProtocol)
	}
	if i.ExpiresIn <= 0 {
		return nil, fmt.Errorf("%w: the hub issued a token with expires_in %v", ErrProtocol, i.ExpiresIn)
	}
	access, refresh := i.AccessToken, i.RefreshToken
	return &Token{
		access:    func() string { return access },
		refresh:   func() string { return refresh },
		TokenType: i.TokenType,
		ExpiresIn: i.ExpiresIn,
		ExpiresAt: f.clk.Now().Add(i.ExpiresIn),
	}, nil
}

// window is the code's full lifetime, for a message that says how long the
// human had.
func (f *Flow) window() string { return f.lifetime.String() }

// cancelled wraps a context failure so it reads as one and still matches
// errors.Is(err, context.Canceled).
func cancelled(err error) error {
	return fmt.Errorf("waiting for device authorisation: %w", err)
}
