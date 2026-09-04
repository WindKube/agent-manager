// Package device runs the client half of RFC 8628's device authorisation
// grant as a state machine over an injected clock and transport.
package device

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// defaultInterval is RFC 8628 §3.2's default, and the floor a zero or
// negative hub-supplied interval is clamped to.
const defaultInterval = 5 * time.Second

// slowDownIncrement is RFC 8628 §3.5's fixed increase for slow_down.
const slowDownIncrement = 5 * time.Second

// AuthorizeRequest is what opens an authorisation. Host is shown to the
// approving human, and an empty one is refused here rather than sent.
type AuthorizeRequest struct {
	ClientID string
	Host     string
	Scope    string
}

// PollRequest is one poll of the token endpoint.
type PollRequest struct {
	ClientID   string
	DeviceCode string
}

// Authorization is the authorisation endpoint's answer, seconds converted to
// durations.
type Authorization struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               time.Duration
	// Interval zero means the hub omitted it; defaultInterval then applies.
	Interval time.Duration
}

// Issued is the token endpoint's 200 answer.
type Issued struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    time.Duration
	RefreshToken string
}

// Transport is the narrowest view of the hub this package needs, declared by
// the consumer so the state machine can be driven by a fake with no HTTP.
type Transport interface {
	Authorize(ctx context.Context, req AuthorizeRequest) (Authorization, error)
	// Poll returns exactly one of: a token (*Issued set, code ""), an RFC
	// 8628 400 envelope (code set, including authorization_pending/slow_down),
	// or a transport error.
	Poll(ctx context.Context, req PollRequest) (*Issued, ErrorCode, error)
}

// Flow is one authorisation in progress: the codes, the deadline and the
// interval currently in force. Not safe for concurrent use, and not
// resumable once Wait returns.
//
// Every field carrying a code is held in a closure rather than a string: a
// func field prints only as an address under %v/%+v/%#v, which is what
// stops a careless fmt.Sprintf("%+v", flow) from leaking a code.
type Flow struct {
	transport Transport
	clk       Clock

	clientID   string
	deviceCode func() string
	userCode   func() string

	verificationURI         string
	verificationURIComplete func() string

	// expiresAt is a deadline, not a duration, so a slow poll cannot extend it.
	expiresAt time.Time
	lifetime  time.Duration
	// interval is the gap in force now; slow_down widens it permanently.
	interval time.Duration
	slowDown time.Duration

	polls int
}

// Begin opens an authorisation and returns the flow to poll. It does not
// poll: the caller must show the user code first.
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

// validate refuses an authorisation that cannot be polled: an interval at or
// past the code's own lifetime can never complete, and catching that up
// front avoids printing a code that is already doomed.
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

// normaliseInterval clamps a zero or negative interval to defaultInterval.
func normaliseInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultInterval
	}
	return d
}

// UserCode is the code the human types; never log it.
func (f *Flow) UserCode() string { return f.userCode() }

func (f *Flow) VerificationURI() string { return f.verificationURI }

// VerificationURIComplete is "" if the hub sent none.
func (f *Flow) VerificationURIComplete() string { return f.verificationURIComplete() }

func (f *Flow) Interval() time.Duration { return f.interval }

func (f *Flow) ExpiresAt() time.Time { return f.expiresAt }

func (f *Flow) Polls() int { return f.polls }

func (f *Flow) String() string {
	return fmt.Sprintf("device authorisation at %s (interval %v, %d polls)",
		f.verificationURI, f.interval, f.polls)
}

// Token is an issued credential and its lifetime. The token is behind a
// closure-typed field, not a string, so no fmt verb can render it.
type Token struct {
	access  func() string
	refresh func() string

	TokenType string
	ExpiresIn time.Duration
	// ExpiresAt is measured from the clock at receipt, not the request.
	ExpiresAt time.Time
}

func (t *Token) AccessToken() string {
	if t.access == nil {
		return ""
	}
	return t.access()
}

func (t *Token) RefreshToken() (string, bool) {
	if t.refresh == nil {
		return "", false
	}
	v := t.refresh()
	return v, v != ""
}

func (t *Token) String() string {
	return fmt.Sprintf("%s token (expires in %v)", t.TokenType, t.ExpiresIn)
}

// Wait polls until the hub issues a token or the flow ends. The first poll
// is immediate; every later gap is at least the interval in force.
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

// apply is the state transition for one poll answer.
func (f *Flow) apply(code ErrorCode) error {
	if !code.Continues() {
		return terminalError(code)
	}
	if code == CodeSlowDown {
		f.interval += f.slowDown
	}
	return nil
}

// pause waits out the interval, or refuses a wait that would end after the
// code expires rather than let a doomed poll run.
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

// issue turns the transport's answer into a Token.
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

func (f *Flow) window() string { return f.lifetime.String() }

func cancelled(err error) error {
	return fmt.Errorf("waiting for device authorisation: %w", err)
}
