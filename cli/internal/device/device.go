// Package device runs the client half of RFC 8628's device authorisation grant
// (FR-001, FR-002) as a state machine over an injected clock and an injected
// transport.
//
// It opens no socket, reads no wall clock and sleeps not at all: Transport and
// Clock are parameters, which is what makes the timing behaviour — the poll
// interval, slow_down widening it, the expiry cutting the loop short — provable
// in microseconds instead of minutes. internal/hub owns the HTTP; this package
// owns the protocol.
//
// WHAT IT DELIBERATELY DOES NOT DO.
//
//   - It holds no logger, writer or output stream, and takes none. The device
//     code and the user code are credentials under FR-007 and must never reach
//     a log; the only defence that survives a refactor is having nothing to log
//     with. Everything a caller may show a human comes back as a return value,
//     and the caller decides what to print. Note the asymmetry that follows:
//     the user code MUST be shown to the human (it is the whole point) and MUST
//     NOT be logged, and only the caller knows which stream is which.
//   - It does not import internal/hub. A pure state machine that imports the
//     network client is not pure, and the two device endpoints' bodies are ten
//     scalar fields — cheap to restate, and restating them is what lets the
//     tests run with no HTTP at all. The cost is that *hub.Hub does not satisfy
//     Transport directly and the command layer wraps it in ~25 lines; that is
//     the intended trade and not an oversight.
//   - It does not retry a transport failure. A dead network mid-poll ends the
//     flow with the transport's own error, so FR-040's diagnosis reaches the
//     user. A poll loop that swallowed "unreachable" would spend the entire
//     expiry window hiding a mistyped hub URL behind "waiting for approval".
//   - It never refreshes and never reads an expiry out of a token. Hub tokens
//     are opaque — base64url of 32 random bytes, no claims — so the lifetime is
//     the expires_in that came beside it, which is why Token carries it.
package device

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// defaultInterval is RFC 8628 §3.2: `interval` is OPTIONAL in the
// authorisation response, and "If no value is provided, clients MUST use 5 as
// the default." The hub's contract marks it required and its fake always sends
// it, so this is the belt to that braces — and it is also what a hostile or
// broken hub's zero or negative interval is clamped to, because the natural
// reading of "poll every 0 seconds" is a spin loop against someone else's
// service.
const defaultInterval = 5 * time.Second

// slowDownIncrement is RFC 8628 §3.5 on slow_down: "the interval MUST be
// increased by 5 seconds for this and all subsequent requests". Increased, not
// doubled and not reset — the RFC names the number, so there is no judgement
// call here to get wrong.
const slowDownIncrement = 5 * time.Second

// AuthorizeRequest is what opens an authorisation. Host is not optional
// padding: the hub shows it to the approving human so approval is an informed
// act (FR-001), and an empty one is refused here rather than sent.
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
// unauthenticated device endpoints, and nothing else.
//
// It is declared here, by the consumer, so that the state machine can be
// driven by a fake with no HTTP in it. *hub.Hub does not satisfy it directly —
// its methods speak the generated wire types — so the command layer wraps it;
// see the package comment for why that trade was taken.
type Transport interface {
	// Authorize opens an authorisation (POST /v1/device/authorize).
	Authorize(ctx context.Context, req AuthorizeRequest) (Authorization, error)
	// Poll polls once for the token (POST /v1/device/token).
	//
	// Exactly one of the three returns is meaningful.
	//
	//   - A token was issued: *Issued non-nil, code "", err nil.
	//   - RFC 8628's 400 error envelope: code set, err nil — including for
	//     authorization_pending and slow_down, which are the ordinary course of
	//     a login and not failures.
	//   - Anything else — no answer, a 500, a body that is not a hub's — err
	//     non-nil.
	//
	// Issued is a POINTER so that the fourth combination stays expressible: a
	// nil Issued with an empty code is a hub that refused the poll and named no
	// reason, which the hub client reports as a flow error with an empty code.
	// With a value type that case is indistinguishable from a successful poll
	// and comes out as "the hub issued a token with no token in it", which is
	// the wrong diagnosis for a refusal.
	//
	// Wait resolves a transport that returns more than one: err first, then
	// code, then the token. Preferring the code means a token arriving beside a
	// refusal is discarded rather than used.
	Poll(ctx context.Context, req PollRequest) (*Issued, ErrorCode, error)
}

// Flow is one authorisation in progress: the codes, the deadline and the
// interval currently in force.
//
// Every field is unexported and every field CARRYING A CODE is held in a
// closure rather than a string. That is not decoration. fmt prints the values
// of unexported struct fields under %v, %+v and %#v and cannot call a String
// method on them, so the usual "wrap it in a redacting type" defence does not
// reach them — but a func field prints as an address. Combined with String
// below, a careless fmt.Sprintf("%+v", flow) anywhere in the CLI cannot leak
// the device code or the user code (FR-007). internal/hub's bearerTransport
// does the same thing for the same measured reason.
//
// verificationURIComplete is one of those closures and the reason the rule is
// stated as "every field carrying a code". It was a plain string field, and
// %#v — which does not consult String — printed it in full, including the
// `?user_code=` query parameter that IS the user code. %v, %+v, %s and %q were
// all clean, so the claim above held for four verbs out of five and the fifth
// was the one a hurried debug print reaches for. Measured, then fixed;
// internal/leakscan's TestTheDeviceFlowNeverRendersTheCodesItHolds is what
// keeps it fixed. verificationURI is deliberately NOT a closure: it carries no
// code, and String prints it on purpose.
//
// A Flow is one login and is not safe for concurrent use: Wait mutates the
// interval and the poll count. Nor is it resumable — calling Wait again after
// it returned polls the same device code once more, which a hub that has
// already redeemed it answers with invalid_grant.
type Flow struct {
	transport Transport
	clk       Clock

	clientID   string
	deviceCode func() string
	userCode   func() string

	verificationURI         string
	verificationURIComplete func() string

	// expiresAt is the wall-clock deadline, fixed at Begin from the clock. The
	// hub sends a duration; keeping the deadline instead means a slow poll
	// cannot silently extend the window.
	expiresAt time.Time
	// lifetime is the window the hub granted, kept only so a message can say
	// how long the human had. Nothing decides anything from it.
	lifetime time.Duration
	// interval is the gap in force now. slow_down widens it, permanently.
	interval time.Duration
	// slowDown is how much slow_down widens the interval by. A field and not
	// the constant so the test can set it to zero and prove that the
	// never-polls-faster-than-told assertion actually fires — a gate with no
	// negative control is a gate nobody has checked.
	slowDown time.Duration

	polls int
}

// Begin opens an authorisation and returns the flow to poll.
//
// It makes exactly one call and does not poll: the caller has to show the user
// code and the verification URI to a human before any waiting is worth doing,
// and a one-shot Login that both printed and polled would need the logger this
// package refuses to hold.
func Begin(ctx context.Context, t Transport, clk Clock, req AuthorizeRequest) (*Flow, error) {
	switch {
	case t == nil:
		return nil, ErrNoTransport
	case clk == nil:
		return nil, ErrNoClock
	case req.ClientID == "":
		return nil, fmt.Errorf("%w: no client id given", ErrProtocol)
	case req.Host == "":
		// FR-001: the authorisation is bound to this machine's hostname so the
		// approving human sees what they are approving. Refused rather than
		// sent empty, because the hub cannot tell an unknown host from a
		// client that did not bother.
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

// validate refuses an authorisation that cannot be polled. Note what it does
// NOT check: the shape of the user code. The contract's pattern is the hub's
// business, and a client that rejected a code the hub happily issued would be
// unloggable-in for reasons no message could explain.
//
// The last case is the one worth explaining. A hub whose advertised interval is
// at or beyond the lifetime of its own device code has described a flow that
// mathematically cannot complete: the first poll is immediate, the second is due
// after the code is dead, and there is no gap in which a human could approve
// anything. That is refused HERE, before a code is shown, because pause() —
// which meets the same arithmetic later — can only report it as ErrExpired, and
// measured against a hub advertising interval 86400 with expires_in 900 the
// result was `amctl login` printing a code, printing an expiry fifteen minutes
// away, and then telling the operator their code had expired and to approve it
// inside the window. The code had its full window; the CLIENT refused to wait,
// every retry behaved identically, and the advice was a loop. The fault is the
// hub's numbers, so it is ErrProtocol and it names both.
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

// normaliseInterval applies RFC 8628 §3.2's default and clamps the hostile
// cases. A zero interval is the RFC's "omitted"; a negative one is a hub
// misbehaving, and both land on 5 seconds rather than on a loop that polls as
// fast as the network allows.
func normaliseInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultInterval
	}
	return d
}

// UserCode is the code the human types. Show it; never log it (FR-007).
func (f *Flow) UserCode() string { return f.userCode() }

// VerificationURI is the page the human opens.
func (f *Flow) VerificationURI() string { return f.verificationURI }

// VerificationURIComplete is the same page with the code pre-filled, or "" if
// the hub sent none. It embeds the user code, so it is subject to exactly the
// same rule: displayable, never loggable.
func (f *Flow) VerificationURIComplete() string { return f.verificationURIComplete() }

// Interval is the gap between polls currently in force, which slow_down may
// have widened.
func (f *Flow) Interval() time.Duration { return f.interval }

// ExpiresAt is when polling must stop.
func (f *Flow) ExpiresAt() time.Time { return f.expiresAt }

// Polls is how many times the token endpoint has been polled.
func (f *Flow) Polls() int { return f.polls }

// String implements fmt.Stringer so that %v and %+v on a Flow — or on anything
// holding one — render this and not the struct. Neither code appears.
func (f *Flow) String() string {
	return fmt.Sprintf("device authorisation at %s (interval %v, %d polls)",
		f.verificationURI, f.interval, f.polls)
}

// Token is an issued credential and its lifetime.
//
// The token is behind a method and not an exported field, and String is
// defined, so every fmt verb a caller might reach for renders the description
// instead of the credential (FR-007). %#v does not consult String, which is
// why the field is a closure: it prints as an address.
type Token struct {
	access  func() string
	refresh func() string

	// TokenType is "Bearer".
	TokenType string
	// ExpiresIn is the lifetime the hub stated. Store it with the token or it
	// is gone: the token is opaque and there is nothing in it to parse.
	ExpiresIn time.Duration
	// ExpiresAt is ExpiresIn measured from the clock at the moment the token
	// arrived — the receipt time, not the request time, so a slow response
	// cannot make the CLI believe the token lives longer than it does.
	ExpiresAt time.Time
}

// AccessToken is the bearer credential.
func (t *Token) AccessToken() string {
	if t.access == nil {
		return ""
	}
	return t.access()
}

// RefreshToken is the refresh credential and whether the hub sent one. The
// hub only sends one when the client may refresh without a second human
// approval, so absence is normal and not an error.
func (t *Token) RefreshToken() (string, bool) {
	if t.refresh == nil {
		return "", false
	}
	v := t.refresh()
	return v, v != ""
}

// String implements fmt.Stringer. See the type comment: this is a defence, not
// a nicety.
func (t *Token) String() string {
	return fmt.Sprintf("%s token (expires in %v)", t.TokenType, t.ExpiresIn)
}

// Wait polls until the hub issues a token or the flow ends.
//
// It returns the token, or an error that is one of: ErrDenied, ErrExpired,
// ErrInvalidGrant, ErrUnknownRefusal, the transport's own error, or the
// context's. The context case is always reachable with errors.Is(err,
// context.Canceled) / context.DeadlineExceeded and is never conflated with a
// refusal, because "you pressed Ctrl-C" and "the hub said no" call for
// different sentences.
//
// The polling contract it keeps (FR-002): the first poll is immediate, and
// every gap between consecutive polls is at least the interval in force at the
// earlier of the two. The gap is measured from when a poll RETURNED, not from
// when it was issued, so the request's own duration can only ever make the gap
// larger than promised.
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
			// A context that ended during the poll surfaces here as the
			// transport's error; keep it recognisable as cancellation rather
			// than wrapping it in prose about the hub.
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

// apply is the state transition for one refusal: the whole of what a poll
// answer means. Anything that does not say "keep polling" stops the loop —
// which covers the three terminal codes, a code this build does not recognise,
// and a refusal with no code at all. slow_down widens the interval for the very
// next gap and every later one, per RFC 8628 §3.5's "for this and all
// subsequent requests".
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
// wait that would end after the code has expired.
//
// That refusal is deliberate and is not the same as sleeping until the
// deadline: the next poll would have to happen at or after expiry, so it could
// only ever return expired_token. Reporting the expiry now, rather than after
// one more round trip that is guaranteed to fail, is the same outcome sooner.
//
// What reaches it, now that validate refuses interval >= ExpiresIn up front, is
// the SLOW_DOWN case: an interval that started inside the window and was widened
// past what is left of it. There ErrExpired is close enough to true — the
// remaining window really is shorter than one poll gap the hub itself asked for
// — and it is what bounds slow_down's otherwise unbounded backoff.
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
		// Refused rather than defaulted. Inventing a lifetime for an opaque
		// token means the CLI would keep presenting a credential it has no
		// reason to believe in, and there is nothing in the token to check it
		// against.
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
