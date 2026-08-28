package device

import (
	"errors"
	"fmt"
)

// ErrorCode is a token-endpoint error code from RFC 8628 §3.5, carried
// verbatim from the hub.
//
// The frozen contract declares exactly five (openapi.yaml, DeviceTokenError):
// two of them mean "keep polling" and three of them are final. A client that
// keeps polling after one of the three is following a bug rather than the RFC,
// which is why the classification lives here — in the state machine that acts
// on it — and not in whatever adapter unwraps the hub's 400 body.
type ErrorCode string

// The five codes. Spelled as the wire spells them, so they stay greppable
// against the contract.
const (
	CodeAuthorizationPending ErrorCode = "authorization_pending"
	CodeSlowDown             ErrorCode = "slow_down"
	CodeAccessDenied         ErrorCode = "access_denied"
	CodeExpiredToken         ErrorCode = "expired_token"
	CodeInvalidGrant         ErrorCode = "invalid_grant"
)

// Codes lists the five declared codes in the contract's own order. The tests
// walk it, so a sixth code cannot be added without deciding whether it is
// terminal.
func Codes() []ErrorCode {
	return []ErrorCode{
		CodeAuthorizationPending, CodeSlowDown, CodeAccessDenied,
		CodeExpiredToken, CodeInvalidGrant,
	}
}

// Continues reports whether c means the authorisation is still pending and the
// client should poll again. Exactly two codes do.
//
// An unrecognised code does NOT continue: this client ships separately from
// the hub, so a code neither side has heard of is possible, and the safe
// reading of an unknown refusal is that it is a refusal. Polling on would burn
// the whole expiry window against a hub that has already said no.
func (c ErrorCode) Continues() bool {
	switch c {
	case CodeAuthorizationPending, CodeSlowDown:
		return true
	case CodeAccessDenied, CodeExpiredToken, CodeInvalidGrant:
		return false
	default:
		return false
	}
}

// Terminal reports whether c is one of the three declared codes that are
// final. The empty code is neither terminal nor continuing here: on its own it
// carries no information, and Wait reads it as an issued token or as an unnamed
// refusal depending on whether a token came with it. The loop's own decision
// goes through Continues, not through this, so an unrecognised code stops it.
func (c ErrorCode) Terminal() bool { return c != "" && !c.Continues() }

// The failures a device authorisation can end in. Each is a sentinel so a
// caller can say which happened with errors.Is without parsing prose, and
// none of them is ever the answer to a cancelled context — see Wait.
var (
	// ErrDenied — the human refused the authorisation (access_denied).
	ErrDenied = errors.New("device authorisation was denied")
	// ErrExpired — the device code ran out before anyone approved it. Returned
	// both for the hub's expired_token and for this package noticing the
	// expiry itself against the clock, because they are the same event seen
	// from two sides and a caller has the same thing to say about either.
	ErrExpired = errors.New("device code expired before it was approved")
	// ErrInvalidGrant — the hub will not accept this device code at all
	// (invalid_grant): already redeemed, or issued by another hub.
	ErrInvalidGrant = errors.New("hub rejected the device code")
	// ErrUnknownRefusal — the hub refused the poll with a code this build does
	// not know, or with no code at all. Reported rather than retried; see
	// ErrorCode.Continues.
	ErrUnknownRefusal = errors.New("hub refused the poll with an unrecognised code")
	// ErrProtocol — the hub answered, and what it said cannot drive a device
	// flow: no device code, no verification URI, a non-positive expires_in.
	// Fails closed here rather than three states later with nothing to name.
	ErrProtocol = errors.New("device authorisation response is not usable")
	// ErrNoTransport / ErrNoClock — a caller wired this up wrong. An error and
	// not a panic: a CLI that exits 1 with a sentence beats a stack trace.
	ErrNoTransport = errors.New("no device transport given")
	ErrNoClock     = errors.New("no clock given")
)

// terminalError maps a terminal code onto its sentinel.
//
// The unrecognised case quotes the hub's code verbatim, because this client
// ships separately from the hub and "the hub said something I do not know"
// is only actionable if it says what. An error code is not a credential:
// the device code and the user code are, and neither is ever in one of these
// (FR-007).
func terminalError(code ErrorCode) error {
	switch code {
	case CodeAccessDenied:
		return ErrDenied
	case CodeExpiredToken:
		return fmt.Errorf("%w: the hub says the code has expired", ErrExpired)
	case CodeInvalidGrant:
		return ErrInvalidGrant
	case "":
		return fmt.Errorf("%w: the hub named no reason", ErrUnknownRefusal)
	default:
		return fmt.Errorf("%w: %q", ErrUnknownRefusal, string(code))
	}
}
