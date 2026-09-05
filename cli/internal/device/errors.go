package device

import (
	"errors"
	"fmt"
)

// ErrorCode is a token-endpoint error code from RFC 8628 §3.5, carried
// verbatim from the hub. Two of the five declared codes mean keep polling,
// three are final.
type ErrorCode string

const (
	CodeAuthorizationPending ErrorCode = "authorization_pending"
	CodeSlowDown             ErrorCode = "slow_down"
	CodeAccessDenied         ErrorCode = "access_denied"
	CodeExpiredToken         ErrorCode = "expired_token"
	CodeInvalidGrant         ErrorCode = "invalid_grant"
)

// Codes lists the five declared codes in the contract's own order.
func Codes() []ErrorCode {
	return []ErrorCode{
		CodeAuthorizationPending, CodeSlowDown, CodeAccessDenied,
		CodeExpiredToken, CodeInvalidGrant,
	}
}

// Continues reports whether c means the client should poll again. An
// unrecognised code does not continue.
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

func (c ErrorCode) Terminal() bool { return c != "" && !c.Continues() }

// The failures a device authorisation can end in, as sentinels for errors.Is.
var (
	ErrDenied         = errors.New("device authorisation was denied")
	ErrExpired        = errors.New("device code expired before it was approved")
	ErrInvalidGrant   = errors.New("hub rejected the device code")
	ErrUnknownRefusal = errors.New("hub refused the poll with an unrecognised code")
	ErrProtocol       = errors.New("device authorisation response is not usable")
	ErrNoTransport    = errors.New("no device transport given")
	ErrNoClock        = errors.New("no clock given")
)

// terminalError maps a terminal code onto its sentinel, quoting an
// unrecognised code verbatim.
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
