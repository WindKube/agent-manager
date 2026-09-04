package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"agent-manager/internal/store/models"
)

// DeviceCodeStatus is why a user code is, or is not, awaiting a decision
// (001 FR-042).
type DeviceCodeStatus int

const (
	// DeviceCodePending is awaiting a decision and still live.
	DeviceCodePending DeviceCodeStatus = iota
	// DeviceCodeUnknown is no matching row at all.
	DeviceCodeUnknown
	// DeviceCodeExpired ran out its validity before it was decided.
	DeviceCodeExpired
	// DeviceCodeDecided is approved, consumed or denied: no longer pending. One
	// value for all three, the same way commands.ErrUserCodeUndecidable is one
	// error for them — a viewer needs to know a code will never work again, not
	// which of the three ways it stopped.
	DeviceCodeDecided
)

// PendingDeviceAuthorization is what FR-041 requires the approving human see
// before deciding: the requesting host and when the code expires.
type PendingDeviceAuthorization struct {
	RequestingHost string
	ExpiresAt      time.Time
}

// normaliseUserCode mirrors commands package's own normaliseUserCode. It cannot
// call that one instead: commands already imports this package (principle
// VIII — a command may read before it writes), so this package importing
// commands back would be a cycle. The two must be kept in step by hand;
// commands/device.go carries the full reasoning for what this forgives.
func normaliseUserCode(typed string) string {
	var out strings.Builder
	out.Grow(len(typed) + 1)
	for _, r := range strings.ToUpper(strings.TrimSpace(typed)) {
		switch r {
		case ' ', '\t', '-':
			continue
		case 'I', 'L':
			out.WriteByte('1')
		case 'O':
			out.WriteByte('0')
		default:
			out.WriteRune(r)
		}
	}
	code := out.String()
	const userCodeLength = 8
	if len(code) == userCodeLength {
		code = code[:userCodeLength/2] + "-" + code[userCodeLength/2:]
	}
	return code
}

const lookupDeviceCodeSQL = `
select requesting_host, state, expires_at, expires_at <= now() as expired
from device_authorization
where user_code = ?`

// LookupDeviceCode classifies a user code for display before it is decided.
//
// It performs no write. Expiry here is a read-time classification against the
// database's clock, not the state transition commands.ConsumeDevice performs
// when a row is actually swept — a code can read as expired here long before
// anything ever sets its stored state to `expired`.
func LookupDeviceCode(ctx context.Context, db bun.IDB, userCode string) (PendingDeviceAuthorization, DeviceCodeStatus, error) {
	code := normaliseUserCode(userCode)
	if code == "" {
		return PendingDeviceAuthorization{}, DeviceCodeUnknown, nil
	}

	var (
		host    string
		state   models.DeviceAuthState
		expires time.Time
		expired bool
	)
	err := db.QueryRowContext(ctx, lookupDeviceCodeSQL, code).Scan(&host, &state, &expires, &expired)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return PendingDeviceAuthorization{}, DeviceCodeUnknown, nil
	case err != nil:
		return PendingDeviceAuthorization{}, DeviceCodeUnknown, fmt.Errorf("look up device code: %w", err)
	}

	switch {
	case expired:
		return PendingDeviceAuthorization{}, DeviceCodeExpired, nil
	case state != models.DeviceAuthStatePending:
		return PendingDeviceAuthorization{}, DeviceCodeDecided, nil
	default:
		return PendingDeviceAuthorization{RequestingHost: host, ExpiresAt: expires}, DeviceCodePending, nil
	}
}
