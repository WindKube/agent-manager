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

// DeviceCodeStatus is why a user code is, or is not, awaiting a decision.
type DeviceCodeStatus int

const (
	// DeviceCodePending is awaiting a decision and still live.
	DeviceCodePending DeviceCodeStatus = iota
	// DeviceCodeUnknown is no matching row at all.
	DeviceCodeUnknown
	// DeviceCodeExpired ran out its validity before it was decided.
	DeviceCodeExpired
	// DeviceCodeDecided is approved, consumed or denied: no longer pending.
	DeviceCodeDecided
)

// PendingDeviceAuthorization is what the approving human sees before deciding:
// the requesting host and when the code expires.
type PendingDeviceAuthorization struct {
	RequestingHost string
	ExpiresAt      time.Time
}

// normaliseUserCode mirrors commands.normaliseUserCode. It is duplicated
// rather than imported to avoid a cycle: commands already imports this package.
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
// It performs no write: expiry here is a read-time classification against the
// database's clock, not the state transition commands.ConsumeDevice performs
// when a row is actually swept.
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
