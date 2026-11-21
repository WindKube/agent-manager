package commands

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/auth"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

// The RFC 8628 §3.5 poll outcomes. Sentinels, so a caller who forgets one
// falls through to invalid_grant, the safe direction to fail.
var (
	// ErrDeviceCodeUnknown also covers a wrong client_id or a malformed
	// request, so an attacker can't tell which applied.
	ErrDeviceCodeUnknown = errors.New("device code is unknown")
	ErrDeviceCodePending = errors.New("device authorisation is still pending")
	ErrDeviceCodeTooFast = errors.New("device authorisation was polled faster than the advertised interval")
	ErrDeviceCodeExpired = errors.New("device code has expired")
	ErrDeviceCodeDenied  = errors.New("device authorisation was denied")
	ErrDeviceCodeUsed    = errors.New("device code has already been exchanged")
	// ErrUserCodeUndecidable covers "no such code", "already decided" and
	// "expired" as one error, so the approval page can't enumerate live codes.
	ErrUserCodeUndecidable = errors.New("user code is unknown, expired or already decided")
)

// userCodeAlphabet is Crockford base32 (no I, L, O, U). Exactly 32 glyphs so
// `byte % 32` over crypto/rand bytes stays uniform; the check below enforces it.
const userCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var _ [32]struct{} = [len(userCodeAlphabet)]struct{}{}

// userCodeLength gives 40 bits, too few to be a secret alone; the rate limit
// on POST /v1/device/authorize bounds how many codes are live instead.
const userCodeLength = 8

// NewUserCode draws a human-typable HKQ2-9FTL-shaped code from crypto/rand;
// a predictable sequence here would be a pre-authorised login.
func NewUserCode() (string, error) {
	buf := make([]byte, userCodeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate user code: %w", err)
	}

	out := make([]byte, 0, userCodeLength+1)
	for i, b := range buf {
		if i == userCodeLength/2 {
			out = append(out, '-')
		}
		out = append(out, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
	}
	return string(out), nil
}

// normaliseUserCode forgives case, spaces, the separator, and the confusables
// I/L -> 1, O -> 0. U is not folded: Crockford drops it for obscenity, not
// confusability.
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
	if len(code) == userCodeLength {
		code = code[:userCodeLength/2] + "-" + code[userCodeLength/2:]
	}
	return code
}

// DeviceCodeHash is sha256 (not a KDF; the code already has 256 bits).
// Hashing the client_id in binds the code to the client that opened it: a
// mismatched client_id finds no row. The NUL separator prevents collisions.
func DeviceCodeHash(clientID, deviceCode string) []byte {
	sum := sha256.Sum256([]byte(clientID + "\x00" + deviceCode))
	return sum[:]
}

// DeviceAuthorizeInput opens an authorisation; there is no identity here.
type DeviceAuthorizeInput struct {
	ClientID string
	Host     string
	// Scope is accepted but not stored: a device token's rights come only from
	// the approving identity's role, never from what the client asked for.
	Scope string
	TTL   time.Duration
}

// DeviceAuthorizeResult carries the device code plaintext exactly once; the
// stored row holds only DeviceCodeHash's output.
type DeviceAuthorizeResult struct {
	DeviceCode string
	UserCode   string
	ExpiresAt  time.Time
}

// deviceCodeAttempts bounds redraws on a unique-constraint collision; rows are
// never deleted, so uniqueness is against every code ever issued.
const deviceCodeAttempts = 3

// AuthorizeDevice opens a pending authorisation bound to the requesting host.
// No audit row: there is no actor until a human decides.
func AuthorizeDevice(ctx context.Context, db bun.IDB, in DeviceAuthorizeInput) (DeviceAuthorizeResult, error) {
	if in.ClientID == "" {
		return DeviceAuthorizeResult{}, fmt.Errorf("device authorisation needs a client id")
	}
	if in.Host == "" {
		return DeviceAuthorizeResult{}, fmt.Errorf("device authorisation needs a requesting host")
	}
	if in.TTL <= 0 {
		return DeviceAuthorizeResult{}, fmt.Errorf("device authorisation needs a positive ttl")
	}

	expiresAt := time.Now().UTC().Add(in.TTL)

	for range deviceCodeAttempts {
		deviceCode, err := auth.NewToken()
		if err != nil {
			return DeviceAuthorizeResult{}, err
		}
		userCode, err := NewUserCode()
		if err != nil {
			return DeviceAuthorizeResult{}, err
		}

		row := &models.DeviceAuthorization{
			ID:             models.NewID(),
			DeviceCodeHash: DeviceCodeHash(in.ClientID, deviceCode),
			UserCode:       userCode,
			RequestingHost: in.Host,
			State:          models.DeviceAuthStatePending,
			ExpiresAt:      expiresAt,
		}
		res, err := db.NewInsert().Model(row).On("conflict do nothing").Exec(ctx)
		if err != nil {
			return DeviceAuthorizeResult{}, fmt.Errorf("open device authorisation: %w", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return DeviceAuthorizeResult{}, fmt.Errorf("open device authorisation: %w", err)
		}
		if affected == 1 {
			return DeviceAuthorizeResult{DeviceCode: deviceCode, UserCode: userCode, ExpiresAt: expiresAt}, nil
		}
	}
	return DeviceAuthorizeResult{}, fmt.Errorf(
		"could not open a device authorisation with a free user code in %d attempts", deviceCodeAttempts)
}

// ApproveDevice records approval and returns the host, which the approver is
// shown before deciding (the RFC 8628 phishing defence).
func ApproveDevice(ctx context.Context, db bun.IDB, p auth.Principal, userCode string) (string, error) {
	return decideDevice(ctx, db, p, userCode, models.DeviceAuthStateApproved)
}

// DenyDevice refuses a pending user code. It doesn't set
// approved_by_identity_id, so who denied lives only in the audit row.
func DenyDevice(ctx context.Context, db bun.IDB, p auth.Principal, userCode string) (string, error) {
	return decideDevice(ctx, db, p, userCode, models.DeviceAuthStateDenied)
}

func decideDevice(
	ctx context.Context, db bun.IDB, p auth.Principal, userCode string, state models.DeviceAuthState,
) (string, error) {
	code := normaliseUserCode(userCode)
	if code == "" {
		return "", ErrUserCodeUndecidable
	}
	if p.IdentityID == uuid.Nil {
		return "", fmt.Errorf("deciding a device authorisation needs an identity")
	}

	var decided models.DeviceAuthorization
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		update := tx.NewUpdate().
			Model((*models.DeviceAuthorization)(nil)).
			Set("state = ?", state).
			Set("updated_at = now()").
			// The WHERE clause is the guard, so a race can't beat a Go-side check.
			Where("user_code = ?", code).
			Where("state = ?", models.DeviceAuthStatePending).
			Where("expires_at > now()")
		if state == models.DeviceAuthStateApproved {
			update = update.Set("approved_by_identity_id = ?", p.IdentityID)
		}

		res, err := update.Exec(ctx)
		if err != nil {
			return fmt.Errorf("decide device authorisation: %w", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("decide device authorisation: %w", err)
		}
		if affected == 0 {
			return ErrUserCodeUndecidable
		}

		if err := tx.NewSelect().
			Model((*models.DeviceAuthorization)(nil)).
			Column("id", "requesting_host").
			Where("user_code = ?", code).
			Scan(ctx, &decided.ID, &decided.RequestingHost); err != nil {
			return fmt.Errorf("read requesting host: %w", err)
		}

		host := decided.RequestingHost
		verb := "approved"
		if state == models.DeviceAuthStateDenied {
			verb = "denied"
		}
		// audit_kind has no `deny`; neither code may appear in this row.
		audit := identityAudit(p, models.AuditKindLogin, verb,
			fmt.Sprintf("%s %s a CLI login on %s", memberRef(p), verb, host),
			audit.Device(decided.ID, host))
		audit.Source = auth.CLISource(host)
		return writeAudit(ctx, tx, audit)
	})
	if err != nil {
		return "", err
	}
	return decided.RequestingHost, nil
}

// DeviceTokenInput is one poll of POST /v1/device/token.
type DeviceTokenInput struct {
	ClientID   string
	DeviceCode string
	TokenTTL   time.Duration
	// Interval must match what /v1/device/authorize advertised.
	Interval time.Duration
}

// DeviceTokenResult carries the access token exactly once.
type DeviceTokenResult struct {
	AccessToken string
	ExpiresAt   time.Time
	Host        string
}

// deviceExpireSQL marks the polled row expired; this role has no DELETE grant.
const deviceExpireSQL = `
update device_authorization
   set state = 'expired', updated_at = now()
 where device_code_hash = ?
   and expires_at <= now()
   and state in ('pending', 'approved')`

// deviceReadSQL derives the poll-rate facts in SQL so they use the database
// clock shared across replicas. `?` not `$1`: bun formats placeholders inline.
const deviceReadSQL = `
select
  id,
  state,
  requesting_host,
  approved_by_identity_id,
  updated_at = created_at as never_polled,
  now() - updated_at < make_interval(secs => ?) as polled_too_soon
from device_authorization
where device_code_hash = ?`

// devicePollSQL reuses updated_at as the last-poll marker rather than process
// memory, which would break with more than one api replica.
const devicePollSQL = `
update device_authorization
   set updated_at = now()
 where id = ? and state = 'pending'`

// deviceConsumeSQL checks expiry in `returning`, not `where`, because a WHERE
// guard isn't re-evaluated after a lock wait unless the blocker modified the
// row. clock_timestamp(), since now() would predate the wait.
const deviceConsumeSQL = `
update device_authorization
   set state = 'consumed', updated_at = now()
 where id = ? and state = 'approved'
returning expires_at > clock_timestamp()`

// ConsumeDevice exchanges an approved device code for exactly one access
// token; of two concurrent polls the second's UPDATE matches nothing. The
// steps before that transaction run outside it so the poll stamp commits
// even when the poll returns an error.
func ConsumeDevice(ctx context.Context, db bun.IDB, in DeviceTokenInput) (DeviceTokenResult, error) {
	if in.ClientID == "" || in.DeviceCode == "" {
		return DeviceTokenResult{}, ErrDeviceCodeUnknown
	}
	if in.TokenTTL <= 0 {
		return DeviceTokenResult{}, fmt.Errorf("issuing a device token needs a positive ttl")
	}
	if in.Interval <= 0 {
		return DeviceTokenResult{}, fmt.Errorf("deciding slow_down needs a positive interval")
	}

	hash := DeviceCodeHash(in.ClientID, in.DeviceCode)

	if _, err := db.ExecContext(ctx, deviceExpireSQL, hash); err != nil {
		return DeviceTokenResult{}, fmt.Errorf("expire device authorisation: %w", err)
	}

	var (
		id          uuid.UUID
		state       models.DeviceAuthState
		host        string
		approvedBy  uuid.NullUUID
		neverPolled bool
		tooSoon     bool
	)
	err := db.QueryRowContext(ctx, deviceReadSQL, in.Interval.Seconds(), hash).
		Scan(&id, &state, &host, &approvedBy, &neverPolled, &tooSoon)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return DeviceTokenResult{}, ErrDeviceCodeUnknown
	case err != nil:
		return DeviceTokenResult{}, fmt.Errorf("read device authorisation: %w", err)
	}

	switch state {
	case models.DeviceAuthStatePending:
		if _, pollErr := db.ExecContext(ctx, devicePollSQL, id); pollErr != nil {
			return DeviceTokenResult{}, fmt.Errorf("record device poll: %w", pollErr)
		}
		if tooSoon && !neverPolled {
			return DeviceTokenResult{}, ErrDeviceCodeTooFast
		}
		return DeviceTokenResult{}, ErrDeviceCodePending
	case models.DeviceAuthStateExpired:
		return DeviceTokenResult{}, ErrDeviceCodeExpired
	case models.DeviceAuthStateDenied:
		return DeviceTokenResult{}, ErrDeviceCodeDenied
	case models.DeviceAuthStateConsumed:
		return DeviceTokenResult{}, ErrDeviceCodeUsed
	case models.DeviceAuthStateApproved:
	default:
		// Fail closed on an unknown state.
		return DeviceTokenResult{}, ErrDeviceCodeUnknown
	}

	if !approvedBy.Valid {
		// A row no transition here can produce: corruption, not client error.
		return DeviceTokenResult{}, fmt.Errorf("device authorisation %s is approved by nobody", id)
	}

	token, err := auth.NewToken()
	if err != nil {
		return DeviceTokenResult{}, err
	}
	result := DeviceTokenResult{
		AccessToken: token,
		ExpiresAt:   time.Now().UTC().Add(in.TokenTTL),
		Host:        host,
	}

	err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var stillLive bool
		scanErr := tx.QueryRowContext(ctx, deviceConsumeSQL, id).Scan(&stillLive)
		switch {
		case errors.Is(scanErr, sql.ErrNoRows):
			// Lost a race or already consumed: single use.
			return ErrDeviceCodeUsed
		case scanErr != nil:
			return fmt.Errorf("consume device authorisation: %w", scanErr)
		case !stillLive:
			// Lapsed mid-wait; the rollback undoes the consume.
			return ErrDeviceCodeExpired
		}

		// A plain session for the approver: approving delegates your own
		// access, re-derived per request like any bearer token.
		session := &models.Session{
			ID:         models.NewID(),
			TokenHash:  auth.HashToken(token),
			IdentityID: approvedBy.UUID,
			ExpiresAt:  result.ExpiresAt,
		}
		if _, execErr := tx.NewInsert().Model(session).Exec(ctx); execErr != nil {
			return fmt.Errorf("open device session: %w", execErr)
		}
		return nil
		// No audit row: ApproveDevice already audited the decision.
	})
	if err != nil {
		return DeviceTokenResult{}, err
	}
	return result, nil
}
