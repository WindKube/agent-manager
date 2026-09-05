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
	"agent-manager/internal/store/models"
)

// The RFC 8628 device authorisation flow's write side. Four transitions:
// AuthorizeDevice creates a `pending` row, ApproveDevice/DenyDevice are a
// human's two possible decisions, and ConsumeDevice turns an `approved`
// row into exactly one access token; `expired` is reached lazily by
// ConsumeDevice since this role holds no DELETE on the table.

// The errors a poll can end in, one per RFC 8628 §3.5 value. They are
// sentinels rather than an enum-shaped return so a caller who forgets one
// falls through to invalid_grant — terminal, the safe direction to fail.
var (
	// ErrDeviceCodeUnknown covers an unknown code, a code presented under
	// the wrong client_id, or a malformed request: one error for all three
	// so an attacker can't learn which case applied.
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

// userCodeAlphabet is Crockford base32 minus I, L, O, U, dropping L too so
// normaliseUserCode's I/L -> 1 mapping is unambiguous. Exactly 32 glyphs
// so `byte % 32` over uniform crypto/rand bytes is itself uniform.
const userCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Compile-time check that the alphabet stays 32 glyphs, since a silent
// drift would skew the modulo above.
var _ [32]struct{} = [len(userCodeAlphabet)]struct{}{}

// userCodeLength is 8 glyphs from a 32-glyph alphabet: 40 bits, not enough
// to be a secret on its own, so the rate limit on POST /v1/device/authorize
// bounds how many codes are live at once instead.
const userCodeLength = 8

// NewUserCode draws a fresh human-typable code in the contract's HKQ2-9FTL
// shape, from crypto/rand: a predictable sequence here is a pre-authorised
// login.
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

// normaliseUserCode forgives case, space, the separator, and I/L -> 1, O -> 0
// (the confusable glyphs Crockford excludes); U is not folded since Crockford
// drops it to avoid obscenity, not confusability. It repairs typography only:
// a normalised code that names no pending row is still just one error.
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

// DeviceCodeHash is what the device_code_hash column holds: sha256, not a
// KDF, since the input already carries 256 bits from crypto/rand. Hashing
// the client_id IN enforces "same client_id that opened the authorisation"
// without a separate column — a mismatched client_id hashes to a row that
// doesn't exist, same as an unknown code. The NUL separator stops
// ("ab","c") and ("a","bc") from colliding.
func DeviceCodeHash(clientID, deviceCode string) []byte {
	sum := sha256.Sum256([]byte(clientID + "\x00" + deviceCode))
	return sum[:]
}

// DeviceAuthorizeInput opens an authorisation; there is no identity here,
// by design.
type DeviceAuthorizeInput struct {
	ClientID string
	Host     string
	// Scope is accepted but deliberately not stored: what a device token may
	// do comes only from the approving identity's role, resolved per
	// request, never from a string the client asked for.
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

// deviceCodeAttempts redraws both codes on a unique-constraint collision:
// never-deleted rows mean uniqueness is against every code ever issued.
const deviceCodeAttempts = 3

// AuthorizeDevice opens a pending authorisation bound to the requesting
// host. It writes no audit row: there is no actor yet, since nobody has
// decided anything. The audited event is the human's later approval.
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
		// auth.NewToken/HashToken, not a second "high-entropy token" impl,
		// so the device code and session token can't disagree on safety.
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

// ApproveDevice records approval and returns the host, shown to the
// approver before they decide — the RFC 8628 phishing defence: bound at
// issue, with the deciding identity recorded.
func ApproveDevice(ctx context.Context, db bun.IDB, p auth.Principal, userCode string) (string, error) {
	return decideDevice(ctx, db, p, userCode, models.DeviceAuthStateApproved)
}

// DenyDevice refuses a pending user code, terminal. It does not write
// approved_by_identity_id — that would read as an approval — so who
// denied lives only in the audit row.
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

	var host string
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		update := tx.NewUpdate().
			Model((*models.DeviceAuthorization)(nil)).
			Set("state = ?", state).
			Set("updated_at = now()").
			// The WHERE clause is the guard, not a read-then-check: a code
			// already decided, consumed or expired matches no row, refused
			// by the database rather than a Go branch a race could beat.
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

		// Read back in the same transaction, so the host is this row's.
		if err := tx.NewSelect().
			Model((*models.DeviceAuthorization)(nil)).
			Column("requesting_host").
			Where("user_code = ?", code).
			Scan(ctx, &host); err != nil {
			return fmt.Errorf("read requesting host: %w", err)
		}

		actor := p.Email
		if actor == "" {
			actor = p.Subject
		}
		verb := "approved"
		if state == models.DeviceAuthStateDenied {
			verb = "denied"
		}
		// audit_kind has no `deny` value; `login` covers both, and the
		// device code must never appear in this text.
		return writeAudit(ctx, tx, models.AuditKindLogin, actor, string(models.ActorKindIdentity),
			fmt.Sprintf("%s %s a CLI login on %s", actor, verb, host), auth.CLISource(host))
	})
	if err != nil {
		return "", err
	}
	return host, nil
}

// DeviceTokenInput is one poll of POST /v1/device/token.
type DeviceTokenInput struct {
	ClientID   string
	DeviceCode string
	TokenTTL   time.Duration
	// Interval must match what /v1/device/authorize advertised: it's the
	// threshold slow_down is decided against.
	Interval time.Duration
}

// DeviceTokenResult carries the access token exactly once.
type DeviceTokenResult struct {
	AccessToken string
	ExpiresAt   time.Time
	Host        string
}

// deviceExpireSQL moves a lapsed code to `expired`, not deleting it (no
// DELETE grant here). It touches only the polled row, not a sweep — inert
// since every WHERE clause also tests expires_at.
const deviceExpireSQL = `
update device_authorization
   set state = 'expired', updated_at = now()
 where device_code_hash = ?
   and expires_at <= now()
   and state in ('pending', 'approved')`

// deviceReadSQL reads the state plus the two facts the poll-rate rule
// needs, both derived in SQL so the comparison uses the database's clock —
// the one clock shared across api replicas. `?` not `$1`: bun formats
// placeholders inline, so a `$N` would reach Postgres unbound.
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

// devicePollSQL implements slow_down: updated_at is reused as the
// last-poll marker (deviceReadSQL compares it) instead of process memory,
// which would break the moment the api runs as two replicas.
const devicePollSQL = `
update device_authorization
   set updated_at = now()
 where id = ? and state = 'pending'`

// deviceConsumeSQL is the `approved` -> `consumed` transition. The expiry
// check lives in `returning`, not `where`: a WHERE guard evaluated before
// a lock wait is not re-checked once the wait ends unless the blocker
// modified the row, so a row that lapses mid-wait would pass it there.
// clock_timestamp(), not now(), which would report a time before the wait.
const deviceConsumeSQL = `
update device_authorization
   set state = 'consumed', updated_at = now()
 where id = ? and state = 'approved'
returning expires_at > clock_timestamp()`

// ConsumeDevice exchanges an approved device code for exactly one access
// token. The transition and the session insert are one transaction: two
// concurrent polls both issue the UPDATE, the second blocks then matches
// nothing, which a read-then-write would not guarantee. Everything before
// that transition runs outside it, since a poll must commit its poll
// stamp even when it then returns an error.
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
		// An unranked state: fail closed with a terminal error.
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
			// Not `approved` when the statement reached it: a race lost, or
			// already consumed. Single use means the loser gets no token.
			return ErrDeviceCodeUsed
		case scanErr != nil:
			return fmt.Errorf("consume device authorisation: %w", scanErr)
		case !stillLive:
			// Lapsed before the transition landed; the rollback means
			// nothing was consumed and no session opened.
			return ErrDeviceCodeExpired
		}

		// This grants the approving human's permissions, re-derived per
		// request through auth.Resolver — approving a device code delegates
		// your own access to the bound host, hence it's a `session` row
		// (the one path bearer tokens resolve through) and not a new format.
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
		// No audit row: the decision was already audited by ApproveDevice,
		// and a second `login` row here would look like two sign-ins.
	})
	if err != nil {
		return DeviceTokenResult{}, err
	}
	return result, nil
}
