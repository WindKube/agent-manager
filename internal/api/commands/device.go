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

// The RFC 8628 device authorisation flow's write side (T088, T089, FR-041..FR-043).
//
// Four transitions and nothing else: AuthorizeDevice creates a `pending` row,
// ApproveDevice and DenyDevice are the two things a human may do to it, and
// ConsumeDevice turns an `approved` row into exactly one access token. There is
// no fifth: `expired` is reached by ConsumeDevice on discovery, because am_api
// holds no DELETE on device_authorization and expiry is therefore a state
// transition (internal/store/migrations/20260827150200_roles_and_grants.sql).

// The errors a poll can end in, one per RFC 8628 §3.5 value the frozen contract's
// DeviceTokenError enum admits. They are sentinels rather than an enum-shaped
// return so that a caller which forgets one gets the default branch's
// invalid_grant — terminal, which is the safe direction for the mistake to fall
// in. internal/api/device.go is the only mapper.
var (
	// ErrDeviceCodeUnknown is no matching row: an unknown device code, a device
	// code presented with a client_id other than the one that opened the
	// authorisation, or a malformed request. The three are deliberately one
	// error, for the reason auth.ErrUnauthenticated is one error: which of them it
	// was tells an attacker whether a code ever existed.
	ErrDeviceCodeUnknown = errors.New("device code is unknown")
	// ErrDeviceCodePending means no human has decided yet. The only non-terminal
	// outcome besides ErrDeviceCodeTooFast.
	ErrDeviceCodePending = errors.New("device authorisation is still pending")
	// ErrDeviceCodeTooFast means the client polled again inside the interval it
	// was told to wait. Non-terminal: the client widens its interval and keeps
	// polling.
	ErrDeviceCodeTooFast = errors.New("device authorisation was polled faster than the advertised interval")
	// ErrDeviceCodeExpired is terminal.
	ErrDeviceCodeExpired = errors.New("device code has expired")
	// ErrDeviceCodeDenied is terminal: a human refused this authorisation, which
	// is a decision and not an absence of one.
	ErrDeviceCodeDenied = errors.New("device authorisation was denied")
	// ErrDeviceCodeUsed is terminal: single use, already spent. This is the reply
	// a replay gets, and the reply the loser of two concurrent polls gets.
	ErrDeviceCodeUsed = errors.New("device code has already been exchanged")
	// ErrUserCodeUndecidable is what a human's approval or denial gets when the
	// user code names no row that is still pending and unexpired. One error for
	// "no such code", "already decided" and "expired", so the approval page
	// cannot be used to enumerate live codes.
	ErrUserCodeUndecidable = errors.New("user code is unknown, expired or already decided")
)

// userCodeAlphabet is Crockford base32: the ten digits and the twenty-two
// letters left after removing I, L, O and U.
//
// The frozen contract's pattern is ^[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}$,
// which excludes I, O and U but still admits L. This alphabet is the stricter
// Crockford set and therefore a subset of what the contract accepts: generating
// from it can never emit a code the pattern refuses, and dropping L as well is
// what makes normaliseUserCode's I/L -> 1 mapping unambiguous.
//
// Exactly 32 glyphs, which is the load-bearing part of the length: 256 is a whole
// multiple of 32, so `byte % 32` over uniform bytes is itself uniform and needs
// no rejection sampling. Generating a wider value and substituting glyphs
// afterwards — the obvious wrong version — biases the distribution towards
// whatever the substitutions collapse onto.
const userCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// A compile-time assertion that the alphabet is exactly 32 glyphs, because the
// modulo in NewUserCode is unbiased only while 256 is a whole multiple of it.
// Adding or removing a glyph without noticing would otherwise skew the
// distribution silently, which is the one failure a test over a sample is least
// likely to catch and an attacker most likely to use.
var _ [32]struct{} = [len(userCodeAlphabet)]struct{}{}

// userCodeLength is the number of alphabet glyphs, excluding the separator.
//
// 8 glyphs from a 32-glyph alphabet is 40 bits — about 1.1e12 codes. That is not
// enough on its own to be treated as a secret, and it is not treated as one: the
// entropy has to cover only the window in which a code is live, which is
// Options.DeviceCodeTTL (10 minutes by default), and the number of codes live in
// that window is what an online guess is actually up against. With N live codes a
// single guess succeeds with probability N/2^40, so the mitigation available to
// this layer is to bound N — which is what the rate limit on
// POST /v1/device/authorize does (internal/api/device.go). Without that limit the
// 40 bits would be the whole defence and an attacker could raise N himself, which
// is why the 429 is implemented and not merely declared.
const userCodeLength = 8

// NewUserCode draws a fresh human-typable code in the contract's HKQ2-9FTL shape.
//
// crypto/rand, not math/rand: this value is typed by a human into a page that
// grants a machine that human's access, so a predictable sequence is a
// pre-authorised login.
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

// normaliseUserCode turns what a human typed into what was stored.
//
// Case, surrounding space and the separator are all forgiven, and the three
// glyphs the alphabet excludes are folded onto the ones they are mistaken for —
// I and L onto 1, O onto 0 — which is the entire reason Crockford drops them. U
// is not folded: Crockford excludes it to avoid accidental obscenity, not because
// it is confusable, so a typed U is simply a code that matches nothing.
//
// This forgives typography and nothing else. It does not repair a wrong code, and
// a normalised code that names no pending row is one error, not a hint.
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

// DeviceCodeHash is what the device_code_hash column holds.
//
// sha256 and not a password KDF, for the reason auth.HashToken gives: the input
// carries 256 bits from crypto/rand, so there is no low-entropy secret for an
// attacker to grind against, and a KDF's cost would be paid on every poll of
// every in-flight authorisation.
//
// The client_id is hashed IN, which is how "must be the same client_id that
// opened the authorisation" (the frozen contract's own words on
// DeviceTokenRequest.client_id) is enforced without a client_id column. A poll
// that presents the right device code under a different client_id computes a
// different hash and therefore matches no row — the same ErrDeviceCodeUnknown an
// unknown code gets, which is the right answer to both. The separator is a NUL
// byte so that ("ab", "c") and ("a", "bc") cannot collide.
func DeviceCodeHash(clientID, deviceCode string) []byte {
	sum := sha256.Sum256([]byte(clientID + "\x00" + deviceCode))
	return sum[:]
}

// DeviceAuthorizeInput opens an authorisation. There is no identity here and
// there cannot be one — that is what the device flow is for.
type DeviceAuthorizeInput struct {
	ClientID string
	Host     string
	// Scope is accepted and deliberately NOT stored.
	//
	// The schema carries no column for it, and it would be a permission this
	// system claims to honour and does not: what a device token may do comes from
	// the approving identity's group-to-role mapping, resolved per request
	// (FR-040, FR-044), never from a string the client asked for. Storing it would
	// invite a later reader to enforce it and end up with two answers to "what may
	// this token do".
	Scope string
	TTL   time.Duration
}

// DeviceAuthorizeResult carries the device code plaintext exactly once. It is
// never stored, never logged and never returned by a second call; what the row
// holds is DeviceCodeHash's output.
type DeviceAuthorizeResult struct {
	DeviceCode string
	UserCode   string
	ExpiresAt  time.Time
}

// deviceCodeAttempts is how many times AuthorizeDevice will redraw both codes
// after a unique-constraint collision.
//
// A collision is not merely theoretical here, and the reason is the withheld
// DELETE grant: user_code and device_code_hash are UNIQUE over the whole table
// and rows are never removed, so the uniqueness is against every code the hub has
// ever issued rather than the handful that are live. Three attempts turn a
// once-in-a-very-long-while collision into a retry instead of a 500.
const deviceCodeAttempts = 3

// AuthorizeDevice opens a pending authorisation bound to the requesting host
// (T088, FR-041).
//
// It writes no audit row, and the omission is deliberate: audit_event requires an
// actor and an actor_kind, and at this point there is no actor — nothing has been
// authorised and nobody has decided anything. The audited event is the human's
// approval, which is where the `login` row is written (T090, ApproveDevice).
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

	// The api's clock, matching session.expires_at in Login, while every
	// comparison against it is the database's now(). A skew between the two moves
	// the window by that skew and does nothing else; two clock conventions in one
	// table would be worse.
	expiresAt := time.Now().UTC().Add(in.TTL)

	for range deviceCodeAttempts {
		// auth.NewToken and auth.HashToken rather than a second implementation of
		// "high-entropy opaque token, hashed at rest": one implementation is what
		// stops the device code and the session token from disagreeing about what
		// makes such a token safe.
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
		// `do nothing` rather than reading the constraint name off a driver error:
		// either unique index is a reason to redraw, and both mean the same thing.
		// The cost is that a genuine insert failure would look like a collision,
		// which is why the loop ends in an error rather than in one more attempt.
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

// ApproveDevice records a human's approval of a pending user code and writes the
// `login` audit row naming the host (T090, FR-050).
//
// It returns the requesting host, which is the value FR-041 requires be shown to
// the approving human so that approval is an informed act.
//
// FR-042 says a device code must be "refusable when approved by an identity other
// than the requester". The naive reading — compare the approver against the
// requester — is not implementable and never was: POST /v1/device/authorize
// carries a client_id and a host and no identity at all, which is the entire
// point of the grant. What the requirement is actually about is RFC 8628's
// phishing case, a user code read aloud or pasted into a chat and typed in by
// somebody who is not sitting at the requesting machine, and the three mechanisms
// the schema provides against it are all used: the host is bound at issue and
// displayed to the approver, the deciding identity is recorded in
// approved_by_identity_id, and DenyDevice makes refusal a first-class terminal
// transition rather than the absence of an approval.
//
// A stronger check — proving that the approver is at the requesting machine —
// needs something no column carries: a value the CLI shows on the terminal that
// the approver must type back, or a channel binding between the two requests.
// Adding one is a migration and a contract change, so it is named here rather
// than invented.
func ApproveDevice(ctx context.Context, db bun.IDB, p auth.Principal, userCode string) (string, error) {
	return decideDevice(ctx, db, p, userCode, models.DeviceAuthStateApproved)
}

// DenyDevice refuses a pending user code. Terminal: ConsumeDevice answers a
// denied authorisation with access_denied forever, and no later approval can move
// it, because the transition's WHERE clause requires `pending`.
//
// It does NOT write approved_by_identity_id. The column says `approved_by`, and a
// denier recorded there is a row that reads as an approval to every future query
// — including any that joins it to work out who authorised a machine. Who denied
// is in the audit row instead, which is where "who did what" lives (principle IV).
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
			// The WHERE clause IS the guard, not a read followed by a check: a code
			// that has already been decided, consumed or has expired matches no row
			// and is refused by the database rather than by a Go branch that a
			// concurrent decision could have raced past.
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

		// Read back inside the same transaction, so the host named in the audit row
		// is the host of the row this statement just moved.
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
		// audit_kind has no `deny` value and adding one is `alter type ... add
		// value`, a migration this layer does not make; `login` is the kind whose
		// domain both decisions belong to, and the text says which one it was.
		//
		// The device code is not in this text and must never be: an audit row is
		// read by more people than a session row and outlives the credential.
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
	// TokenTTL is how long the issued access token lasts (FR-043).
	TokenTTL time.Duration
	// Interval is what the client was told to wait between polls. It is the
	// threshold slow_down is decided against, so it must be the same value
	// /v1/device/authorize advertised.
	Interval time.Duration
}

// DeviceTokenResult carries the access token exactly once.
type DeviceTokenResult struct {
	AccessToken string
	ExpiresAt   time.Time
	// Host is the requesting host the token was issued to, for the caller's log
	// line. Not the token, and not the device code.
	Host string
}

// deviceExpireSQL moves a code past its expiry into `expired` before anything
// reads its state.
//
// Expiry is a transition and not a delete: am_api holds no DELETE on this table
// (roles_and_grants.sql, asserted in internal/store/store_test.go), the state
// enum already contains `expired`, and a deleted row would destroy the evidence
// that a code was ever issued.
//
// What this does NOT do is sweep the table. It touches only the row being polled,
// so a pending authorisation whose client walks away stays `pending` past its
// expiry forever. That is inert rather than wrong — every WHERE clause that could
// act on it also tests `expires_at > now()`, so an expired-but-pending row can
// neither be approved nor exchanged — but a row count of pending authorisations
// is not a count of live ones, and a background sweep is the thing that would
// make it one. There is no scheduled job in this layer to host it.
const deviceExpireSQL = `
update device_authorization
   set state = 'expired', updated_at = now()
 where device_code_hash = ?
   and expires_at <= now()
   and state in ('pending', 'approved')`

// deviceReadSQL reads the state plus the two facts the poll-rate rule needs.
//
// Both derived in SQL, so the comparison uses the database's clock: it is the one
// clock every api replica shares, which is what makes the rule below hold across
// replicas rather than per process.
//
// `?` and never `$1`, and the reason is auth.Sessions.Resolve's: bun formats
// placeholders inline and passes no args to the driver, so a `$N` reaches
// Postgres unbound.
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

// devicePollSQL stamps the poll.
//
// THE slow_down MECHANISM, and what it costs. RFC 8628 §3.5 distinguishes
// authorization_pending from slow_down by whether the client polled faster than
// the advertised interval, so the server needs a last-poll timestamp per
// authorisation. No column carries one and this layer adds no migration, so
// updated_at is used as that marker: it is stamped on every poll of a pending
// row, and deviceReadSQL compares the previous value against the interval.
//
// The alternative — a map in the process — was rejected because it is wrong the
// moment the api runs as two replicas: each replica sees half the polls, so a
// client polling twice as fast as allowed looks compliant to both. Postgres is
// the shared clock and the shared memory, and using it costs nothing per poll
// that the poll was not already paying.
//
// What it costs: updated_at on device_authorization no longer means "when the
// state last changed". Nothing reads it that way today, and anything that wants
// to later must read the audit row or created_at instead.
//
// What it does NOT catch, in full:
//
//   - The first poll. A fresh row has updated_at = created_at, and that case is
//     exempted: RFC 8628 asks the client to wait `interval` before polling at
//     all, but charging slow_down for an eager first poll would make every
//     well-behaved client's opening request look abusive.
//   - A poll that finds no row, or one that is not pending. Nothing is stamped,
//     so hammering an expired or denied code is not rate-limited here — it is
//     answered with a terminal error, which a correct client stops on.
//   - Rate across authorisations. This is per row, so a client can poll as fast
//     as it likes by opening several authorisations. The cap on that is the rate
//     limit on POST /v1/device/authorize.
//   - A client polling just barely slower than the interval. That is the
//     definition of compliant, so it is not meant to be caught.
const devicePollSQL = `
update device_authorization
   set updated_at = now()
 where id = ? and state = 'pending'`

// deviceConsumeSQL is the whole `approved` -> `consumed` transition: the state
// guard, the expiry guard and the single-use guard in one statement.
//
// WHY THE EXPIRY CHECK IS IN `returning` AND NOT IN THE `where` CLAUSE, which is
// where every other guard in this file lives. A WHERE clause is evaluated by the
// scan node BEFORE the update tries to lock the row. When something else holds a
// write lock on that row, this statement waits — and Postgres re-evaluates the
// quals afterwards only if the blocker actually modified the row (EvalPlanQual);
// a blocker that merely held a lock leaves the pre-wait evaluation standing. So a
// row whose expiry lapsed during the wait passes a WHERE guard, `now()` and
// `clock_timestamp()` alike — measured, not assumed: see
// TestAnApprovalThatExpiresWhileTheConsumingUpdateWaitsIssuesNoToken, which still
// redeemed an authorisation that had expired a second earlier with the guard
// written that way.
//
// A `returning` expression is projected from the updated row after the lock is
// taken, so `clock_timestamp()` there is the time the row actually changed. The
// caller rolls the transaction back when it comes out false, which is what makes
// the check part of the transition rather than a Go branch beside it: the
// transition only ever STANDS if the row was live when it happened.
//
// `clock_timestamp()` and not `now()` for the same reason: `now()` is the
// transaction's start time, so inside a transaction that waited it reports a
// moment before the wait.
//
// What this does NOT do is move the lapsed row to `expired` — the rollback that
// refuses the exchange also discards any state change made alongside it. The next
// poll's deviceExpireSQL does that, and until one arrives the row reads
// `approved` past its expiry. Inert: every clause that could act on it tests the
// expiry too.
const deviceConsumeSQL = `
update device_authorization
   set state = 'consumed', updated_at = now()
 where id = ? and state = 'approved'
returning expires_at > clock_timestamp()`

// ConsumeDevice exchanges an approved device code for exactly one access token
// (T089, FR-042, FR-043).
//
// The `approved` -> `consumed` transition and the session insert are ONE
// transaction, and the transition is deviceConsumeSQL, whose returned row is
// checked. That is what makes the code single-use under concurrency: two
// simultaneous polls of the same approved code both issue the same UPDATE, the
// second blocks on the row lock, re-evaluates `state = 'approved'` against the
// committed row and matches nothing. A read-then-write would let both through,
// and it is exactly the race a replay test exercises.
//
// The transition carries the EXPIRY as well as the state, and it has to: the
// sweep below (deviceExpireSQL) runs before the transaction, so on its own it
// leaves a window in which a code that lapsed a moment ago is still redeemable.
// deviceConsumeSQL says why that guard is a `returning` expression rather than
// another WHERE clause.
//
// Everything before that transition is deliberately NOT in the transaction. A
// poll of a pending code has to COMMIT its poll stamp before returning an error,
// and a transaction that returns an error rolls back — so a single transaction
// around the whole function would silently discard the last-poll timestamp and
// leave slow_down permanently unreachable. Each of the three statements outside
// the transaction is atomic on its own and none of them is a mutation whose
// partner could be lost.
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
		// A state the enum admits and this switch does not rank. Failing closed is
		// the only safe reading, and invalid_grant is terminal.
		return DeviceTokenResult{}, ErrDeviceCodeUnknown
	}

	if !approvedBy.Valid {
		// approved with no approver is a row no transition here can produce, so it
		// is corruption rather than a client error.
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
			// The row was not `approved` when the statement reached it: somebody else
			// won the race, or the code was consumed between the read above and this
			// statement. Single use means the loser gets no token.
			return ErrDeviceCodeUsed
		case scanErr != nil:
			return fmt.Errorf("consume device authorisation: %w", scanErr)
		case !stillLive:
			// The authorisation lapsed before this transition landed. Returning an
			// error rolls it back, so nothing was consumed and no session is opened —
			// approval is not a licence to collect whenever.
			return ErrDeviceCodeExpired
		}

		// WHOSE PERMISSIONS THIS MACHINE GETS: the approving human's, and nothing
		// else. The session is opened for approved_by_identity_id, so every request
		// the CLI makes with this token resolves through auth.Sessions to that
		// identity — that person's groups, and the role their groups map to,
		// re-derived per request (FR-040, FR-044). Approving a device code is
		// therefore delegating your own access to a named host for the token's
		// lifetime, which is why the host is bound at issue and shown to you before
		// you decide (FR-041), and why the decision is audited.
		//
		// It is a `session` row and not a new token format on purpose. A bearer
		// token reaching this API is resolved by exactly one path —
		// internal/api/middleware.go's authenticate, over auth.Resolver — and a
		// second format would be a login flow whose token the middleware rejects.
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
		// No audit row here. The audited event is the human's decision, written by
		// ApproveDevice; this poll adds no actor and no new decision, and a second
		// `login` row would make one approval look like two sign-ins.
	})
	if err != nil {
		return DeviceTokenResult{}, err
	}
	return result, nil
}
