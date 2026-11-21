//go:build integration

// The device authorisation flow against a real Postgres: these guarantees (no plaintext
// in the row, single use, expiry as a transition, the token's identity) live in the database.
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
)

const (
	deviceClientID = "agent-manager-cli"
	deviceGrant    = "urn:ietf:params:oauth:grant-type:device_code"
)

// deviceUserCodePattern is transcribed from the frozen contract, not read off the struct tag.
var deviceUserCodePattern = regexp.MustCompile(`^[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}$`)

// deviceHandler is liveHandler with controllable device TTLs.
func deviceHandler(t *testing.T, opts api.Options) http.Handler {
	t.Helper()

	bucket, err := blob.Open(context.Background(), "mem://")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bucket.Close()) })

	return api.New(api.Deps{
		DB:       db,
		Bundles:  bucket.Reader(),
		Sessions: auth.NewSessions(db),
	}, opts).Handler()
}

func requireJSON(t *testing.T, rec *httptest.ResponseRecorder, into any) {
	t.Helper()
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), into), rec.Body.String())
}

// asAPIRole runs fn as am_api, the role `serve api` connects as; the suite's pool is the owner.
func asAPIRole(t *testing.T, fn func(ctx context.Context, conn *pgxpool.Conn)) {
	t.Helper()
	ctx := context.Background()

	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	_, err = conn.Exec(ctx, "set role am_api")
	require.NoError(t, err)
	// A released connection keeps whatever role it last had.
	defer func() {
		_, resetErr := conn.Exec(ctx, "reset role")
		require.NoError(t, resetErr)
	}()

	fn(ctx, conn)
}

func requireUniqueViolation(t *testing.T, err error) {
	t.Helper()

	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23505", pgErr.Code, "want a unique violation, message was %q", pgErr.Message)
}

func pollDeviceToken(t *testing.T, h http.Handler, clientID, deviceCode string) *httptest.ResponseRecorder {
	t.Helper()

	body := fmt.Sprintf("grant_type=%s&device_code=%s&client_id=%s",
		deviceGrant, deviceCode, clientID)
	req := httptest.NewRequest(http.MethodPost, "/v1/device/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func openDeviceAuthorization(t *testing.T, h http.Handler, host string) contract.DeviceAuthorization {
	t.Helper()

	body := fmt.Sprintf(`{"client_id":%q,"host":%q,"scope":"profiles:read"}`, deviceClientID, host)
	rec := request(t, h, http.MethodPost, "/v1/device/authorize", "", body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var out contract.DeviceAuthorization
	requireJSON(t, rec, &out)
	require.Regexp(t, deviceUserCodePattern, out.UserCode)
	require.NotEmpty(t, out.DeviceCode)
	return out
}

func deviceState(t *testing.T, userCode string) string {
	t.Helper()

	var state string
	require.NoError(t, pool.QueryRow(context.Background(),
		"select state::text from device_authorization where user_code = $1", userCode).Scan(&state))
	return state
}

func tokenErrorOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Equal(t, "application/json", strings.Split(rec.Header().Get("Content-Type"), ";")[0],
		"RFC 8628 clients parse this body, so it is application/json and not problem+json")
	var envelope contract.DeviceTokenError
	requireJSON(t, rec, &envelope)
	return envelope.Error
}

func TestDeviceAuthorizeStoresNoCredentialAndBindsTheHost(t *testing.T) {
	h := deviceHandler(t, api.Options{DeviceVerificationURL: "https://hub.example.dev/cli"})
	const host = "dev-laptop-01"

	out := openDeviceAuthorization(t, h, host)
	require.Equal(t, "https://hub.example.dev/cli", out.VerificationURI)
	require.Equal(t, "https://hub.example.dev/cli?user_code="+out.UserCode, out.VerificationURIComplete)
	require.Equal(t, 600, out.ExpiresIn, "the default DEVICE_CODE_TTL is ten minutes")
	require.Equal(t, 5, out.Interval)

	ctx := context.Background()

	// The whole row as text: the plaintext must be nowhere in it, not just absent from one column.
	var rendered string
	require.NoError(t, pool.QueryRow(ctx,
		"select to_jsonb(device_authorization)::text from device_authorization where user_code = $1",
		out.UserCode).Scan(&rendered))
	t.Logf("issued device code: %s", out.DeviceCode)
	t.Logf("stored row:         %s", rendered)
	require.NotContains(t, rendered, out.DeviceCode,
		"the raw device code appears in the row: a database read yields a bearer credential")

	var (
		storedHash []byte
		storedHost string
		state      string
		approvedBy *uuid.UUID
		ttl        time.Duration
	)
	require.NoError(t, pool.QueryRow(ctx,
		`select device_code_hash, requesting_host, state::text, approved_by_identity_id,
		        expires_at - created_at
		   from device_authorization where user_code = $1`, out.UserCode).
		Scan(&storedHash, &storedHost, &state, &approvedBy, &ttl))

	require.Equal(t, commands.DeviceCodeHash(deviceClientID, out.DeviceCode), storedHash)
	require.Equal(t, host, storedHost, "the host is bound at issue")
	require.Equal(t, "pending", state, "nothing is authorised until a human decides")
	require.Nil(t, approvedBy)
	require.InDelta(t, (10 * time.Minute).Seconds(), ttl.Seconds(), 5,
		"the expiry is the advertised one")

	t.Run("the stored hash cannot be replayed as a device code", func(t *testing.T) {
		for name, replay := range map[string]string{
			"raw bytes": string(storedHash),
			"hex":       fmt.Sprintf("%x", storedHash),
			"base64":    encodeBase64(storedHash),
		} {
			require.Equalf(t, "invalid_grant",
				tokenErrorOf(t, pollDeviceToken(t, h, deviceClientID, replay)),
				"the %s form of the stored hash was accepted as a device code", name)
		}
	})

	t.Run("two authorisations never share a code", func(t *testing.T) {
		second := openDeviceAuthorization(t, h, host)
		require.NotEqual(t, out.UserCode, second.UserCode)
		require.NotEqual(t, out.DeviceCode, second.DeviceCode)
	})
}

func TestDeviceAuthorizationRowsAreUniqueAndUndeletable(t *testing.T) {
	ctx := context.Background()
	out := openDeviceAuthorization(t, deviceHandler(t, api.Options{}), "dev-laptop-01")

	var id uuid.UUID
	require.NoError(t, pool.QueryRow(ctx,
		"select id from device_authorization where user_code = $1", out.UserCode).Scan(&id))

	t.Run("device_code_hash is unique, which is what makes one code one authorisation", func(t *testing.T) {
		_, err := pool.Exec(ctx,
			`insert into device_authorization
			   (id, device_code_hash, user_code, requesting_host, state, expires_at)
			 values ($1, $2, $3, 'other-host', 'pending', now() + interval '10 minutes')`,
			uuid.New(), commands.DeviceCodeHash(deviceClientID, out.DeviceCode), "AAAA-AAAA")
		requireUniqueViolation(t, err)
	})

	t.Run("user_code is unique, so one typed code names one authorisation", func(t *testing.T) {
		_, err := pool.Exec(ctx,
			`insert into device_authorization
			   (id, device_code_hash, user_code, requesting_host, state, expires_at)
			 values ($1, $2, $3, 'other-host', 'pending', now() + interval '10 minutes')`,
			uuid.New(), []byte("thirty-two-bytes-of-something!!!"), out.UserCode)
		requireUniqueViolation(t, err)
	})

	t.Run("am_api may not delete one, because expiry is a state transition", func(t *testing.T) {
		// Re-asserted here because this layer's expiry design depends on the withheld grant.
		asAPIRole(t, func(ctx context.Context, conn *pgxpool.Conn) {
			_, err := conn.Exec(ctx, "delete from device_authorization where id = $1", id)
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, "42501", pgErr.Code, "message was %q", pgErr.Message)
		})

		tag, err := pool.Exec(ctx, "delete from device_authorization where id = $1", id)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected())
	})
}

func TestDeviceTokenPollingFollowsRFC8628ThroughToAWorkingToken(t *testing.T) {
	h := deviceHandler(t, api.Options{DeviceVerificationURL: "https://hub.example.dev/cli"})
	const host = "dev-laptop-01"

	beforeAudit := countRows(t, "select count(*) from audit_event where kind = 'login'")
	out := openDeviceAuthorization(t, h, host)

	// The first poll is never slow_down, or every well-behaved client would look abusive.
	require.Equal(t, "authorization_pending", tokenErrorOf(t, pollDeviceToken(t, h, deviceClientID, out.DeviceCode)))

	require.Equal(t, "slow_down", tokenErrorOf(t, pollDeviceToken(t, h, deviceClientID, out.DeviceCode)))

	t.Run("a poll after the interval is pending again, not slow_down", func(t *testing.T) {
		// Moves the last-poll marker back instead of sleeping; it is the column the mechanism reads.
		_, err := pool.Exec(context.Background(),
			`update device_authorization set updated_at = now() - interval '30 seconds'
			  where user_code = $1`, out.UserCode)
		require.NoError(t, err)
		require.Equal(t, "authorization_pending",
			tokenErrorOf(t, pollDeviceToken(t, h, deviceClientID, out.DeviceCode)))
	})

	t.Run("the client_id is bound to the authorisation", func(t *testing.T) {
		require.Equal(t, "invalid_grant",
			tokenErrorOf(t, pollDeviceToken(t, h, "some-other-client", out.DeviceCode)))
		require.Equal(t, "pending", deviceState(t, out.UserCode),
			"a poll under the wrong client_id must not have changed the authorisation")
	})

	approvedHost, err := commands.ApproveDevice(context.Background(), db, principalFor(t, an), out.UserCode)
	require.NoError(t, err)
	require.Equal(t, host, approvedHost,
		"the host is what the approving human is shown, so it is what the command returns")

	t.Run("approval writes one login audit row naming the host", func(t *testing.T) {
		require.Equal(t, beforeAudit+1, countRows(t, "select count(*) from audit_event where kind = 'login'"))

		var text, source, actor string
		require.NoError(t, pool.QueryRow(context.Background(),
			`select text, source, actor from audit_event
			  where kind = 'login' order by occurred_at desc limit 1`).Scan(&text, &source, &actor))
		require.Contains(t, text, host)
		require.Contains(t, text, "approved")
		require.Equal(t, "cli / "+host, source, "a client source identifies the host")
		require.Equal(t, an.claims.Email, actor)
		require.NotContains(t, text, out.DeviceCode, "no credential reaches an audit row")
	})

	rec := pollDeviceToken(t, h, deviceClientID, out.DeviceCode)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var token contract.DeviceToken
	requireJSON(t, rec, &token)
	require.Equal(t, "Bearer", token.TokenType)
	require.NotEmpty(t, token.AccessToken)
	require.Equal(t, 3600, token.ExpiresIn, "short-lived, and the advertised DEVICE_TOKEN_TTL")
	require.Empty(t, token.RefreshToken,
		"this build issues no refresh token, so the field is omitted rather than empty")
	require.Equal(t, "consumed", deviceState(t, out.UserCode))

	t.Run("the issued token is one the middleware accepts", func(t *testing.T) {
		// Through a real authenticated operation, not by resolving the session directly.
		profiles := request(t, h, http.MethodGet, "/v1/profiles", token.AccessToken, "")
		require.Equal(t, http.StatusOK, profiles.Code, profiles.Body.String())
	})

	t.Run("the token carries the approving identity's access and nobody else's", func(t *testing.T) {
		// `an` may read security-review but not kw-private; `kw` is the opposite.
		profiles := request(t, h, http.MethodGet, "/v1/profiles", token.AccessToken, "")
		require.Equal(t, http.StatusOK, profiles.Code)

		var list contract.ProfileList
		requireJSON(t, profiles, &list)
		require.ElementsMatch(t, listSlugs(t, h, an), slugsOf(list.Profiles))
		require.Contains(t, slugsOf(list.Profiles), "security-review")
		require.NotContains(t, slugsOf(list.Profiles), "kw-private")
	})

	t.Run("the device code is single-use", func(t *testing.T) {
		require.Equal(t, "invalid_grant",
			tokenErrorOf(t, pollDeviceToken(t, h, deviceClientID, out.DeviceCode)),
			"a replayed device code must not yield a second token")
	})

	t.Run("approving a consumed authorisation is refused", func(t *testing.T) {
		_, err := commands.ApproveDevice(context.Background(), db, principalFor(t, kw), out.UserCode)
		require.ErrorIs(t, err, commands.ErrUserCodeUndecidable)
	})
}

func TestDeviceTokenRefusesAnExpiredCodeAndRecordsTheExpiryAsATransition(t *testing.T) {
	// withDefaults only replaces a non-positive TTL, so a nanosecond survives.
	h := deviceHandler(t, api.Options{DeviceCodeTTL: time.Nanosecond})
	out := openDeviceAuthorization(t, h, "dev-laptop-01")

	before := countRows(t, "select count(*) from device_authorization")

	require.Equal(t, "expired_token", tokenErrorOf(t, pollDeviceToken(t, h, deviceClientID, out.DeviceCode)))
	require.Equal(t, "expired", deviceState(t, out.UserCode),
		"expiry is a state transition: device_auth_state has `expired` and am_api holds no DELETE")
	require.Equal(t, before, countRows(t, "select count(*) from device_authorization"),
		"an expired authorisation is still there, so the evidence that a code was issued survives")

	t.Run("expired_token is terminal", func(t *testing.T) {
		require.Equal(t, "expired_token", tokenErrorOf(t, pollDeviceToken(t, h, deviceClientID, out.DeviceCode)))
	})

	t.Run("an expired code cannot be approved into life", func(t *testing.T) {
		_, err := commands.ApproveDevice(context.Background(), db, principalFor(t, kw), out.UserCode)
		require.ErrorIs(t, err, commands.ErrUserCodeUndecidable)
		require.Equal(t, "expired", deviceState(t, out.UserCode))
	})

	t.Run("an approved code that expires before it is collected yields no token", func(t *testing.T) {
		slow := deviceHandler(t, api.Options{})
		second := openDeviceAuthorization(t, slow, "dev-laptop-02")
		identity := principalFor(t, kw).IdentityID
		sessions := fmt.Sprintf("select count(*) from session where identity_id = '%s'", identity)
		before := countRows(t, sessions)

		_, err := commands.ApproveDevice(context.Background(), db, principalFor(t, kw), second.UserCode)
		require.NoError(t, err)

		_, err = pool.Exec(context.Background(),
			"update device_authorization set expires_at = now() - interval '1 second' where user_code = $1",
			second.UserCode)
		require.NoError(t, err)

		require.Equal(t, "expired_token", tokenErrorOf(t, pollDeviceToken(t, slow, deviceClientID, second.DeviceCode)))
		require.Equal(t, "expired", deviceState(t, second.UserCode))
		require.Equal(t, before, countRows(t, sessions),
			"an expired authorisation opens no session, approved or not")
	})
}

func TestDeviceTokenRefusesADeniedCodeTerminally(t *testing.T) {
	h := deviceHandler(t, api.Options{})
	out := openDeviceAuthorization(t, h, "someone-elses-laptop")

	beforeAudit := countRows(t, "select count(*) from audit_event where kind = 'login'")

	host, err := commands.DenyDevice(context.Background(), db, principalFor(t, kw), out.UserCode)
	require.NoError(t, err)
	require.Equal(t, "someone-elses-laptop", host)
	require.Equal(t, "denied", deviceState(t, out.UserCode))

	var approvedBy *uuid.UUID
	require.NoError(t, pool.QueryRow(context.Background(),
		"select approved_by_identity_id from device_authorization where user_code = $1",
		out.UserCode).Scan(&approvedBy))
	require.Nil(t, approvedBy,
		"a denier must not be recorded in approved_by_identity_id, where every later reader would read it as an approval")

	require.Equal(t, beforeAudit+1, countRows(t, "select count(*) from audit_event where kind = 'login'"))
	var text string
	require.NoError(t, pool.QueryRow(context.Background(),
		`select text from audit_event where kind = 'login' order by occurred_at desc limit 1`).Scan(&text))
	require.Contains(t, text, "denied")
	require.Contains(t, text, host)

	require.Equal(t, "access_denied", tokenErrorOf(t, pollDeviceToken(t, h, deviceClientID, out.DeviceCode)))

	t.Run("access_denied is terminal", func(t *testing.T) {
		for range 3 {
			require.Equal(t, "access_denied",
				tokenErrorOf(t, pollDeviceToken(t, h, deviceClientID, out.DeviceCode)))
		}
		require.Equal(t, "denied", deviceState(t, out.UserCode))
	})

	t.Run("a denied code cannot be approved afterwards", func(t *testing.T) {
		_, err := commands.ApproveDevice(context.Background(), db, principalFor(t, an), out.UserCode)
		require.ErrorIs(t, err, commands.ErrUserCodeUndecidable)
		require.Equal(t, "denied", deviceState(t, out.UserCode))
	})
}

func TestApprovalRecordsWhichIdentityDecidedAndOnlyOneMay(t *testing.T) {
	h := deviceHandler(t, api.Options{})
	out := openDeviceAuthorization(t, h, "dev-laptop-01")

	// There is no requester identity to compare against, so what is testable is that the
	// deciding identity is recorded and a second identity cannot decide again.
	_, err := commands.ApproveDevice(context.Background(), db, principalFor(t, an), out.UserCode)
	require.NoError(t, err)

	var approvedBy uuid.UUID
	require.NoError(t, pool.QueryRow(context.Background(),
		"select approved_by_identity_id from device_authorization where user_code = $1",
		out.UserCode).Scan(&approvedBy))
	require.Equal(t, principalFor(t, an).IdentityID, approvedBy)

	_, err = commands.ApproveDevice(context.Background(), db, principalFor(t, kw), out.UserCode)
	require.ErrorIs(t, err, commands.ErrUserCodeUndecidable,
		"a second identity must not be able to re-approve, or approved_by would name whoever was last")

	var stillAn uuid.UUID
	require.NoError(t, pool.QueryRow(context.Background(),
		"select approved_by_identity_id from device_authorization where user_code = $1",
		out.UserCode).Scan(&stillAn))
	require.Equal(t, approvedBy, stillAn)

	_, err = commands.DenyDevice(context.Background(), db, principalFor(t, kw), out.UserCode)
	require.ErrorIs(t, err, commands.ErrUserCodeUndecidable,
		"nor may a second identity deny an approved authorisation")
}

func TestApprovalForgivesTypographyAndNothingElse(t *testing.T) {
	h := deviceHandler(t, api.Options{})

	t.Run("lower case, spaces and a missing separator all reach the same row", func(t *testing.T) {
		out := openDeviceAuthorization(t, h, "dev-laptop-01")
		typed := "  " + strings.ToLower(strings.ReplaceAll(out.UserCode, "-", "")) + "  "
		_, err := commands.ApproveDevice(context.Background(), db, principalFor(t, kw), typed)
		require.NoError(t, err)
		require.Equal(t, "approved", deviceState(t, out.UserCode))
	})

	t.Run("a code that names no pending row is one error and not a hint", func(t *testing.T) {
		for _, typed := range []string{"", "ZZZZ-ZZZZ", "nonsense", "ZZZZ-ZZZ"} {
			_, err := commands.ApproveDevice(context.Background(), db, principalFor(t, kw), typed)
			require.ErrorIsf(t, err, commands.ErrUserCodeUndecidable, "typed %q", typed)
		}
	})
}

func TestConcurrentPollsOfOneApprovedCodeYieldExactlyOneToken(t *testing.T) {
	h := deviceHandler(t, api.Options{})
	out := openDeviceAuthorization(t, h, "dev-laptop-01")

	identity := principalFor(t, an).IdentityID
	_, err := commands.ApproveDevice(context.Background(), db, principalFor(t, an), out.UserCode)
	require.NoError(t, err)

	beforeSessions := countRows(t, fmt.Sprintf(
		"select count(*) from session where identity_id = '%s'", identity))

	// Real concurrency: sequential calls would pass against a read-then-write implementation.
	const pollers = 8
	var (
		start   = make(chan struct{})
		wg      sync.WaitGroup
		mu      sync.Mutex
		codes   []int
		tokens  []string
		refused []string
	)
	for range pollers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := pollDeviceToken(t, h, deviceClientID, out.DeviceCode)

			mu.Lock()
			defer mu.Unlock()
			codes = append(codes, rec.Code)
			if rec.Code == http.StatusOK {
				var token contract.DeviceToken
				requireJSON(t, rec, &token)
				tokens = append(tokens, token.AccessToken)
				return
			}
			var envelope contract.DeviceTokenError
			requireJSON(t, rec, &envelope)
			refused = append(refused, envelope.Error)
		}()
	}
	close(start)
	wg.Wait()

	require.Len(t, codes, pollers)
	require.Len(t, tokens, 1, "exactly one poll may win: got %d tokens and refusals %v", len(tokens), refused)
	require.Len(t, refused, pollers-1)
	for _, code := range refused {
		require.Equal(t, "invalid_grant", code,
			"the losers of the race get the same terminal answer a replay gets")
	}

	require.Equal(t, "consumed", deviceState(t, out.UserCode))
	require.Equal(t, beforeSessions+1, countRows(t, fmt.Sprintf(
		"select count(*) from session where identity_id = '%s'", identity)),
		"one authorisation opened one session, whatever the poll count")

	profiles := request(t, h, http.MethodGet, "/v1/profiles", tokens[0], "")
	require.Equal(t, http.StatusOK, profiles.Code, profiles.Body.String())
}

// holdDeviceRow row-locks one authorisation to stall the consuming UPDATE, widening a
// microsecond race window enough to assert on. It returns the release.
func holdDeviceRow(t *testing.T, userCode string) (release func()) {
	t.Helper()
	ctx := context.Background()

	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)

	tx, err := conn.Begin(ctx)
	require.NoError(t, err)

	var id uuid.UUID
	require.NoError(t, tx.QueryRow(ctx,
		"select id from device_authorization where user_code = $1 for update", userCode).Scan(&id))

	released := false
	t.Cleanup(func() {
		if !released {
			_ = tx.Rollback(ctx)
		}
		conn.Release()
	})
	return func() {
		require.NoError(t, tx.Rollback(ctx))
		released = true
		conn.Release()
	}
}

func setDeviceExpiry(t *testing.T, userCode string, in time.Duration) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		"update device_authorization set expires_at = clock_timestamp() + make_interval(secs => $2) where user_code = $1",
		userCode, in.Seconds())
	require.NoError(t, err)
}

func TestAnApprovalThatExpiresWhileTheConsumingUpdateWaitsIssuesNoToken(t *testing.T) {
	// ConsumeDevice's expiry sweep runs before its transaction, so an approval can lapse while
	// the consuming UPDATE waits; only the guard inside the transaction can then refuse it.
	const grace = 400 * time.Millisecond

	h := deviceHandler(t, api.Options{})
	out := openDeviceAuthorization(t, h, "dev-laptop-04")

	identity := principalFor(t, kw).IdentityID
	sessions := fmt.Sprintf("select count(*) from session where identity_id = '%s'", identity)
	before := countRows(t, sessions)

	_, err := commands.ApproveDevice(context.Background(), db, principalFor(t, kw), out.UserCode)
	require.NoError(t, err)
	setDeviceExpiry(t, out.UserCode, grace)

	release := holdDeviceRow(t, out.UserCode)
	polled := make(chan *httptest.ResponseRecorder, 1)
	go func() { polled <- pollDeviceToken(t, h, deviceClientID, out.DeviceCode) }()

	time.Sleep(4 * grace)
	release()
	rec := <-polled

	require.Equal(t, "expired_token", tokenErrorOf(t, rec),
		"an approval that lapsed while the consuming update waited must not be redeemable")
	require.NotEqual(t, "consumed", deviceState(t, out.UserCode),
		"a refused exchange must leave no consumed row behind")
	require.Equal(t, before, countRows(t, sessions),
		"an expired approval opens no session, however narrow the window it expired in")

	t.Run("and the refusal is terminal", func(t *testing.T) {
		require.Equal(t, "expired_token", tokenErrorOf(t, pollDeviceToken(t, h, deviceClientID, out.DeviceCode)))
		require.Equal(t, "expired", deviceState(t, out.UserCode))
	})
}

func TestAnApprovalStillLiveAfterTheConsumingUpdateWaitsIssuesItsToken(t *testing.T) {
	// Negative control for the test above: the same stall with a future expiry must still issue.
	h := deviceHandler(t, api.Options{})
	out := openDeviceAuthorization(t, h, "dev-laptop-05")

	identity := principalFor(t, kw).IdentityID
	sessions := fmt.Sprintf("select count(*) from session where identity_id = '%s'", identity)
	before := countRows(t, sessions)

	_, err := commands.ApproveDevice(context.Background(), db, principalFor(t, kw), out.UserCode)
	require.NoError(t, err)
	setDeviceExpiry(t, out.UserCode, 30*time.Second)

	release := holdDeviceRow(t, out.UserCode)
	polled := make(chan *httptest.ResponseRecorder, 1)
	go func() { polled <- pollDeviceToken(t, h, deviceClientID, out.DeviceCode) }()

	time.Sleep(500 * time.Millisecond)
	release()
	rec := <-polled

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var token contract.DeviceToken
	requireJSON(t, rec, &token)
	require.NotEmpty(t, token.AccessToken)
	require.Equal(t, "consumed", deviceState(t, out.UserCode))
	require.Equal(t, before+1, countRows(t, sessions))

	profiles := request(t, h, http.MethodGet, "/v1/profiles", token.AccessToken, "")
	require.Equal(t, http.StatusOK, profiles.Code, profiles.Body.String())
}
