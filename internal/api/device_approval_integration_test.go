//go:build integration

// The browser half of the device flow: lookupDeviceCode and approveDeviceCode
// against a real Postgres.
package api_test

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
)

// deviceApprovalHandler is deviceHandler with a logger this suite can inspect.
func deviceApprovalHandler(t *testing.T, log zerolog.Logger) http.Handler {
	t.Helper()

	bucket, err := blob.Open(context.Background(), "mem://")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bucket.Close()) })

	return api.New(api.Deps{
		DB:       db,
		Bundles:  bucket.Reader(),
		Sessions: auth.NewSessions(db),
		Log:      log,
	}, api.Options{}).Handler()
}

func lookupPath(userCode string) string {
	return "/v1/device/authorizations/" + url.PathEscape(userCode)
}

func approvePath(userCode string) string {
	return "/v1/device/authorizations/" + url.PathEscape(userCode) + "/approve"
}

func TestLookupDeviceCodeShowsTheHostAndValidityBeforeConfirmation(t *testing.T) {
	h := deviceHandler(t, api.Options{})
	out := openDeviceAuthorization(t, h, "dev-laptop-06")

	rec := request(t, h, http.MethodGet, lookupPath(out.UserCode), kw.token, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body contract.PendingDeviceAuthorization
	requireJSON(t, rec, &body)
	require.Equal(t, "dev-laptop-06", body.RequestingHost)
	require.Positive(t, body.ExpiresIn)

	// A lookup is a read: it must not decide anything. The row is still pending
	// and still approvable afterwards.
	require.Equal(t, "pending", deviceState(t, out.UserCode))
}

func TestLookupDeviceCodeNeedsASession(t *testing.T) {
	h := deviceHandler(t, api.Options{})
	out := openDeviceAuthorization(t, h, "dev-laptop-06")

	rec := request(t, h, http.MethodGet, lookupPath(out.UserCode), "", "")
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
}

// There is no requester identity in this schema to compare an approver
// against, so any signed-in identity may approve a pending code.
func TestTheThreeRefusalsAreDistinguishableAndTheFourthIsNot(t *testing.T) {
	h := deviceHandler(t, api.Options{})

	t.Run("unknown", func(t *testing.T) {
		lookup := request(t, h, http.MethodGet, lookupPath("ZZZZ-ZZZZ"), kw.token, "")
		require.Equal(t, http.StatusNotFound, lookup.Code, lookup.Body.String())

		approve := request(t, h, http.MethodPost, approvePath("ZZZZ-ZZZZ"), kw.token, "")
		require.Equal(t, http.StatusNotFound, approve.Code, approve.Body.String())
	})

	t.Run("expired", func(t *testing.T) {
		out := openDeviceAuthorization(t, h, "dev-laptop-07")
		setDeviceExpiry(t, out.UserCode, -time.Minute)

		lookup := request(t, h, http.MethodGet, lookupPath(out.UserCode), kw.token, "")
		require.Equal(t, http.StatusGone, lookup.Code, lookup.Body.String())

		approve := request(t, h, http.MethodPost, approvePath(out.UserCode), kw.token, "")
		require.Equal(t, http.StatusGone, approve.Code, approve.Body.String())
	})

	t.Run("already decided", func(t *testing.T) {
		out := openDeviceAuthorization(t, h, "dev-laptop-08")
		approveRec := request(t, h, http.MethodPost, approvePath(out.UserCode), kw.token, "")
		require.Equal(t, http.StatusOK, approveRec.Code, approveRec.Body.String())

		lookup := request(t, h, http.MethodGet, lookupPath(out.UserCode), kw.token, "")
		require.Equal(t, http.StatusConflict, lookup.Code, lookup.Body.String())

		approve := request(t, h, http.MethodPost, approvePath(out.UserCode), kw.token, "")
		require.Equal(t, http.StatusConflict, approve.Code, approve.Body.String())
	})

	t.Run("approval by a different identity reads exactly like already decided", func(t *testing.T) {
		out := openDeviceAuthorization(t, h, "dev-laptop-09")
		first := request(t, h, http.MethodPost, approvePath(out.UserCode), kw.token, "")
		require.Equal(t, http.StatusOK, first.Code, first.Body.String())

		// `an` is a different identity from `kw`, the one that just approved.
		second := request(t, h, http.MethodPost, approvePath(out.UserCode), an.token, "")
		require.Equal(t, http.StatusConflict, second.Code, second.Body.String())

		var decided, wrongIdentity contract.Error
		requireJSON(t, request(t, h, http.MethodGet, lookupPath(out.UserCode), kw.token, ""), &decided)
		requireJSON(t, second, &wrongIdentity)
		require.Equal(t, decided.Title, wrongIdentity.Title)
		require.Equal(t, decided.Detail, wrongIdentity.Detail,
			"the wrong-identity refusal must read exactly like any other already-decided code")
	})
}

func TestApproveDeviceCodeWritesOneLoginAuditRowAndCompletesTheFlow(t *testing.T) {
	h := deviceHandler(t, api.Options{})
	out := openDeviceAuthorization(t, h, "dev-laptop-10")

	beforeAudit := countRows(t, "select count(*) from audit_event where kind = 'login'")

	rec := request(t, h, http.MethodPost, approvePath(out.UserCode), an.token, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body contract.ApprovedDeviceAuthorization
	requireJSON(t, rec, &body)
	require.Equal(t, "dev-laptop-10", body.RequestingHost)
	require.Equal(t, "approved", deviceState(t, out.UserCode))

	require.Equal(t, beforeAudit+1, countRows(t, "select count(*) from audit_event where kind = 'login'"))

	var text, source string
	require.NoError(t, pool.QueryRow(context.Background(),
		`select text, source from audit_event where kind = 'login' order by occurred_at desc limit 1`).
		Scan(&text, &source))
	require.Contains(t, text, "dev-laptop-10")
	require.Equal(t, "cli / dev-laptop-10", source)

	pollRec := pollDeviceToken(t, h, deviceClientID, out.DeviceCode)
	require.Equal(t, http.StatusOK, pollRec.Code, pollRec.Body.String())
	var token contract.DeviceToken
	requireJSON(t, pollRec, &token)
	require.NotEmpty(t, token.AccessToken)

	profiles := request(t, h, http.MethodGet, "/v1/profiles", token.AccessToken, "")
	require.Equal(t, http.StatusOK, profiles.Code, profiles.Body.String())
}

// deviceAuthorize logs the fresh user code once, by design, on the request that
// mints it, so only the generic per-request "request" line is asserted here.
func TestApprovalPathParameterNeverAppearsInTheRequestLog(t *testing.T) {
	var logged bytes.Buffer
	log := zerolog.New(&logged)
	h := deviceApprovalHandler(t, log)

	out := openDeviceAuthorization(t, h, "dev-laptop-12")

	request(t, h, http.MethodGet, lookupPath(out.UserCode), kw.token, "")
	request(t, h, http.MethodPost, approvePath(out.UserCode), kw.token, "")
	// An unknown code too: the secret must not leak even on a miss.
	request(t, h, http.MethodGet, lookupPath("ZZZZ-ZZZZ"), kw.token, "")

	for _, line := range strings.Split(strings.TrimSpace(logged.String()), "\n") {
		if !strings.Contains(line, `"message":"request"`) {
			continue
		}
		require.NotContains(t, line, out.UserCode,
			"a per-request log line must never carry the user code, matched or unmatched: %s", line)
	}

	// The route template is still there, so the fix is a redaction and not a
	// silently dropped log line.
	require.Contains(t, logged.String(), "/v1/device/authorizations/:user_code")
}
