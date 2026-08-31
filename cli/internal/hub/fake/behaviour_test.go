package fake_test

// These tests are in `package fake_test` ON PURPOSE.
//
// R5 requires that the same behavioural suite can run against the fake and against
// T062's compose stack. The mechanism is that a behavioural test accepts a
// fake.Target — a URL, a token, a client, fixture names and an operator hook — and
// never a *fake.Hub. Being outside `package fake` makes that a compile error rather
// than a convention: nothing unexported is reachable from here, so no case written
// in this file can quietly depend on the fake's internals.
//
// When T035+ move these cases into a shared suite, the signature to keep is
// `func(t *testing.T, tg fake.Target)`.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/archive"
	"github.com/WindKube/agent-manager/cli/internal/cache"
	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/hub/fake"
)

const grantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

// fastPolls shortens the advertised poll interval to its 1s floor — the contract's
// `interval` is an integer number of seconds, so nothing shorter can be advertised
// honestly. The client still reads the value off the wire; nothing under test
// learns the number from here.
func fastPolls() fake.Options { return fake.Options{PollInterval: time.Second} }

type client struct {
	t  *testing.T
	tg fake.Target
	// follow decides whether redirects are followed. Both settings matter: the
	// FR-016 case is about what happens on the hop.
	follow bool
}

func newClient(t *testing.T, tg fake.Target) *client { return &client{t: t, tg: tg} }

// result is a response with its body already read and closed. No *http.Response
// leaves these helpers: one that did would leave every caller owning a Close, and
// a leaked body in a test suite this size eventually shows up as an unrelated
// timeout on someone else's machine.
type result struct {
	Status int
	Header http.Header
	Body   []byte
}

func (c *client) do(req *http.Request) result {
	c.t.Helper()
	hc := *c.tg.HTTPClient
	if !c.follow {
		hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	resp, err := hc.Do(req)
	require.NoError(c.t, err)
	defer func() { require.NoError(c.t, resp.Body.Close()) }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(c.t, err)
	return result{Status: resp.StatusCode, Header: resp.Header, Body: b}
}

func (c *client) get(path, token string) result {
	c.t.Helper()
	req, err := http.NewRequestWithContext(c.t.Context(), http.MethodGet, c.tg.BaseURL+path, http.NoBody)
	require.NoError(c.t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.do(req)
}

func (c *client) post(path, contentType, token string, payload []byte) result {
	c.t.Helper()
	req, err := http.NewRequestWithContext(c.t.Context(), http.MethodPost, c.tg.BaseURL+path, bytes.NewReader(payload))
	require.NoError(c.t, err)
	req.Header.Set("Content-Type", contentType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.do(req)
}

func decode[T any](t *testing.T, r result) T {
	t.Helper()
	var out T
	require.NoError(t, json.Unmarshal(r.Body, &out))
	return out
}

func authorize(t *testing.T, c *client) hub.DeviceAuthorization {
	t.Helper()
	req, err := json.Marshal(hub.DeviceAuthorizeRequest{ClientId: "agent-manager-cli", Host: "dev-laptop-01"})
	require.NoError(t, err)
	resp := c.post("/v1/device/authorize", "application/json", "", req)
	require.Equal(t, http.StatusOK, resp.Status)
	return decode[hub.DeviceAuthorization](t, resp)
}

func poll(t *testing.T, c *client, deviceCode string) result {
	t.Helper()
	form := url.Values{
		"grant_type":  {grantDeviceCode},
		"device_code": {deviceCode},
		"client_id":   {"agent-manager-cli"},
	}
	return c.post("/v1/device/token", "application/x-www-form-urlencoded", "", []byte(form.Encode()))
}

func requireTokenError(t *testing.T, resp result, want hub.DeviceTokenErrorError) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, resp.Status)
	// application/json, not problem+json: this one route answers with the OAuth
	// error object.
	require.True(t, strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json"),
		"got %q", resp.Header.Get("Content-Type"))
	got := decode[hub.DeviceTokenError](t, resp)
	require.NotNil(t, got.Error)
	require.Equal(t, want, *got.Error)
}

// ---- device flow

func TestDeviceFlow(t *testing.T) {
	t.Run("a first poll is authorization_pending and never slow_down", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		c := newClient(t, h.Target())

		auth := authorize(t, c)
		require.Positive(t, auth.Interval)
		require.Positive(t, auth.ExpiresIn)
		require.NotEmpty(t, auth.DeviceCode)
		require.NotContains(t, auth.DeviceCode, ".")
		require.NotNil(t, auth.VerificationUriComplete)
		require.Contains(t, *auth.VerificationUriComplete, auth.UserCode)

		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.AuthorizationPending)
	})

	t.Run("a second poll inside the interval is slow_down", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		c := newClient(t, h.Target())

		auth := authorize(t, c)
		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.AuthorizationPending)
		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.SlowDown)
		// Hammering keeps earning slow_down rather than sliding into a free poll.
		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.SlowDown)
	})

	t.Run("a poll after the interval is pending again", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		c := newClient(t, h.Target())

		auth := authorize(t, c)
		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.AuthorizationPending)
		time.Sleep(time.Duration(auth.Interval)*time.Second + 60*time.Millisecond)
		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.AuthorizationPending)
	})

	t.Run("an approved code yields an opaque token that authenticates other calls", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		tg := h.Target()
		c := newClient(t, tg)

		auth := authorize(t, c)
		require.NoError(t, tg.Control.ApproveDevice(auth.UserCode))

		resp := poll(t, c, auth.DeviceCode)
		require.Equal(t, http.StatusOK, resp.Status)
		tok := decode[hub.DeviceToken](t, resp)
		require.Equal(t, hub.Bearer, tok.TokenType)
		require.Positive(t, tok.ExpiresIn)
		require.Nil(t, tok.RefreshToken)
		// Opaque. A test that read an expiry out of the token would pass here and
		// fail against the real hub, whose bearerFormat is `opaque`.
		require.NotContains(t, tok.AccessToken, ".")

		require.Equal(t, http.StatusOK, newClient(t, tg).get("/v1/profiles", tok.AccessToken).Status)
	})

	t.Run("a second poll of a consumed code is invalid_grant not authorization_pending", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		tg := h.Target()
		c := newClient(t, tg)

		auth := authorize(t, c)
		require.NoError(t, tg.Control.ApproveDevice(auth.UserCode))
		require.Equal(t, http.StatusOK, poll(t, c, auth.DeviceCode).Status)

		time.Sleep(time.Duration(auth.Interval) * time.Second)
		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.InvalidGrant)
	})

	t.Run("access_denied is terminal", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		tg := h.Target()
		c := newClient(t, tg)

		auth := authorize(t, c)
		require.NoError(t, tg.Control.DenyDevice(auth.UserCode))
		// Twice, back to back: a terminal state must beat slow_down, or a client
		// gets told to keep polling a grant that can never succeed.
		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.AccessDenied)
		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.AccessDenied)
	})

	t.Run("expired_token is terminal", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		tg := h.Target()
		c := newClient(t, tg)

		auth := authorize(t, c)
		require.NoError(t, tg.Control.ExpireDevice(auth.UserCode))
		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.ExpiredToken)
		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.ExpiredToken)
	})

	t.Run("an approval that expires before it is collected yields no token", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		tg := h.Target()
		c := newClient(t, tg)

		auth := authorize(t, c)
		require.NoError(t, tg.Control.ApproveDevice(auth.UserCode))
		require.NoError(t, tg.Control.ExpireDevice(auth.UserCode))
		requireTokenError(t, poll(t, c, auth.DeviceCode), hub.ExpiredToken)
	})

	// The R5 case in its purest form: RFC 8628 3.4 fixes the token body as
	// form-encoded and the real hub enforces it. A fake that also accepted JSON
	// would let a client ship that the real hub rejects.
	t.Run("a JSON body on the token endpoint is refused", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		c := newClient(t, h.Target())

		auth := authorize(t, c)
		req, err := json.Marshal(hub.DeviceTokenRequest{
			GrantType: grantDeviceCode, DeviceCode: auth.DeviceCode, ClientId: "agent-manager-cli",
		})
		require.NoError(t, err)
		resp := c.post("/v1/device/token", "application/json", "", req)
		require.Equal(t, http.StatusUnsupportedMediaType, resp.Status)
	})

	t.Run("an unknown grant type is invalid_grant", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		c := newClient(t, h.Target())

		auth := authorize(t, c)
		form := url.Values{"grant_type": {"password"}, "device_code": {auth.DeviceCode}}
		resp := c.post("/v1/device/token", "application/x-www-form-urlencoded", "", []byte(form.Encode()))
		requireTokenError(t, resp, hub.InvalidGrant)
	})

	t.Run("an unknown device code is invalid_grant", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		c := newClient(t, h.Target())
		requireTokenError(t, poll(t, c, "not-a-device-code"), hub.InvalidGrant)
	})

	t.Run("a wrong media type on authorize is 415 and a broken body is 400", func(t *testing.T) {
		h := fake.New(fastPolls())
		defer h.Close()
		c := newClient(t, h.Target())

		require.Equal(t, http.StatusUnsupportedMediaType,
			c.post("/v1/device/authorize", "text/plain", "", []byte("{}")).Status)
		require.Equal(t, http.StatusBadRequest,
			c.post("/v1/device/authorize", "application/json", "", []byte("{")).Status)
		require.Equal(t, http.StatusBadRequest,
			c.post("/v1/device/authorize", "application/json", "", []byte(`{"client_id":"x"}`)).Status)
	})
}

// ---- auth classification (FR-040)

func TestAuthenticationClasses(t *testing.T) {
	h := fake.New(fake.Options{})
	defer h.Close()
	tg := h.Target()

	authenticated := []string{
		"/v1/profiles",
		"/v1/profiles/" + tg.Fixtures.Profile + "/revisions/head",
		"/v1/bundles/acme/code-review/2.4.1",
	}
	for _, path := range authenticated {
		t.Run("an absent bearer is 401 on "+path, func(t *testing.T) {
			resp := newClient(t, tg).get(path, "")
			require.Equal(t, http.StatusUnauthorized, resp.Status)
			require.Equal(t, "application/problem+json", resp.Header.Get("Content-Type"))
		})
		t.Run("an unknown bearer is 401 on "+path, func(t *testing.T) {
			require.Equal(t, http.StatusUnauthorized, newClient(t, tg).get(path, "nonsense").Status)
		})
	}

	t.Run("health needs no bearer, which is what separates unreachable from unauthorised", func(t *testing.T) {
		resp := newClient(t, tg).get("/v1/health", "")
		require.Equal(t, http.StatusOK, resp.Status)
		require.Equal(t, hub.Ok, decode[hub.Health](t, resp).Status)
	})

	t.Run("an unwell hub answers 503 on health while still refusing an unknown token with 401", func(t *testing.T) {
		require.NoError(t, tg.Control.SetHealthy(false))
		defer func() { require.NoError(t, tg.Control.SetHealthy(true)) }()

		resp := newClient(t, tg).get("/v1/health", "")
		require.Equal(t, http.StatusServiceUnavailable, resp.Status)
		require.Equal(t, hub.Unavailable, decode[hub.Health](t, resp).Status)
		require.Equal(t, http.StatusUnauthorized, newClient(t, tg).get("/v1/profiles", "nonsense").Status)
	})
}

// ---- bundles

// FR-016: the bearer must not reach the pre-signed target. Both halves are here,
// and the first is the one that matters — net/http's own default PRESERVES
// Authorization on a same-host redirect, so this asserts the fake would catch a
// client that relied on that default.
func TestPresignedRedirect(t *testing.T) {
	h := fake.New(fake.Options{})
	defer h.Close()
	tg := h.Target()
	c := newClient(t, tg)

	resp := c.get("/v1/profiles/"+tg.Fixtures.PresignedBundle+"/revisions/head", tg.Token)
	require.Equal(t, http.StatusOK, resp.Status)
	lf := decode[hub.Lockfile](t, resp)
	require.Len(t, lf.Entries, 1)
	e := lf.Entries[0]
	ns, name, _ := strings.Cut(e.Id, "/")
	path := fmt.Sprintf("/v1/bundles/%s/%s/%s", ns, name, e.Version)

	t.Run("the bundle answers 307 to a same-host location", func(t *testing.T) {
		r := newClient(t, tg).get(path, tg.Token)
		require.Equal(t, http.StatusTemporaryRedirect, r.Status)
		loc, err := url.Parse(r.Header.Get("Location"))
		require.NoError(t, err)
		// Same host on purpose: net/http drops Authorization across hosts already,
		// so a cross-host fixture would pass even with FR-016 unimplemented.
		require.True(t, loc.Host == "" || loc.Host == mustHost(t, tg.BaseURL))
		require.NotEmpty(t, loc.Query().Get("X-Amz-Signature"))
	})

	t.Run("a client that leaks the bearer to the redirect target is refused", func(t *testing.T) {
		leaky := newClient(t, tg)
		leaky.follow = true // net/http's default behaviour, which preserves the header
		r := leaky.get(path, tg.Token)
		require.Equal(t, http.StatusBadRequest, r.Status,
			"the pre-signed target accepted a request carrying Authorization; FR-016 is untestable")
		require.Contains(t, string(r.Body), "Authorization")
	})

	t.Run("a client that strips the bearer on the hop gets the bytes and a matching digest", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tg.BaseURL+path, http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+tg.Token)

		hc := *tg.HTTPClient
		hc.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
			r.Header.Del("Authorization")
			return nil
		}
		r, err := hc.Do(req)
		require.NoError(t, err)
		defer func() { _ = r.Body.Close() }()

		require.Equal(t, http.StatusOK, r.StatusCode)
		bs, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		fromHeader, err := cache.ParseHeaderDigest(r.Header.Get("Digest"))
		require.NoError(t, err)
		require.Equal(t, cache.Compute(bs), fromHeader)

		fromLockfile, err := cache.ParseLockfileDigest(e.Digest)
		require.NoError(t, err)
		require.Equal(t, cache.Compute(bs), fromLockfile)
	})
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u.Host
}

func TestAGatedBundleIs403WhileItsNeighboursServe(t *testing.T) {
	h := fake.New(fake.Options{})
	defer h.Close()
	tg := h.Target()
	c := newClient(t, tg)

	resp := c.get("/v1/profiles/"+tg.Fixtures.ForbiddenBundle+"/revisions/head", tg.Token)
	require.Equal(t, http.StatusOK, resp.Status)
	lf := decode[hub.Lockfile](t, resp)
	require.GreaterOrEqual(t, len(lf.Entries), 3)

	var idx = -1
	for i, e := range lf.Entries {
		if e.Id == tg.Fixtures.ForbiddenEntryID {
			idx = i
		}
	}
	require.Positive(t, idx, "the 403 entry must not be first")
	require.Less(t, idx, len(lf.Entries)-1, "the 403 entry must not be last, or 'sync continues' is untested")

	for i, e := range lf.Entries {
		ns, name, _ := strings.Cut(e.Id, "/")
		r := newClient(t, tg).get(fmt.Sprintf("/v1/bundles/%s/%s/%s", ns, name, e.Version), tg.Token)
		if i == idx {
			require.Equal(t, http.StatusForbidden, r.Status)
			require.Equal(t, "application/problem+json", r.Header.Get("Content-Type"))
			continue
		}
		require.Equal(t, http.StatusOK, r.Status, e.Id)
	}
}

func TestAnUnknownBundleVersionIs404(t *testing.T) {
	h := fake.New(fake.Options{})
	defer h.Close()
	tg := h.Target()
	require.Equal(t, http.StatusNotFound,
		newClient(t, tg).get("/v1/bundles/acme/code-review/9.9.9", tg.Token).Status)
	require.Equal(t, http.StatusNotFound,
		newClient(t, tg).get("/v1/bundles/nope/nothing/1.0.0", tg.Token).Status)
}

// The bytes must be a real bundle, not plaintext under a hand-written header:
// otherwise internal/archive (T013) and the digest check (T038) are never
// exercised and every test above them is decorative.
func TestServedBundlesExtractUnderTheRealCaps(t *testing.T) {
	h := fake.New(fake.Options{})
	defer h.Close()
	tg := h.Target()

	resp := newClient(t, tg).get("/v1/bundles/acme/code-review/2.4.1", tg.Token)
	require.Equal(t, http.StatusOK, resp.Status)
	bs := resp.Body

	dest := filepath.Join(t.TempDir(), "code-review")
	res, err := archive.Extract(t.Context(), bytes.NewReader(bs), dest, archive.Limits{})
	require.NoError(t, err)
	require.NotEmpty(t, res.Files)
	requireFile(t, filepath.Join(dest, "SKILL.md"))
	requireFile(t, filepath.Join(dest, "references", "usage.md"))
}

func requireFile(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEmpty(t, b)
}

// ---- profiles and revisions

func TestRevisions(t *testing.T) {
	h := fake.New(fake.Options{})
	defer h.Close()
	tg := h.Target()

	t.Run("head and a pinned revision differ in content, not only in number", func(t *testing.T) {
		head := decode[hub.Lockfile](t, newClient(t, tg).get(
			"/v1/profiles/"+tg.Fixtures.Profile+"/revisions/head", tg.Token))
		prior := decode[hub.Lockfile](t, newClient(t, tg).get(
			fmt.Sprintf("/v1/profiles/%s/revisions/%d", tg.Fixtures.Profile, tg.Fixtures.PriorRevision), tg.Token))

		require.Equal(t, tg.Fixtures.HeadRevision, head.Revision)
		require.Equal(t, tg.Fixtures.PriorRevision, prior.Revision)
		require.NotEqual(t, len(head.Entries), len(prior.Entries))
		// FR-013: `head` is a request, never a stored value. The body always names
		// the number it resolved to.
		require.Positive(t, head.Revision)
	})

	t.Run("an unknown profile is 404", func(t *testing.T) {
		require.Equal(t, http.StatusNotFound, newClient(t, tg).get(
			"/v1/profiles/"+tg.Fixtures.MissingProfile+"/revisions/head", tg.Token).Status)
	})

	t.Run("a revision outside the contract's pattern is 422", func(t *testing.T) {
		require.Equal(t, http.StatusUnprocessableEntity, newClient(t, tg).get(
			"/v1/profiles/"+tg.Fixtures.Profile+"/revisions/latest", tg.Token).Status)
	})

	t.Run("a revision that does not exist is 404", func(t *testing.T) {
		require.Equal(t, http.StatusNotFound, newClient(t, tg).get(
			"/v1/profiles/"+tg.Fixtures.Profile+"/revisions/9999", tg.Token).Status)
	})

	t.Run("listProfiles counts entries and excludes skipped", func(t *testing.T) {
		list := decode[hub.ProfileList](t, newClient(t, tg).get("/v1/profiles", tg.Token))
		var found bool
		for _, p := range list.Profiles {
			if p.Slug != tg.Fixtures.Profile {
				continue
			}
			found = true
			lf := decode[hub.Lockfile](t, newClient(t, tg).get(
				"/v1/profiles/"+p.Slug+"/revisions/head", tg.Token))
			require.NotEmpty(t, lf.Skipped)
			require.Equal(t, int64(len(lf.Entries)), p.PackageCount)
			require.Equal(t, p.HeadRevision, lf.Revision)
		}
		require.True(t, found)
	})
}

// ---- sync

func TestReportSync(t *testing.T) {
	h := fake.New(fake.Options{})
	defer h.Close()
	tg := h.Target()
	c := newClient(t, tg)

	report := hub.SyncReport{
		Profile:  tg.Fixtures.Profile,
		Revision: tg.Fixtures.HeadRevision,
		Host:     "dev-laptop-01",
		Targets:  []hub.SyncReportTargets{"claude-code"},
		Skipped:  &[]string{"contoso/gated"},
	}
	raw, err := json.Marshal(report)
	require.NoError(t, err)

	resp := c.post("/v1/sync", "application/json", tg.Token, raw)
	require.Equal(t, http.StatusNoContent, resp.Status)
	require.Empty(t, resp.Body)

	got, err := tg.Control.SyncReports()
	require.NoError(t, err)
	require.Len(t, got, 1, "one call per sync, never one per package")
	require.Equal(t, report.Profile, got[0].Profile)
	require.Equal(t, report.Revision, got[0].Revision)

	t.Run("an unknown profile is 404", func(t *testing.T) {
		bad := report
		bad.Profile = tg.Fixtures.MissingProfile
		raw, err := json.Marshal(bad)
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound,
			newClient(t, tg).post("/v1/sync", "application/json", tg.Token, raw).Status)
	})

	t.Run("a missing host is 422", func(t *testing.T) {
		bad := report
		bad.Host = ""
		raw, err := json.Marshal(bad)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnprocessableEntity,
			newClient(t, tg).post("/v1/sync", "application/json", tg.Token, raw).Status)
	})

	t.Run("a non-integer revision is refused, because head must already be resolved", func(t *testing.T) {
		raw := []byte(`{"profile":"` + tg.Fixtures.Profile + `","revision":"head","host":"h","targets":["claude-code"]}`)
		require.Equal(t, http.StatusUnprocessableEntity,
			newClient(t, tg).post("/v1/sync", "application/json", tg.Token, raw).Status)
	})

	t.Run("an unknown target is 422", func(t *testing.T) {
		raw := []byte(`{"profile":"` + tg.Fixtures.Profile + `","revision":1,"host":"h","targets":["emacs"]}`)
		require.Equal(t, http.StatusUnprocessableEntity,
			newClient(t, tg).post("/v1/sync", "application/json", tg.Token, raw).Status)
	})

	t.Run("only the accepted report was recorded", func(t *testing.T) {
		got, err := tg.Control.SyncReports()
		require.NoError(t, err)
		require.Len(t, got, 1, "a refused report must not leave an audit row")
	})
}

// ---- the fake claims to support every case

func TestTheFakeFillsInEveryFixture(t *testing.T) {
	h := fake.New(fake.Options{})
	defer h.Close()
	f := h.Target().Fixtures

	// An empty field is the protocol for "this hub cannot express that case", and a
	// suite is then required to skip. The FAKE must express all of them, or the
	// suite skips silently and R5's whole point is lost.
	require.NotEmpty(t, f.Profile)
	require.NotEmpty(t, f.DigestMismatch)
	require.NotEmpty(t, f.ForbiddenBundle)
	require.NotEmpty(t, f.ForbiddenEntryID)
	require.NotEmpty(t, f.PresignedBundle)
	require.NotEmpty(t, f.UnknownSkipReason)
	require.NotEmpty(t, f.MissingProfile)
	require.Len(t, f.SharedNamespaceIDs, 2)
	require.Positive(t, f.HeadRevision)
	require.Positive(t, f.PriorRevision)
	require.Greater(t, f.HeadRevision, f.PriorRevision)
}

func TestTLSVariantServesHTTPS(t *testing.T) {
	h := fake.New(fake.Options{TLS: true})
	defer h.Close()
	tg := h.Target()
	require.True(t, strings.HasPrefix(tg.BaseURL, "https://"))
	// The CLI refuses a plaintext hub without an explicit flag (FR-041), so the
	// suite's default hub must be reachable over TLS with the client the Target
	// hands out and no system trust store involved.
	require.Equal(t, http.StatusOK, newClient(t, tg).get("/v1/profiles", tg.Token).Status)
}
