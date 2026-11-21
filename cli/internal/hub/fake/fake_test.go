package fake

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/cache"
	"github.com/WindKube/agent-manager/cli/internal/hub"
)

// The fake's self-test that what it serves conforms to the contract; internal because some cases need the catalog.

// response is the fetched result with the body already read and closed.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

// fetch does one GET without following redirects, so the pre-signed hop stays visible.
func fetch(t *testing.T, tg Target, path, token string) response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tg.BaseURL+path, http.NoBody)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := *tg.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return response{Status: resp.StatusCode, Header: resp.Header, Body: b}
}

// servedLockfiles fetches every lockfile through the API, so the same walk works against a real hub.
func servedLockfiles(t *testing.T, tg Target) map[string][]byte {
	t.Helper()
	resp := fetch(t, tg, "/v1/profiles", tg.Token)
	require.Equal(t, http.StatusOK, resp.Status)
	var list hub.ProfileList
	require.NoError(t, json.Unmarshal(resp.Body, &list))
	require.NotEmpty(t, list.Profiles)

	out := map[string][]byte{}
	for _, p := range list.Profiles {
		r := fetch(t, tg, fmt.Sprintf("/v1/profiles/%s/revisions/head", p.Slug), tg.Token)
		require.Equal(t, http.StatusOK, r.Status, p.Slug)
		out[p.Slug+"/head"] = r.Body
	}
	r := fetch(t, tg, fmt.Sprintf("/v1/profiles/%s/revisions/%d", tg.Fixtures.Profile, tg.Fixtures.PriorRevision), tg.Token)
	require.Equal(t, http.StatusOK, r.Status)
	out[fmt.Sprintf("%s/%d", tg.Fixtures.Profile, tg.Fixtures.PriorRevision)] = r.Body
	return out
}

func TestServedLockfilesConformToTheFrozenSchema(t *testing.T) {
	h := New(Options{})
	defer h.Close()
	tg := h.Target()
	schema := lockfileSchema(t)

	bodies := servedLockfiles(t, tg)
	// Eight profile heads plus the baseline's older revision.
	require.Len(t, bodies, 9)

	for key, body := range bodies {
		t.Run("lockfile "+key+" validates", func(t *testing.T) {
			var doc any
			require.NoError(t, json.Unmarshal(body, &doc))
			v := &validator{}
			if strings.HasPrefix(key, slugFutureSkip+"/") {
				// Deliberately carries a reason the enum does not list.
				v.relaxEnumAt = "/skipped/0/reason"
			}
			v.check(schema, doc, "")
			require.Empty(t, v.out, "%v", v.out)
		})
	}
}

// relaxEnumAt is only safe if it is that profile's only deviation.
func TestTheUnknownSkipReasonProfileDeviatesInExactlyOneWay(t *testing.T) {
	h := New(Options{})
	defer h.Close()
	tg := h.Target()

	resp := fetch(t, tg, "/v1/profiles/"+tg.Fixtures.UnknownSkipReason+"/revisions/head", tg.Token)
	require.Equal(t, http.StatusOK, resp.Status)
	var doc any
	require.NoError(t, json.Unmarshal(resp.Body, &doc))

	v := &validator{}
	v.check(lockfileSchema(t), doc, "")
	require.Len(t, v.out, 1)
	require.Equal(t, "/skipped/0/reason", v.out[0].path)
	require.Contains(t, v.out[0].msg, "not in the enum")
	require.Contains(t, v.out[0].msg, futureSkipReason)
}

func TestTheBaselineLockfileReportsSkippedEntriesWithLegalReasons(t *testing.T) {
	h := New(Options{})
	defer h.Close()
	tg := h.Target()

	resp := fetch(t, tg, "/v1/profiles/"+tg.Fixtures.Profile+"/revisions/head", tg.Token)
	require.Equal(t, http.StatusOK, resp.Status)
	var lf hub.Lockfile
	require.NoError(t, json.Unmarshal(resp.Body, &lf))

	require.NotEmpty(t, lf.Skipped, "verbatim skip reasons cannot be exercised against an empty skipped array")
	reasons := map[hub.LockfileSkipReason]bool{}
	for _, s := range lf.Skipped {
		require.True(t, s.Reason.Valid(), "%q is not one of the six legal reasons", s.Reason)
		reasons[s.Reason] = true
	}
	require.GreaterOrEqual(t, len(reasons), 2, "at least two distinct reasons must appear")
}

// Reads the catalog directly, since the lockfile carries no publisher field.
func TestTwoPublishersShareOneNamespaceInTheCatalog(t *testing.T) {
	h := New(Options{})
	defer h.Close()
	ids := h.Target().Fixtures.SharedNamespaceIDs
	require.Len(t, ids, 2)

	publishers := map[string]string{}
	namespaces := map[string]bool{}
	for _, p := range h.pkgs {
		for _, id := range ids {
			if p.ID != id {
				continue
			}
			publishers[p.Publisher] = p.ID
			namespaces[p.namespace()] = true
		}
	}
	require.Len(t, namespaces, 1, "the two fixture ids must sit in ONE namespace")
	require.Len(t, publishers, 2, "the two fixture ids must come from TWO publishers")
	require.NotEqual(t, ids[0], ids[1])
}

// Re-derived through internal/cache's parsers, independently of the blob helper that produced them.
func TestDigestHeaderAndLockfileDigestMatchTheServedBytes(t *testing.T) {
	h := New(Options{})
	defer h.Close()
	tg := h.Target()

	checked := 0
	for key, body := range servedLockfiles(t, tg) {
		var lf hub.Lockfile
		require.NoError(t, json.Unmarshal(body, &lf))
		mismatchProfile := strings.HasPrefix(key, tg.Fixtures.DigestMismatch+"/")

		for _, e := range lf.Entries {
			ns, name, ok := strings.Cut(e.Id, "/")
			require.True(t, ok, "entry id %q must be exactly namespace/name", e.Id)
			require.NotEmpty(t, ns)
			require.NotEmpty(t, name)

			resp := fetch(t, tg, "/v1/bundles/"+ns+"/"+name+"/"+e.Version, tg.Token)
			if resp.Status == http.StatusForbidden || resp.Status == http.StatusTemporaryRedirect {
				continue // covered by their own behavioural cases
			}
			require.Equal(t, http.StatusOK, resp.Status, e.Id)
			require.Equal(t, "application/zstd", resp.Header.Get("Content-Type"))
			bytesOut := resp.Body

			fromHeader, err := cache.ParseHeaderDigest(resp.Header.Get("Digest"))
			require.NoError(t, err, "the Digest header must be RFC 3230 sha-256=<base64>")
			require.Equal(t, cache.Compute(bytesOut), fromHeader,
				"the Digest header does not describe the bytes served for %s", e.Id)

			fromLockfile, err := cache.ParseLockfileDigest(e.Digest)
			require.NoError(t, err)
			if mismatchProfile && e.Id == "contoso/stale-digest" {
				require.NotEqual(t, cache.Compute(bytesOut), fromLockfile,
					"the digest-mismatch fixture must actually mismatch")
			} else {
				require.Equal(t, cache.Compute(bytesOut), fromLockfile,
					"the lockfile digest does not describe the bytes served for %s", e.Id)
			}
			require.Equal(t, `"`+fromHeader.Hex()+`"`, resp.Header.Get("ETag"))
			checked++
		}
	}
	require.GreaterOrEqual(t, checked, 5, "too few bundles were reached for this to mean anything")
}

var userCodePattern = regexp.MustCompile(`^[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}$`)

func TestUserCodesMatchTheContractShape(t *testing.T) {
	for range 500 {
		code := randomUserCode()
		require.Regexp(t, userCodePattern, code)
		require.NotContains(t, code, "I")
		require.NotContains(t, code, "L")
		require.NotContains(t, code, "O")
		require.NotContains(t, code, "U")
	}
}

func TestIssuedTokensAreOpaque(t *testing.T) {
	for range 100 {
		tok := randomToken()
		require.NotContains(t, tok, ".", "a token with dots invites jwt.Parse; the hub's are opaque")
		require.NotContains(t, tok, "=")
		require.Len(t, tok, 43, "base64url of 32 bytes, unpadded")
	}
}
