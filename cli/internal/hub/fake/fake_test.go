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

// This file is the R5 self-test: it checks that what the fake SERVES conforms to
// the frozen contract. It lives in `package fake` because a couple of cases need
// the catalog. The behavioural tests live in behaviour_test.go, in
// `package fake_test`, which cannot reach anything unexported — that is the R5
// seam enforced by the compiler rather than by a comment.
//
// Note for whoever writes internal/hub's own tests (T021): package hub's IN-PACKAGE
// test files cannot import this package, because fake imports hub and Go treats
// that as an import cycle. Use `package hub_test` there. That is a real constraint
// but not the reason for the dependency direction; see doc.go.

// response is the fetched result with the body already read and closed. It exists
// so no *http.Response escapes fetch: a helper that hands one back leaves every
// caller responsible for a Close it cannot be checked for.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

// fetch does one GET and returns the whole response, body included and closed.
// Redirects are NOT followed: this walk is about what each response says, and a 307
// followed silently would hide the pre-signed hop entirely. The behavioural test
// that does follow one builds its own client.
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

// servedLockfiles fetches every lockfile the fake serves, THROUGH THE API: the
// slugs and heads come from listProfiles and the older revision from the fixture
// descriptor. Nothing here reads h.lockfiles, so the same walk works against a
// real hub.
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
	// Seven: six profile heads plus the baseline's older revision. Asserted so a
	// profile silently dropped from the catalog cannot shrink this test to nothing.
	require.Len(t, bodies, 7)

	for key, body := range bodies {
		t.Run("lockfile "+key+" validates", func(t *testing.T) {
			var doc any
			require.NoError(t, json.Unmarshal(body, &doc))
			v := &validator{}
			if strings.HasPrefix(key, slugFutureSkip+"/") {
				// The one profile that deliberately carries a reason the frozen enum
				// does not list, because FR-011 requires the CLI to pass an
				// unrecognised reason through verbatim and it cannot be tested
				// against a fake that only serves the six.
				v.relaxEnumAt = "/skipped/0/reason"
			}
			v.check(schema, doc, "")
			require.Empty(t, v.out, "%v", v.out)
		})
	}
}

// The relaxation above is only safe if it is the ONLY deviation. If that profile
// drifted in some other way, relaxEnumAt would hide it.
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

	require.NotEmpty(t, lf.Skipped, "FR-011 cannot be exercised against an empty skipped array")
	reasons := map[hub.LockfileSkipReason]bool{}
	for _, s := range lf.Skipped {
		require.True(t, s.Reason.Valid(), "%q is not one of the six legal reasons", s.Reason)
		reasons[s.Reason] = true
	}
	require.GreaterOrEqual(t, len(reasons), 2, "at least two distinct reasons must appear")
}

// FR-023 is about namespace/name, so the fake must contain a namespace shared by
// two publishers. The lockfile carries no publisher field, so the publisher half of
// this assertion reads the catalog directly — it is a property of the fixture, not
// of a response, and there is nothing on the wire that could carry it.
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
	require.Len(t, publishers, 2, "the two fixture ids must come from TWO publishers, or FR-023 is untestable")
	require.NotEqual(t, ids[0], ids[1])
}

// The digest header and the bytes cannot be allowed to disagree. This re-derives
// both through internal/cache's parsers — an independent implementation of the same
// two encodings — rather than through the blob helper that produced them.
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
	// 500 draws: the alphabet excludes I, L, O and U, and a single draw would not
	// notice one of them slipping in.
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
