package hub_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The api is a stub here, and the assertions are on the WIRE: the raw query
// string it receives and the raw JSON it answers with. Asserting against
// apiclient's structs instead would let a mapping bug in this package cancel out
// against the same bug in the test, and the whole point of this package is that
// the two roles only ever meet over HTTP.

func TestTheScreensVocabularyReachesTheApiAsTheOperationsVocabulary(t *testing.T) {
	var got string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		writeCatalog(w, `{"packages":[],"total":0,"page":1,"pageSize":10,"categories":[],"tags":[]}`)
	})

	_, err := client.Catalog(t.Context(), view.CatalogQuery{
		Text:       "terraform",
		Kind:       view.KindFilterPlugins,
		Status:     view.StatusVerified,
		Categories: []string{"Infrastructure", "Data"},
		Tags:       []string{"aws", "guardrails"},
		Sort:       view.SortName,
		Dir:        view.DirAsc,
		Page:       3,
	})
	require.NoError(t, err)

	// The chips are the design's labels — "Plugins", "Verified" — and the
	// operation's enums are lowercase singulars. Sending a label would be a 422 the
	// person sees as an empty catalog.
	require.Contains(t, got, "kind=plugin&")
	require.Contains(t, got, "status=verified")
	require.Contains(t, got, "q=terraform")
	require.Contains(t, got, "sort=name")
	require.Contains(t, got, "dir=asc")
	require.Contains(t, got, "page=3")
	require.Contains(t, got, "pageSize=10")

	// Repeated rather than comma-joined: the operation declares these exploded, and
	// a category called "Security & compliance" has no separator a join could use.
	require.Equal(t, 2, strings.Count(got, "category="), got)
	require.Equal(t, 2, strings.Count(got, "tag="), got)
	require.Contains(t, got, "category=Infrastructure")
	require.Contains(t, got, "category=Data")
}

func TestARowIsRenderedFromTheApisAnswerAndNothingElse(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		writeCatalog(w, `{
		  "packages": [
		    {"id":"example/pii-redactor","name":"pii-redactor","publisher":"example/security",
		     "kind":"skill","category":"Security & compliance","version":"1.4.2","verdict":"clean",
		     "uses":34,"updatedAt":"2026-08-23T12:00:00Z","tags":["pii","security"]},
		    {"id":"community/slack-digest","name":"slack-digest","publisher":"community/hexley",
		     "kind":"plugin","version":"0.5.1","verdict":"rejected","uses":0,
		     "updatedAt":"2026-08-27T11:59:30Z"}
		  ],
		  "total": 2, "page": 1, "pageSize": 10,
		  "categories": [{"value":"Security & compliance","count":2},{"value":"Data","count":1}],
		  "tags": [{"value":"pii","count":1}]
		}`)
	}, hub.WithClock(func() time.Time { return now }))

	page, err := client.Catalog(t.Context(), view.CatalogQuery{Categories: []string{"Data"}})
	require.NoError(t, err)
	require.Len(t, page.Rows, 2)

	first := page.Rows[0]
	require.Equal(t, "example/pii-redactor", first.ID)
	require.Equal(t, "example/security", first.Publisher,
		"the publisher is the owning team's slug, which is not the id's namespace")
	require.Equal(t, "Pii Redactor", first.Name,
		"the title is derived here because no column carries one — PII is unrecoverable")
	require.Equal(t, "4 days ago", first.Updated)
	require.Equal(t, view.ScanClean, first.Scan)
	require.Equal(t, "Security & compliance", first.Category)

	second := page.Rows[1]
	// A rejected version is the strongest case of "do not adopt without reading the
	// finding", so it shares the Flagged pill rather than inventing a fourth.
	require.Equal(t, view.ScanFlagged, second.Scan)
	require.Equal(t, "just now", second.Updated)
	require.Empty(t, second.Category, "an absent category is empty, not the literal null")
	require.NotNil(t, second.Tags, "a row with no tags renders an empty list, never a nil range")

	// Selection is the screen's state, not the api's: the api counts, this marks.
	require.Equal(t, []view.FacetOption{
		{Label: "Security & compliance", Count: 2},
		{Label: "Data", Count: 1, Selected: true},
	}, page.Categories)
}

func TestA401IsTheSignedOutStateAndEveryOtherRefusalIsAnError(t *testing.T) {
	t.Run("401 is a state the screen can render", func(t *testing.T) {
		client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"title":"Unauthorized","status":401,"detail":"missing bearer token"}`))
		})

		_, err := client.Catalog(t.Context(), view.CatalogQuery{})
		require.ErrorIs(t, err, view.ErrSignedOut)
	})

	// The negative control: if every refusal mapped to signed out, the test above
	// would pass for the wrong reason and a broken api would ask people to log in.
	t.Run("every other refusal stays an error", func(t *testing.T) {
		for _, status := range []int{http.StatusForbidden, http.StatusUnprocessableEntity,
			http.StatusInternalServerError, http.StatusBadGateway} {
			client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"title":"nope","detail":"a detail for the api's own logs"}`))
			})

			_, err := client.Catalog(t.Context(), view.CatalogQuery{})
			require.NotErrorIs(t, err, view.ErrSignedOut, "%d must not read as signed out", status)
			require.ErrorContains(t, err, strconv.Itoa(status))
			require.NotContains(t, err.Error(), "a detail for the api's own logs",
				"an api problem detail is not a web-role log line")
		}
	})
}

// Principle II from the other side of the hop: the header the api actually
// receives is built from the caller's own token and from nothing else.
func TestTheAuthorizationHeaderIsTheCallersTokenOrIsAbsent(t *testing.T) {
	var seen string
	var present bool
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		seen, present = r.Header.Get("Authorization"), r.Header.Values("Authorization") != nil
		writeCatalog(w, `{"packages":[],"total":0,"page":1,"pageSize":10,"categories":[],"tags":[]}`)
	})

	_, err := client.Catalog(view.WithToken(t.Context(), "the-callers-own-session-token"),
		view.CatalogQuery{})
	require.NoError(t, err)
	require.Equal(t, "Bearer the-callers-own-session-token", seen)

	// No token, no header. Sending an empty bearer would be a different request
	// from sending none, and the api would answer it the same way for now — but a
	// header that is always present is one nobody notices going stale.
	_, err = client.Catalog(t.Context(), view.CatalogQuery{})
	require.NoError(t, err)
	require.False(t, present, "an unauthenticated request must carry no Authorization header at all")
}

func TestTheRegistrationBannerShowsTheIdTheCatalogWillShow(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"018f0000-0000-7000-8000-000000000000",
		  "publisher":"example/security","name":"pii-redactor","version":"1.4.2","status":"queued"}`))
	})

	result, err := client.Register(t.Context(), view.Registration{
		Tab: view.ImportURL, URL: "https://example.invalid/repo.git", Publisher: "example/security",
	})
	require.NoError(t, err)
	require.True(t, result.Registered)
	// namespace/name. Concatenating the publisher whole gives
	// example/security/pii-redactor, which is not an id the catalog can ever show.
	require.Equal(t, "example/pii-redactor", result.ID)
	require.Equal(t, "1.4.2", result.Version)
}

func TestARefusedRegistrationIsAResultToRenderAndNotAnError(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"title":"Unprocessable Entity","status":422,
		  "detail":"the archive declares no manifest"}`))
	})

	result, err := client.Register(t.Context(), view.Registration{Tab: view.ImportURL})
	require.NoError(t, err, "a refusal the person must read is not a transport failure")
	require.False(t, result.Registered)
	require.Equal(t, "the archive declares no manifest", result.Message)
}

// Registration is fully authenticated and stays that way, so its 401 is not the
// catalog's: it is a person to send to a login, not a finding about their bundle.
func TestASignedOutRegistrationIsWordedAsALoginAndNotAsARejectedArchive(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"title":"Unauthorized","status":401,"detail":"missing bearer token"}`))
	})

	result, err := client.Register(t.Context(), view.Registration{Tab: view.ImportURL})
	require.NoError(t, err)
	require.False(t, result.Registered)
	require.Equal(t, "Sign in to register a package.", result.Message)
	require.NotContains(t, result.Message, "refused",
		"nothing about the archive was judged, so nothing may say it was")
}

func clientAgainst(t *testing.T, handler http.HandlerFunc, opts ...hub.Option) *hub.Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := hub.New(server.URL, opts...)
	require.NoError(t, err)
	return client
}

func writeCatalog(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	// Compacted so the stub answers the bytes a real api would rather than the
	// indentation this file needs to stay readable.
	var out any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		panic(err)
	}
	_ = json.NewEncoder(w).Encode(out)
}
