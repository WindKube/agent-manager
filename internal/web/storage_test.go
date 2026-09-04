package web_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The Storage screen (US7 scenario 2; 001 FR-053).

// TestTheStorageScreenTellsItsFourStatesApart is FR-122, the same property the
// Scanner and Audit screens carry: signed out, refused by role, the api
// unreachable and genuinely empty are four different screens, not one collapsed
// onto "nothing to show".
func TestTheStorageScreenTellsItsFourStatesApart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source *governance
		id     string
		status int
	}{
		{
			name:   "genuinely empty",
			source: &governance{},
			id:     `id="storage-fetches-empty"`,
			status: http.StatusOK,
		},
		{
			name:   "refused by role",
			source: &governance{err: hub.ErrForbidden},
			id:     `id="storage-refused"`,
			status: http.StatusForbidden,
		},
		{
			name:   "the api did not answer",
			source: &governance{err: errBoom},
			id:     `id="storage-unavailable"`,
			status: http.StatusBadGateway,
		},
		{
			name:   "no usable session",
			source: &governance{err: view.ErrSignedOut},
			id:     `id="storage-signed-out"`,
			status: http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := get(t, govHandler(tc.source, fixture.SignedInViewers(), nil), "/storage")
			require.Equal(t, tc.status, rec.Code)
			body := rec.Body.String()
			require.Contains(t, body, tc.id)

			for _, other := range []string{
				"storage-fetches-empty", "storage-refused", "storage-unavailable", "storage-signed-out",
			} {
				if strings.Contains(tc.id, other) {
					continue
				}
				require.NotContainsf(t, body, `id="`+other+`"`, "this state also renders %q", other)
			}
		})
	}
}

// TestTheEmptyStorageScreenSaysWhatWouldBeThereAndHowToGetIt is the other half of
// FR-122: an empty state that only says "nothing here" tells a reader nothing
// they did not already know.
func TestTheEmptyStorageScreenSaysWhatWouldBeThereAndHowToGetIt(t *testing.T) {
	body := get(t, govHandler(&governance{}, fixture.SignedInViewers(), nil), "/storage").Body.String()
	require.Contains(t, body, "Register a package")
}

// TestAnUnknownBucketSettingRendersAsUnknownAndNotAsAGuessedDefault is 001
// FR-053's central claim: a setting the bucket declines to answer is UNKNOWN,
// never a value this screen invented on its behalf.
func TestAnUnknownBucketSettingRendersAsUnknownAndNotAsAGuessedDefault(t *testing.T) {
	source := &governance{storage: view.Storage{
		Bucket: view.BucketSettings{
			Versioning:  view.BucketSetting{Known: false},
			ObjectLock:  view.BucketSetting{Known: false},
			Encryption:  view.BucketSetting{Known: false},
			Retention:   view.BucketSetting{Known: false},
			WriteAccess: view.BucketSetting{Known: true, Value: "read-only; only the fetcher role can write"},
		},
	}}
	body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/storage").Body.String()

	// Versioning, object lock, encryption and retention are all unknown, and so is
	// the region and the read-cache figure this zero-value report also carries —
	// six in total. Write access is known and must not be among them.
	require.Equal(t, 6, strings.Count(body, "Unknown"))
	require.Contains(t, body, "read-only; only the fetcher role can write")
	require.NotContains(t, body, "disabled")
	require.NotContains(t, body, "false")
}

// TestStorageEscapesEverythingAPublisherOrAnOperatorSupplied is 001 FR-055 /
// FR-127: a fetch's requested reference and its error detail are the two fields
// on this screen that arrive from outside the hub, so they are the two a hostile
// value is aimed at.
func TestStorageEscapesEverythingAPublisherOrAnOperatorSupplied(t *testing.T) {
	source := &governance{storage: view.Storage{
		RecentFetches: []view.FetchRow{
			{
				ID: "f1", At: "2026-01-01 00:00 UTC", Kind: "archive-url",
				Ref: `<script>alert(1)</script>`, Outcome: "unreachable",
				Detail: `<img src=x onerror=alert(2)>`,
			},
		},
	}}
	body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/storage").Body.String()

	require.NotContains(t, body, "<script>")
	require.NotContains(t, body, "<img src=x")
	require.Contains(t, body, "&lt;script&gt;")
	require.Contains(t, body, "&lt;img src=x")
}

// TestStorageStatsRenderTheFiguresTheApiReported is FR-121: nothing on this
// screen's headline row is a constant in the product.
func TestStorageStatsRenderTheFiguresTheApiReported(t *testing.T) {
	source := &governance{storage: view.Storage{
		ObjectCount: 482, CompressedSize: "1.2 GB", Region: "us-east-1",
	}}
	body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/storage").Body.String()

	require.Contains(t, body, "482")
	require.Contains(t, body, "1.2 GB")
	require.Contains(t, body, "us-east-1")
}

// TestStorageWithNoSourceRendersUnavailableNotEmpty mirrors the audit and
// scanner screens: a hub with no source wired is a deployment fault, and it must
// not render as a bucket with nothing in it.
func TestStorageWithNoSourceRendersUnavailableNotEmpty(t *testing.T) {
	h := web.New(web.Deps{
		Catalog: &governance{}, Viewers: fixture.SignedInViewers(), Log: zerolog.Nop(),
	}, web.Options{}).Handler()

	rec := get(t, h, "/storage")
	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), `id="storage-unavailable"`)
}
