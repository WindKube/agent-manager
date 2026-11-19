package web_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
)

func TestTheStorageScreenTellsItsFourStatesApart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		failAs int
		id     string
		status int
	}{
		{name: "genuinely empty", id: `id="storage-fetches-empty"`, status: http.StatusOK},
		{name: "refused by role", failAs: http.StatusForbidden, id: `id="storage-refused"`, status: http.StatusForbidden},
		{
			name: "the api did not answer", failAs: http.StatusServiceUnavailable,
			id: `id="storage-unavailable"`, status: http.StatusBadGateway,
		},
		{name: "no usable session", failAs: http.StatusUnauthorized, id: `id="storage-signed-out"`, status: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, h := newServer(t)
			api.Data.Storage = apiclient.StorageReport{}
			if tc.failAs != 0 {
				api.Fail("getStorage", tc.failAs)
			}
			rec := get(t, h, "/storage")
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

func TestTheEmptyStorageScreenSaysWhatWouldBeThereAndHowToGetIt(t *testing.T) {
	api, h := newServer(t)
	api.Data.Storage = apiclient.StorageReport{}
	body := get(t, h, "/storage").Body.String()
	require.Contains(t, body, "Register a package")
}

func TestAnUnknownBucketSettingRendersAsUnknownAndNotAsAGuessedDefault(t *testing.T) {
	api, h := newServer(t)
	api.Data.Storage = apiclient.StorageReport{
		Bucket: apiclient.BucketSettings{
			WriteAccess: apiclient.BucketSetting{Known: true, Value: ptrTo("read-only; only the fetcher role can write")},
		},
	}
	body := get(t, h, "/storage").Body.String()

	// Versioning, object lock, encryption and retention are all unknown, and so is
	// the region and the read-cache figure this zero-value report also carries —
	// six in total. Write access is known and must not be among them.
	require.Equal(t, 6, strings.Count(body, "Unknown"))
	require.Contains(t, body, "read-only; only the fetcher role can write")

	// Scoped to the panel. "disabled" and "false" are the two guesses an unknown
	// setting must not be rendered as, and the sidebar around this screen has
	// legitimate uses for both words — a gated nav entry carries aria-disabled,
	// and a datastar signal block is full of false.
	settings := bucketSettingsPanel(t, body)
	require.NotContains(t, settings, "disabled")
	require.NotContains(t, settings, "false")
}

// bucketSettingsPanel is the "Bucket settings" card and nothing else, so an
// assertion about a setting's rendering cannot be satisfied or broken by the
// chrome around it.
func bucketSettingsPanel(t *testing.T, body string) string {
	t.Helper()

	const head = `<div class="am-section-title">Bucket settings</div>`
	start := strings.Index(body, head)
	require.GreaterOrEqual(t, start, 0, "the bucket settings panel is not on this page")
	rest := body[start+len(head):]
	end := strings.Index(rest, "</section>")
	require.GreaterOrEqual(t, end, 0, "the bucket settings panel does not close")
	return rest[:end]
}

func TestStorageEscapesEverythingAPublisherOrAnOperatorSupplied(t *testing.T) {
	api, h := newServer(t)
	api.Data.Storage = apiclient.StorageReport{
		RecentFetches: []apiclient.FetchAttemptSummary{{
			Id: uuid.New(), OccurredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			SourceKind:   apiclient.FetchAttemptSummarySourceKindArchiveUrl,
			RequestedRef: `<script>alert(1)</script>`, Outcome: apiclient.FetchAttemptSummaryOutcomeUnreachable,
			Detail: ptrTo(`<img src=x onerror=alert(2)>`),
		}},
	}
	body := get(t, h, "/storage").Body.String()

	require.NotContains(t, body, "<script>")
	require.NotContains(t, body, "<img src=x")
	require.Contains(t, body, "&lt;script&gt;")
	require.Contains(t, body, "&lt;img src=x")
}

func TestStorageStatsRenderTheFiguresTheApiReported(t *testing.T) {
	api, h := newServer(t)
	api.Data.Storage = apiclient.StorageReport{
		ObjectCount: 482, CompressedBytes: 1288490189, Region: ptrTo("us-east-1"),
	}
	body := get(t, h, "/storage").Body.String()

	require.Contains(t, body, "482")
	require.Contains(t, body, "1.2 GB")
	require.Contains(t, body, "us-east-1")
}
