package hub_test

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The governance methods, with the api stubbed and the assertions on the WIRE.
// Same reasoning as the catalog's tests: asserting against apiclient's structs
// would let a mapping bug here cancel out against the same bug in the test.

func TestTheScannerSummaryReadsItsInstantsAgainstTheClientsClock(t *testing.T) {
	var got string
	now := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		writeCatalog(w, `{
		  "periodDays": 30, "versionsScanned": 1284, "quarantined": 2, "overridesActive": 1,
		  "nearestOverrideExpiry": "2026-09-12T09:00:00Z", "medianScanSeconds": 18.5
		}`)
	}, hub.WithClock(func() time.Time { return now }))

	summary, err := client.ScannerSummary(t.Context(), 30)
	require.NoError(t, err)
	require.Contains(t, got, "days=30")

	require.Equal(t, 30, summary.PeriodDays,
		"the caption's window comes from the api, so no figure on the screen is a constant")
	require.Equal(t, 1284, summary.VersionsScanned)
	require.Equal(t, 2, summary.Quarantined)
	require.Equal(t, 1, summary.OverridesActive)
	require.Equal(t, "in 12 days", summary.NearestExpiry)
	require.Equal(t, "19s", summary.MedianScan)
}

// An absent figure must stay absent. "No scan finished in the window" and "the
// median is zero" are different cards, and a zero-valued duration would render as
// "0s" — a claim about a scan that never happened.
func TestAnAbsentSummaryFigureStaysAbsentRatherThanBecomingZero(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		writeCatalog(w, `{"periodDays":30,"versionsScanned":0,"quarantined":0,"overridesActive":0}`)
	})

	summary, err := client.ScannerSummary(t.Context(), 0)
	require.NoError(t, err)
	require.Empty(t, summary.MedianScan)
	require.Empty(t, summary.NearestExpiry)
}

// days of 0 sends no parameter at all, so the api's own default applies. A client
// that filled in 30 here would be a second place that knows the window.
func TestAnUnaskedForWindowIsNotInventedByThisRole(t *testing.T) {
	var got string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		writeCatalog(w, `{"periodDays":30,"versionsScanned":0,"quarantined":0,"overridesActive":0}`)
	})

	_, err := client.ScannerSummary(t.Context(), 0)
	require.NoError(t, err)
	require.NotContains(t, got, "days=")
}

func TestAFindingRowCarriesTheSubjectAndTheVersionsOwnVerdict(t *testing.T) {
	var got string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		writeCatalog(w, `{
		  "findings": [
		    {"id":"01930000-0000-7000-8000-000000000001","ruleId":"SH-NET-002","severity":"high",
		     "state":"open","title":"Undeclared network egress","packageId":"community/slack-digest",
		     "version":"0.5.1","verdict":"flagged","raisedAt":"2026-08-27T10:00:00Z",
		     "evidencePath":"scripts/digest.sh","evidenceLine":41},
		    {"id":"01930000-0000-7000-8000-000000000002","ruleId":"SH-FS-007","severity":"low",
		     "state":"rejected","title":"Broad filesystem write scope","packageId":"community/finops",
		     "version":"2.0.0","verdict":"rejected","raisedAt":"2026-08-26T10:00:00Z"}
		  ],
		  "total": 2, "page": 1, "pageSize": 20
		}`)
	})

	page, err := client.Findings(t.Context(), hub.FindingQuery{State: "open", Severity: "high", Page: 2})
	require.NoError(t, err)
	require.Contains(t, got, "state=open")
	require.Contains(t, got, "severity=high")
	require.Contains(t, got, "page=2")

	require.Len(t, page.Rows, 2)
	require.Equal(t, "community/slack-digest@0.5.1", page.Rows[0].Subject)
	require.Equal(t, "community/slack-digest", page.Rows[0].PackageID)
	require.NotNil(t, page.Rows[0].Primary)
	require.Equal(t, "scripts/digest.sh:41", page.Rows[0].Primary.Location())

	// A finding with no recorded location carries none, rather than an empty one.
	require.Nil(t, page.Rows[1].Primary)

	// `rejected` survives as itself. The catalog collapses it onto the Flagged pill
	// — "do not adopt this without reading the finding" — and on this screen the
	// difference between awaiting a decision and having had one is the subject of
	// the page.
	require.Equal(t, view.VerdictRejected, page.Rows[1].Verdict)
	require.Equal(t, view.FindingRejected, page.Rows[1].State)
}

func TestAnEmptyFilterSendsNoParameterRatherThanTheWordAll(t *testing.T) {
	var got string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		writeCatalog(w, `{"findings":[],"total":0,"page":1,"pageSize":20}`)
	})

	_, err := client.Findings(t.Context(), hub.FindingQuery{})
	require.NoError(t, err)
	require.NotContains(t, got, "state=")
	require.NotContains(t, got, "severity=")
}

// The whole matrix reaches the screen, passes included, and the primary evidence
// location is picked off the row whose role says so rather than by position.
func TestTheFindingDetailKeepsEveryCheckAndFindsThePrimaryLocationByItsRole(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		writeCatalog(w, `{
		  "id":"01930000-0000-7000-8000-000000000001","ruleId":"SH-NET-002","severity":"high",
		  "state":"open","title":"Undeclared network egress","packageId":"community/slack-digest",
		  "version":"0.5.1","verdict":"flagged","raisedAt":"2026-08-27T10:00:00Z",
		  "detail":"The digest script issues an HTTP request to an undeclared host.",
		  "evidence":[
		    {"path":"scripts/digest.sh","line":58,"quote":"curl ...","role":"supporting"},
		    {"path":"scripts/digest.sh","line":41,"quote":"curl ...","role":"primary"}
		  ],
		  "checks":[
		    {"checkId":"manifest-schema","label":"Manifest schema","result":"pass","warnCount":0},
		    {"checkId":"network-allowlist","label":"Network allowlist","result":"fail","warnCount":0},
		    {"checkId":"shell-command-audit","label":"Shell command audit","result":"warn","warnCount":2}
		  ],
		  "scan":{"packVersion":"1.4.0","startedAt":"2026-08-27T09:59:42Z",
		          "finishedAt":"2026-08-27T10:00:00Z","verdict":"flagged","timedOut":false},
		  "override":{"reviewer":"ewojcik@example.com","note":"accepted",
		              "expiresAt":"2026-09-12T09:00:00Z","decidedAt":"2026-08-31T09:00:00Z"}
		}`)
	})

	detail, err := client.Finding(t.Context(), "01930000-0000-7000-8000-000000000001")
	require.NoError(t, err)

	require.Len(t, detail.Checks, 3, "the passes are carried, or the matrix cannot be told from silence")
	require.Equal(t, view.CheckPass, detail.Checks[0].Result)
	require.Equal(t, 2, detail.Checks[2].WarnCount)

	// The primary row is second in the answer, so a mapping that took evidence[0]
	// would name the consequence as the cause.
	require.NotNil(t, detail.Primary)
	require.Equal(t, "scripts/digest.sh", detail.Primary.Path)
	require.Equal(t, 41, detail.Primary.Line)
	require.Len(t, detail.Supporting, 1)
	require.Equal(t, 58, detail.Supporting[0].Line)

	require.Equal(t, "1.4.0", detail.Scan.PackVersion)
	require.Equal(t, "2026-08-27 10:00 UTC", detail.Scan.Finished)
	require.NotNil(t, detail.Override)
	require.Equal(t, "ewojcik@example.com", detail.Override.Reviewer)
	require.Contains(t, detail.Explanation, "undeclared host")
}

// An id out of a URL a person can edit is answered as "no such finding" here,
// without a round trip to be told the same thing.
func TestAnIdThatIsNotAUuidIsNotFoundWithoutReachingTheApi(t *testing.T) {
	reached := false
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		writeCatalog(w, `{}`)
	})

	_, err := client.Finding(t.Context(), "../../etc/passwd")
	require.ErrorIs(t, err, view.ErrNotFound)
	require.False(t, reached, "the api was called with an id that cannot name a finding")
}

// FR-126: a role refusal is a screen state with a reason, not a bad gateway. It
// must also not be confused with the signed-out state — signing in again does not
// acquire a role, so a person sent round that loop cannot get out of it.
func TestARoleRefusalIsItsOwnStateAndNotTheSignedOutOne(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   error
	}{
		{"a role that may not decide", http.StatusForbidden, hub.ErrForbidden},
		{"no usable session", http.StatusUnauthorized, view.ErrSignedOut},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			})

			err := client.AcceptFinding(t.Context(), "01930000-0000-7000-8000-000000000001",
				"considered", 12)
			require.ErrorIs(t, err, tc.want)

			err = client.RejectFinding(t.Context(), "01930000-0000-7000-8000-000000000001", "")
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestAcceptSendsTheNoteAndTheLifetimeAndRejectSendsNoLifetimeAtAll(t *testing.T) {
	var bodies []string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		writeCatalog(w, `{"id":"01930000-0000-7000-8000-000000000001","state":"approved",
		                  "verdict":"flagged","expiresAt":"2026-09-12T09:00:00Z"}`)
	})

	err := client.AcceptFinding(t.Context(), "01930000-0000-7000-8000-000000000001",
		"Egress is to our own collector", 12)
	require.NoError(t, err)

	err = client.RejectFinding(t.Context(), "01930000-0000-7000-8000-000000000001",
		"publisher is shipping a fix")
	require.NoError(t, err)

	require.Len(t, bodies, 2)
	require.Contains(t, bodies[0], `"note":"Egress is to our own collector"`)
	require.Contains(t, bodies[0], `"expiresInDays":12`)
	require.NotContains(t, bodies[1], "expiresInDays",
		"a rejection is terminal, so there is no lifetime to send and no field to suggest one")
}

// A lifetime nobody chose is left to the api. The default is policy and it lives
// on the side that owns the row.
func TestAnUnstatedOverrideLifetimeIsNotInventedHere(t *testing.T) {
	var body string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		writeCatalog(w, `{"id":"01930000-0000-7000-8000-000000000001","state":"approved",
		                  "verdict":"flagged"}`)
	})

	err := client.AcceptFinding(t.Context(), "01930000-0000-7000-8000-000000000001", "note", 0)
	require.NoError(t, err)
	require.NotContains(t, body, "expiresInDays")
}

func TestTheAuditPageIsMappedRowForRow(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		writeCatalog(w, `{
		  "entries":[
		    {"id":"01930000-0000-7000-8000-00000000000a","occurredAt":"2026-08-27T14:02:00Z",
		     "actor":"jkowalski@example.com","actorKind":"identity","kind":"sync",
		     "text":"synced platform-baseline r14","source":"cli / mbp-jk"},
		    {"id":"01930000-0000-7000-8000-00000000000b","occurredAt":"2026-08-27T13:48:00Z",
		     "actor":"scanner","actorKind":"system","kind":"scan",
		     "text":"quarantined community/slack-digest@0.5.1"}
		  ],
		  "total":512,"page":1,"pageSize":50
		}`)
	})

	page, err := client.Audit(t.Context(), 1, view.AuditFilter{})
	require.NoError(t, err)
	require.Equal(t, 512, page.Total)
	require.Len(t, page.Rows, 2)
	require.Equal(t, "cli / mbp-jk", page.Rows[0].Source)
	require.False(t, page.Rows[0].System)
	require.True(t, page.Rows[1].System,
		"a system row must not be attributable to a person, so the kind is carried and not inferred")
	require.Empty(t, page.Rows[1].Source)
}

// The filter travels as the api's query params, and a row about a version is
// mapped to its package so the screen can link it.
func TestTheAuditFilterIsForwardedAndSubjectsAreMapped(t *testing.T) {
	var query url.Values
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		writeCatalog(w, `{
		  "entries":[
		    {"id":"01930000-0000-7000-8000-00000000000a","occurredAt":"2026-08-27T14:02:00Z",
		     "actor":"scanner","actorKind":"system","kind":"scan","text":"flagged community/slack-digest@0.5.1",
		     "subjectKind":"version","subjectId":"community/slack-digest@0.5.1","namespace":"community",
		     "data":{"action":"scanned","package":"community/slack-digest","semver":"0.5.1"}},
		    {"id":"01930000-0000-7000-8000-00000000000b","occurredAt":"2026-08-27T13:48:00Z",
		     "actor":"a@example.com","actorKind":"identity","kind":"login","text":"a signed in",
		     "subjectKind":"identity","subjectId":"01930000-0000-7000-8000-0000000000ff"}
		  ],
		  "total":2,"page":1,"pageSize":50
		}`)
	})

	page, err := client.Audit(t.Context(), 1,
		view.AuditFilter{SubjectKind: "package", SubjectID: "community/slack-digest"})
	require.NoError(t, err)
	require.Equal(t, "package", query.Get("subjectKind"))
	require.Equal(t, "community/slack-digest", query.Get("subjectId"))
	require.False(t, query.Has("namespace"), "an unset filter is left off the query")

	require.Equal(t, "version", page.Rows[0].SubjectKind)
	require.Equal(t, "community/slack-digest", page.Rows[0].Package)
	require.Equal(t, "/packages/community/slack-digest", page.Rows[0].PackageHref())
	require.Empty(t, page.Rows[1].Package)
	require.Empty(t, page.Rows[1].PackageHref())
}

// The export is handed back as a live stream. A method that decoded it would
// undo, one layer later, the whole reason the api streams it.
func TestTheAuditExportIsHandedBackAsAStreamAndNotAsBytes(t *testing.T) {
	lines := "{\"id\":\"a\"}\n{\"id\":\"b\"}\n{\"complete\":true,\"rows\":2}\n"
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = w.Write([]byte(lines))
	})

	body, mediaType, err := client.AuditExport(t.Context(), view.AuditFilter{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, body.Close()) })
	require.Equal(t, "application/x-ndjson", mediaType)

	read, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, lines, string(read))
	require.Equal(t, 3, strings.Count(string(read), "\n"))
}

// A refused export must not be handed back as if it were one: its body is a
// problem document, and a caller copying it to the browser would write that into
// the operator's file.
func TestARefusedExportYieldsNoReader(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"title":"Unauthorized"}`))
	})

	body, _, err := client.AuditExport(t.Context(), view.AuditFilter{})
	require.Nil(t, body)
	require.True(t, errors.Is(err, view.ErrSignedOut))
}

func TestTheBadgeCountsAreReadAsThreeIntegers(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		writeCatalog(w, `{"packages":10,"profiles":4,"openFindings":4}`)
	})

	badges, err := client.Badges(t.Context())
	require.NoError(t, err)
	require.Equal(t, 10, badges.Packages)
	require.Equal(t, 4, badges.Profiles)
	require.Equal(t, 4, badges.OpenFindings)
}
