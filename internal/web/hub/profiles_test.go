package hub_test

import (
	"context"
	"io"
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

// The profile methods, with the api stubbed and the assertions on the WIRE — the
// escaped path it receives, the bytes of the body it is sent, the raw JSON it
// answers with. Same reasoning as the catalog's and the governance tests:
// asserting against apiclient's structs would let a mapping bug here cancel out
// against the same bug in the test.

// The detail body below is the shape the design's example/platform-engineer has:
// a clean floating entry, a flagged one the gate let through on an override, and
// a pin at a version the gate refused.
const profileDetailBody = `{
  "slug":"example/platform-engineer","name":"Platform Engineer",
  "description":"What a platform engineer's machine gets.",
  "visibility":"organisation","ownerTeam":"example/platform",
  "defaultPolicy":"floating-latest","gate":"warn-with-override","headRevision":14,
  "forkedFrom":"example/sre-oncall","role":"maintainer",
  "permissions":{"curate":true,"share":false,"publish":true},
  "unpublishedChanges":true,
  "entries":[
    {"id":"example/adr-writer","name":"ADR Writer","kind":"skill","mode":"latest",
     "latestVersion":"3.1.0","latestVerdict":"clean","version":"3.1.0","verdict":"clean",
     "digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
     "outcome":"resolved","unpublished":false},
    {"id":"community/slack-digest","name":"Slack Digest","kind":"plugin","mode":"latest",
     "latestVersion":"0.5.1","latestVerdict":"flagged","version":"0.5.1","verdict":"flagged",
     "digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222",
     "outcome":"overridden",
     "note":"Flagged (SH-NET-002 in scripts/digest.sh); an override lets it through.",
     "override":{"reviewer":"ewojcik@example.com","note":"Egress is to our own collector",
                 "expiresAt":"2026-09-12T09:00:00Z"},
     "unpublished":true},
    {"id":"community/finops","name":"FinOps","kind":"skill","mode":"pinned",
     "pinnedVersion":"2.0.0","latestVersion":"2.0.0","latestVerdict":"rejected",
     "outcome":"skipped",
     "skip":{"id":"community/finops","reason":"version-rejected",
             "detail":"SH-FS-007 in scripts/collect.sh","wouldHaveResolvedTo":"2.0.0"},
     "unpublished":false}
  ],
  "members":[
    {"kind":"user","ref":"kwiatrzyk@example.com","role":"owner","displayName":"Krzysztof Wiatrzyk"},
    {"kind":"group","ref":"eng-platform","role":"maintainer"}
  ],
  "targets":[{"target":"claude-code","enabled":true},{"target":"codex","enabled":false}],
  "revisions":[
    {"revision":14,"note":"pinned ADR Writer to 3.0.2","publishedAt":"2026-08-27T14:02:00Z",
     "publishedBy":"pkaczmarek@example.com"},
    {"revision":13,"publishedAt":"2026-08-20T09:15:00Z","publishedBy":"kwiatrzyk@example.com"}
  ]
}`

func TestTheProfileDetailReachesTheScreenAsFactsAndNotAsSentences(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		writeCatalog(w, profileDetailBody)
	})

	detail, err := client.Profile(t.Context(), "example/platform-engineer")
	require.NoError(t, err)

	require.Equal(t, "example/platform-engineer", detail.Slug)
	require.Equal(t, "organisation", detail.Visibility)
	require.Equal(t, "warn-with-override", detail.Gate,
		"the gate is the one in force now, and the screen states it rather than deducing it")
	require.Equal(t, 14, detail.HeadRevision)
	require.Equal(t, "example/sre-oncall", detail.ForkedFrom)
	require.Equal(t, "maintainer", detail.Role)
	require.True(t, detail.UnpublishedChanges)

	// FR-126's answer, carried as three booleans so a screen disables a control
	// rather than offering one that will be refused.
	require.True(t, detail.Permissions.Curate)
	require.False(t, detail.Permissions.Share)
	require.True(t, detail.Permissions.Publish)

	require.Len(t, detail.Members, 2)
	require.Equal(t, "group", detail.Members[1].Kind,
		"a group is matched against the claim, never expanded into people, so the kind travels")
	require.Empty(t, detail.Members[1].DisplayName,
		"a membership may name somebody this hub has never seen sign in")

	require.Equal(t, []hub.ProfileTarget{
		{Target: "claude-code", Enabled: true},
		{Target: "codex", Enabled: false},
	}, detail.Targets, "the whole vocabulary arrives, so the screen holds no copy of the enum")

	require.Len(t, detail.Revisions, 2)
	require.Equal(t, 14, detail.Revisions[0].Revision)
	require.Equal(t, time.Date(2026, 8, 27, 14, 2, 0, 0, time.UTC), detail.Revisions[0].PublishedAt.UTC())
	require.Empty(t, detail.Revisions[1].Note)
}

// The two version pairs answer different questions, and collapsing them would
// lose the only thing the row is trying to say: what the catalog offers, and what
// the gate then did about it.
func TestARowKeepsTheCatalogsOfferingApartFromWhatTheEntryResolvesTo(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		writeCatalog(w, profileDetailBody)
	})

	detail, err := client.Profile(t.Context(), "example/platform-engineer")
	require.NoError(t, err)
	require.Len(t, detail.Entries, 3)

	flagged := detail.Entries[1]
	require.Equal(t, "flagged", flagged.LatestVerdict, "the Scan badge is the catalog's verdict")
	require.Equal(t, "0.5.1", flagged.Version)
	require.Equal(t, "overridden", flagged.Outcome)
	require.True(t, flagged.Unpublished)
	require.NotNil(t, flagged.Override)
	require.Equal(t, "ewojcik@example.com", flagged.Override.Reviewer)

	// FR-036: an excluded entry is reported with its reason. It keeps its mode —
	// a pin the gate refused is still a pin — and resolves to nothing.
	excluded := detail.Entries[2]
	require.Equal(t, "pinned", excluded.Mode)
	require.Equal(t, "2.0.0", excluded.PinnedVersion)
	require.Empty(t, excluded.Version, "an excluded entry resolves to nothing, and says so")
	require.Empty(t, excluded.Verdict)
	require.NotNil(t, excluded.Skip)
	require.Equal(t, "version-rejected", excluded.Skip.Reason)
	require.Equal(t, "2.0.0", excluded.Skip.WouldHaveResolvedTo)
	require.Equal(t, "rejected", excluded.LatestVerdict,
		"the row still shows what the catalog holds, or the reader cannot see why it was excluded")
}

// resolve.Override models "does not lapse" as a nil pointer; the lockfile schema
// makes `expiresAt` required, so the two meet at the zero instant. A screen handed
// that would say an override that never expires expired in the year 1.
func TestAnOverrideThatDoesNotLapseIsNotOneThatExpiredInTheYearOne(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		writeCatalog(w, `{
		  "slug":"example/platform-engineer","name":"Platform Engineer","visibility":"private",
		  "defaultPolicy":"floating-latest","gate":"warn-with-override","headRevision":0,
		  "permissions":{"curate":true,"share":true,"publish":true},"unpublishedChanges":true,
		  "entries":[
		    {"id":"community/slack-digest","name":"Slack Digest","kind":"plugin","mode":"latest",
		     "version":"0.5.1","verdict":"flagged","outcome":"overridden","unpublished":false,
		     "override":{"reviewer":"ewojcik@example.com","note":"permanent",
		                 "expiresAt":"0001-01-01T00:00:00Z"}}
		  ],
		  "members":[],"targets":[],"revisions":[]
		}`)
	})

	detail, err := client.Profile(t.Context(), "example/platform-engineer")
	require.NoError(t, err)
	require.NotNil(t, detail.Entries[0].Override)
	require.Nil(t, detail.Entries[0].Override.ExpiresAt,
		"the zero instant is the absence of an expiry, and must not reach a screen as a date")
}

// The one defect the api half found reaches this side too: a profile slug carries
// several segments, and it must arrive as ONE escaped path segment or the api
// routes it as two and answers 404.
func TestAProfileSlugOfSeveralSegmentsIsSentAsOnePathSegment(t *testing.T) {
	const slug = "example/platform-engineer"

	for _, tc := range []struct {
		name string
		want string
		call func(*hub.Client) error
	}{
		{"reading it", "/v1/profiles/example%2Fplatform-engineer",
			func(c *hub.Client) error { _, err := c.Profile(t.Context(), slug); return err }},
		{"setting its entries", "/v1/profiles/example%2Fplatform-engineer/entries",
			func(c *hub.Client) error {
				_, err := c.SetProfileEntries(t.Context(), slug, nil)
				return err
			}},
		{"setting its sharing", "/v1/profiles/example%2Fplatform-engineer/sharing",
			func(c *hub.Client) error {
				_, err := c.SetProfileSharing(t.Context(), slug, []hub.Share{
					{Kind: "user", Ref: "kw@example.com", Role: "owner"},
				})
				return err
			}},
		{"setting its targets", "/v1/profiles/example%2Fplatform-engineer/targets",
			func(c *hub.Client) error {
				_, err := c.SetProfileTargets(t.Context(), slug, []string{"claude-code"})
				return err
			}},
		{"publishing a revision", "/v1/profiles/example%2Fplatform-engineer/revisions",
			func(c *hub.Client) error {
				_, err := c.PublishRevision(t.Context(), slug, "")
				return err
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				got = r.URL.EscapedPath()
				body := `{"schemaVersion":"1.0.0","revision":1,"gate":"warn-with-override",
				          "resolvedAt":"2026-08-31T10:00:00Z","entries":[],"skipped":[],
				          "targets":[],"profile":{"slug":"example/platform-engineer",
				          "name":"Platform Engineer"}}`
				if strings.HasSuffix(r.URL.Path, "/revisions") {
					writeCreated(w, body)
					return
				}
				writeCatalog(w, body)
			})

			require.NoError(t, tc.call(client))
			require.Equal(t, tc.want, got,
				"an unescaped slash makes this two path segments, which the api routes as no route at all")
		})
	}
}

// An empty slug is not a profile, and it is answered here rather than sent.
//
// GET /v1/profiles/ carries no slug: gin answers it with a 301 to /v1/profiles —
// measured against the api's own router — net/http follows it, and the client
// would decode the LIST of every readable profile into a ProfileDetail. Nothing
// about that body raises an error; the screen would get a blank profile and a nil.
func TestAnEmptySlugIsAnsweredAsNoProfileRatherThanBecomingTheWholeList(t *testing.T) {
	reached := false
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, "/v1/profiles", http.StatusMovedPermanently)
			return
		}
		writeCatalog(w, `{"profiles":[{"slug":"example/sre-oncall","name":"SRE On-call",
		                  "packageCount":9,"headRevision":14}]}`)
	})

	detail, err := client.Profile(t.Context(), "")
	require.ErrorIs(t, err, view.ErrNotFound)
	require.Empty(t, detail.Slug)
	require.False(t, reached, "the api was asked for a profile with no slug")

	_, err = client.PublishRevision(t.Context(), "", "note")
	require.ErrorIs(t, err, view.ErrNotFound)
	require.False(t, reached)
}

// FR-044: a profile this identity may not read answers exactly as one that does
// not exist, and this side must not try to tell them apart — on the mutating
// paths either, where anything else would confirm the slug is taken.
func TestAProfileThatIsMissingAndOneThisIdentityMayNotReadAreOneAnswer(t *testing.T) {
	for name, call := range profileCalls(t.Context()) {
		t.Run(name, func(t *testing.T) {
			client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			})
			// The sentinel itself and not something carrying it: this is a screen
			// rather than a failure, and it goes back the way Package and Finding
			// hand it back rather than under a sentence that reads like a fault.
			require.Equal(t, view.ErrNotFound, call(client))
		})
	}
}

// FR-126 again, on every profile path: a role refusal is a screen state with a
// reason and not a bad gateway, and it is not the signed-out state either —
// signing in again does not acquire a role.
func TestARoleRefusalOnAProfileIsNeitherSignedOutNorUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   error
	}{
		{"a role that may not curate", http.StatusForbidden, hub.ErrForbidden},
		{"no usable session", http.StatusUnauthorized, view.ErrSignedOut},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, call := range profileCalls(t.Context()) {
				t.Run(name, func(t *testing.T) {
					client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(tc.status)
					})
					require.ErrorIs(t, call(client), tc.want)
				})
			}
		})
	}
}

// A refusal the api explained is the one answer a screen must quote rather than
// reword. Every one of these sentences names the thing that was wrong, and this
// role does not enforce any of the rules that produced them.
func TestARefusalTheApiExplainedArrivesWithItsExplanation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		detail string
		call   func(*hub.Client) error
	}{
		{
			"a body that leaves out a package the profile holds", http.StatusUnprocessableEntity,
			"community/finops is held by this profile and the request leaves it out; " +
				"removal is not supported",
			func(c *hub.Client) error {
				_, err := c.SetProfileEntries(t.Context(), "example/platform-engineer",
					[]hub.EntrySetting{{ID: "example/adr-writer", Mode: "latest"}})
				return err
			},
		},
		{
			"a change that would leave no owner", http.StatusUnprocessableEntity,
			"this change would leave example/platform-engineer with no owner",
			func(c *hub.Client) error {
				_, err := c.SetProfileSharing(t.Context(), "example/platform-engineer",
					[]hub.Share{{Kind: "user", Ref: "kw@example.com", Role: "consumer"}})
				return err
			},
		},
		{
			"a slug somebody already took", http.StatusConflict,
			"a profile with the slug example/platform-engineer already exists",
			func(c *hub.Client) error {
				_, err := c.CreateProfile(t.Context(), hub.ProfileCreation{
					Slug: "example/platform-engineer", Name: "Platform Engineer",
				})
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(tc.status)
				writeCatalog(w, `{"title":"Unprocessable Entity","detail":`+strconv.Quote(tc.detail)+`}`)
			})

			err := tc.call(client)

			var refused *hub.ProfileRefusedError
			require.ErrorAs(t, err, &refused)
			require.Equal(t, tc.detail, refused.Detail)
			require.NotErrorIs(t, err, view.ErrNotFound)
			require.NotErrorIs(t, err, hub.ErrForbidden,
				"the caller was permitted; what they sent was refused, and the two need different screens")
		})
	}
}

// A refusal whose body this role cannot read is still a refusal, and it must say
// something bounded rather than echo an upstream string into a browser.
func TestARefusalWithNoReadableDetailStillSaysSomethingOfItsOwn(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte("<html>a proxy wrote this</html>"))
	})

	_, err := client.SetProfileTargets(t.Context(), "example/platform-engineer", []string{"codex"})

	var refused *hub.ProfileRefusedError
	require.ErrorAs(t, err, &refused)
	require.NotContains(t, refused.Detail, "<html>")
	require.Contains(t, refused.Detail, "Unprocessable Entity")
}

// The api being unreachable is the fourth state, and it is none of the other
// three: the caller renders it as a bad gateway, so it must not be mistaken for a
// refusal it could explain to somebody.
func TestAnApiThatIsDownIsNotARefusalNorASignedOutScreen(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	address := server.URL
	server.Close()

	client, err := hub.New(address)
	require.NoError(t, err)

	for name, call := range profileCalls(t.Context()) {
		t.Run(name, func(t *testing.T) {
			err := call(client)
			require.Error(t, err)
			require.NotErrorIs(t, err, view.ErrSignedOut)
			require.NotErrorIs(t, err, view.ErrNotFound)
			require.NotErrorIs(t, err, hub.ErrForbidden)

			var refused *hub.ProfileRefusedError
			require.NotErrorAs(t, err, &refused)
		})
	}
}

// Every optional half of the create form is omitted when it is empty, which is
// what makes the api's defaults apply: private, floating-latest. An empty string
// is not a polite way of saying nothing — it is outside all three enums and would
// be refused.
func TestTheUnfilledHalvesOfACreateFormAreOmittedRatherThanSentBlank(t *testing.T) {
	var bodies []string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		writeCreated(w, `{"slug":"example/new","name":"New","visibility":"private",
		                  "packageCount":0,"headRevision":0}`)
	})

	created, err := client.CreateProfile(t.Context(), hub.ProfileCreation{
		Slug: "example/new", Name: "New",
	})
	require.NoError(t, err)
	require.Equal(t, "private", created.Visibility)
	require.Equal(t, 0, created.HeadRevision)

	_, err = client.CreateProfile(t.Context(), hub.ProfileCreation{
		Slug: "example/fork", Name: "Fork", Visibility: "organisation",
		DefaultPolicy: "pinned", OwnerTeam: "example/platform", Description: "a fork",
		ForkOf: "example/sre-oncall",
	})
	require.NoError(t, err)

	require.Len(t, bodies, 2)
	for _, field := range []string{"visibility", "defaultPolicy", "ownerTeam", "description", "forkOf"} {
		require.NotContains(t, bodies[0], field,
			"an unset field must not be sent blank: the api's default is the one that applies")
	}
	require.Contains(t, bodies[1], `"visibility":"organisation"`)
	require.Contains(t, bodies[1], `"defaultPolicy":"pinned"`)
	require.Contains(t, bodies[1], `"forkOf":"example/sre-oncall"`)
}

// `latest` carries no version, and a mode that sent an empty one would be
// claiming a pin at "".
func TestAFloatingEntrySendsNoVersionAndAPinnedOneSendsIts(t *testing.T) {
	var body string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		writeCatalog(w, profileDetailBody)
	})

	_, err := client.SetProfileEntries(t.Context(), "example/platform-engineer", []hub.EntrySetting{
		{ID: "example/adr-writer", Mode: "pinned", Version: "3.0.2"},
		{ID: "community/slack-digest", Mode: "latest"},
		{ID: "community/finops", Mode: "range", Version: ">=1.4.0 <2.0.0"},
	})
	require.NoError(t, err)

	require.Contains(t, body, `{"id":"example/adr-writer","mode":"pinned","version":"3.0.2"}`)
	require.Contains(t, body, `{"id":"community/slack-digest","mode":"latest"}`)
	// encoding/json escapes the angle brackets on the way out and the api decodes
	// them straight back, so the constraint on the wire is the escaped form.
	require.Contains(t, body,
		`{"id":"community/finops","mode":"range","version":"\u003e=1.4.0 \u003c2.0.0"}`)
}

// An empty set is a legal choice on both of these paths and must travel as `[]`.
// A nil slice marshals to `null`, which is not an empty array to a validator: the
// request would come back malformed instead of answered.
func TestChoosingNothingIsSentAsAnEmptyListAndNotAsNull(t *testing.T) {
	var body string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		writeCatalog(w, profileDetailBody)
	})

	_, err := client.SetProfileTargets(t.Context(), "example/platform-engineer", nil)
	require.NoError(t, err)
	require.Contains(t, body, `"targets":[]`)
	require.NotContains(t, body, "null")

	_, err = client.SetProfileEntries(t.Context(), "example/platform-engineer", nil)
	require.NoError(t, err)
	require.Contains(t, body, `"entries":[]`)
	require.NotContains(t, body, "null")
}

// Sharing is an upsert of roles: the body names only the subjects being changed,
// and a group's name travels exactly as the identity provider spells it, because
// it is compared against the claim and a near miss grants nothing.
func TestSharingSendsOnlyTheSubjectsWhoseRoleIsChanging(t *testing.T) {
	var body string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		writeCatalog(w, profileDetailBody)
	})

	_, err := client.SetProfileSharing(t.Context(), "example/platform-engineer", []hub.Share{
		{Kind: "group", Ref: "eng-platform", Role: "maintainer"},
	})
	require.NoError(t, err)
	require.Equal(t, `{"members":[{"kind":"group","ref":"eng-platform","role":"maintainer"}]}`,
		strings.TrimSpace(body))
}

func TestPublishingReportsTheNumberTheServerChoseAndWhatItLeftOut(t *testing.T) {
	var body string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.Header().Set("Location", "/v1/profiles/example%2Fplatform-engineer/revisions/15")
		writeCreated(w, `{
		  "schemaVersion":"1.0.0",
		  "profile":{"slug":"example/platform-engineer","name":"Platform Engineer",
		             "visibility":"organisation"},
		  "revision":15,"note":"pinned ADR Writer to 3.0.2",
		  "resolvedAt":"2026-08-31T10:00:00Z","gate":"warn-with-override",
		  "defaultPolicy":"floating-latest",
		  "entries":[
		    {"id":"example/adr-writer","kind":"skill","version":"3.0.2",
		     "digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		     "objectKey":"bundles/example/adr-writer/3.0.2/bundle.tar.zst",
		     "resolution":"pinned","verdict":"clean"},
		    {"id":"community/slack-digest","kind":"plugin","version":"0.5.1",
		     "digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222",
		     "objectKey":"bundles/community/slack-digest/0.5.1/bundle.tar.zst",
		     "resolution":"latest","verdict":"flagged",
		     "override":{"reviewer":"ewojcik@example.com","note":"our own collector",
		                 "expiresAt":"2026-09-12T09:00:00Z"}}
		  ],
		  "skipped":[{"id":"community/finops","reason":"version-rejected",
		              "detail":"SH-FS-007 in scripts/collect.sh","wouldHaveResolvedTo":"2.0.0"}],
		  "targets":["claude-code"]
		}`)
	})

	published, err := client.PublishRevision(t.Context(), "example/platform-engineer",
		"pinned ADR Writer to 3.0.2")
	require.NoError(t, err)
	require.Contains(t, body, `"note":"pinned ADR Writer to 3.0.2"`)

	require.Equal(t, 15, published.Revision,
		"the number is the server's, and this is the only place a screen may learn which one it got")
	require.Equal(t, "warn-with-override", published.Gate)
	require.Equal(t, time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC), published.ResolvedAt.UTC())

	require.Len(t, published.Entries, 2)
	require.Equal(t, "3.0.2", published.Entries[0].Version)
	require.Equal(t, "pinned", published.Entries[0].Resolution)
	require.NotNil(t, published.Entries[1].Override)
	require.NotNil(t, published.Entries[1].Override.ExpiresAt)

	// FR-036: a revision that excluded a package says so. A publish confirmation
	// that dropped this would announce a clean publish of an incomplete profile.
	require.Len(t, published.Skipped, 1)
	require.Equal(t, "community/finops", published.Skipped[0].ID)
	require.Equal(t, "version-rejected", published.Skipped[0].Reason)
	require.Equal(t, "SH-FS-007 in scripts/collect.sh", published.Skipped[0].Detail)
}

// A publish with nothing to say sends no note rather than an empty one, so the
// history does not fill with blank captions.
func TestAPublishWithNoNoteSendsNoNoteField(t *testing.T) {
	var body string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		writeCreated(w, `{"schemaVersion":"1.0.0","revision":1,"gate":"block",
		                  "resolvedAt":"2026-08-31T10:00:00Z","entries":[],"skipped":[],
		                  "targets":[],"profile":{"slug":"example/new","name":"New"}}`)
	})

	published, err := client.PublishRevision(t.Context(), "example/new", "")
	require.NoError(t, err)
	require.Equal(t, `{}`, strings.TrimSpace(body))
	require.Empty(t, published.Note)
	require.Empty(t, published.Skipped)
}

// writeCreated answers a 201 with a JSON body. The content type has to be set
// BEFORE the status line or net/http sniffs one, and the generated client decodes
// a 201 only when it is told the body is JSON.
func writeCreated(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	writeCatalog(w, body)
}

// profileCalls is every profile method, so the error-path tests cover the whole
// door rather than the one method whose branch somebody remembered to write.
func profileCalls(ctx context.Context) map[string]func(*hub.Client) error {
	const slug = "example/platform-engineer"
	return map[string]func(*hub.Client) error{
		"reading it": func(c *hub.Client) error {
			_, err := c.Profile(ctx, slug)
			return err
		},
		"creating one": func(c *hub.Client) error {
			_, err := c.CreateProfile(ctx, hub.ProfileCreation{Slug: slug, Name: "Platform Engineer"})
			return err
		},
		"setting its entries": func(c *hub.Client) error {
			_, err := c.SetProfileEntries(ctx, slug, []hub.EntrySetting{{ID: "a/b", Mode: "latest"}})
			return err
		},
		"setting its sharing": func(c *hub.Client) error {
			_, err := c.SetProfileSharing(ctx, slug, []hub.Share{{Kind: "user", Ref: "a", Role: "owner"}})
			return err
		},
		"setting its targets": func(c *hub.Client) error {
			_, err := c.SetProfileTargets(ctx, slug, []string{"claude-code"})
			return err
		},
		"publishing a revision": func(c *hub.Client) error {
			_, err := c.PublishRevision(ctx, slug, "note")
			return err
		},
	}
}
