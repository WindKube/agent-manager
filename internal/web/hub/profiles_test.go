package hub_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// Assertions are on the wire (escaped path, body bytes, raw JSON) so a mapping bug
// cannot cancel out against the same bug in the test.

// The design's example/platform-engineer: a clean floating entry, a flagged one let
// through on an override, and a pin the gate refused.
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

	// Booleans so a screen disables a control rather than offering a refused one.
	require.True(t, detail.Permissions.Curate)
	require.False(t, detail.Permissions.Share)
	require.True(t, detail.Permissions.Publish)

	require.Len(t, detail.Members, 2)
	require.Equal(t, "group", detail.Members[1].Kind,
		"a group is matched against the claim, never expanded into people, so the kind travels")
	require.Empty(t, detail.Members[1].DisplayName,
		"a membership may name somebody this hub has never seen sign in")

	require.Equal(t, []view.ProfileTargetRow{
		{Target: "claude-code", Enabled: true},
		{Target: "codex", Enabled: false},
	}, detail.Targets, "the whole vocabulary arrives, so the screen holds no copy of the enum")

	require.Len(t, detail.Revisions, 2)
	require.Equal(t, 14, detail.Revisions[0].Revision)
	require.Equal(t, "2026-08-27 14:02 UTC", detail.Revisions[0].PublishedAt)
	require.Empty(t, detail.Revisions[1].Note)
}

// The two version pairs answer different questions: what the catalog offers, and
// what the gate did about it.
func TestARowKeepsTheCatalogsOfferingApartFromWhatTheEntryResolvesTo(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		writeCatalog(w, profileDetailBody)
	})

	detail, err := client.Profile(t.Context(), "example/platform-engineer")
	require.NoError(t, err)
	require.Len(t, detail.Entries, 3)

	flagged := detail.Entries[1]
	require.Equal(t, view.VerdictFlagged, flagged.LatestVerdict, "the Scan badge is the catalog's verdict")
	require.Equal(t, "0.5.1", flagged.Version)
	require.Equal(t, view.OutcomeOverridden, flagged.Outcome)
	require.True(t, flagged.Unpublished)
	require.NotNil(t, flagged.Override)
	require.Equal(t, "ewojcik@example.com", flagged.Override.Reviewer)

	// An excluded entry keeps its mode and reason and resolves to nothing.
	excluded := detail.Entries[2]
	require.Equal(t, "pinned", excluded.Mode)
	require.Equal(t, "2.0.0", excluded.PinnedVersion)
	require.Empty(t, excluded.Version, "an excluded entry resolves to nothing, and says so")
	require.Empty(t, excluded.Verdict)
	require.NotNil(t, excluded.Skip)
	require.Equal(t, "version-rejected", excluded.Skip.Reason)
	require.Equal(t, "2.0.0", excluded.Skip.WouldHaveResolvedTo)
	require.Equal(t, view.VerdictRejected, excluded.LatestVerdict,
		"the row still shows what the catalog holds, or the reader cannot see why it was excluded")
}

// resolve.Override's "does not lapse" is the zero instant in the lockfile schema;
// a screen must not say it expired in year 1.
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
	require.Empty(t, detail.Entries[0].Override.Expires,
		"the zero instant is the absence of an expiry, and must not reach a screen as a date")
}

// A multi-segment slug must arrive as one escaped path segment, or the api routes
// it as two and answers 404.
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
			func(c *hub.Client) error { return c.PublishRevision(t.Context(), slug, "") }},
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

// An empty slug is refused here: GET /v1/profiles/ gets a 301 to the list, which
// net/http follows and decodes into a blank ProfileDetail without error.
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

	err = client.PublishRevision(t.Context(), "", "note")
	require.ErrorIs(t, err, view.ErrNotFound)
	require.False(t, reached)
}

// A missing and an unreadable profile are one answer, on mutating paths too,
// where anything else would confirm the slug is taken.
func TestAProfileThatIsMissingAndOneThisIdentityMayNotReadAreOneAnswer(t *testing.T) {
	for name, call := range profileCalls(t.Context()) {
		t.Run(name, func(t *testing.T) {
			client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			})
			// The bare sentinel: a screen state, not a wrapped fault.
			require.Equal(t, view.ErrNotFound, call(client))
		})
	}
}

// A role refusal on every profile path is neither signed out nor a bad gateway.
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

// An explained refusal must reach the screen verbatim; this role enforces none of
// the rules behind it.
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

// An unreadable refusal body still yields a bounded sentence, never the upstream string.
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

// An unreachable api must not be mistaken for a refusal it could explain.
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

// Empty optional create fields are omitted so the api's defaults apply; an empty
// string is outside every enum and would be refused.
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

// `latest` carries no version; an empty one would claim a pin at "".
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
	// encoding/json escapes angle brackets, so the wire carries the escaped form.
	require.Contains(t, body,
		`{"id":"community/finops","mode":"range","version":"\u003e=1.4.0 \u003c2.0.0"}`)
}

// An empty set must travel as `[]`; `null` would be rejected as malformed.
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

// Sharing upserts only the named subjects, and a group name travels exactly as the
// identity provider spells it, since a near miss grants nothing.
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

func TestPublishingPostsTheNoteAndTakesA201AsSuccess(t *testing.T) {
	var method, path, body string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		method, path, body = r.Method, r.URL.EscapedPath(), string(raw)
		writeCreated(w, `{"schemaVersion":"1.0.0","revision":15,"gate":"warn-with-override",
		                  "resolvedAt":"2026-08-31T10:00:00Z","entries":[],"skipped":[],
		                  "targets":[],"profile":{"slug":"example/platform-engineer",
		                  "name":"Platform Engineer"}}`)
	})

	err := client.PublishRevision(t.Context(), "example/platform-engineer", "pinned ADR Writer to 3.0.2")
	require.NoError(t, err)
	require.Equal(t, http.MethodPost, method)
	require.Equal(t, "/v1/profiles/example%2Fplatform-engineer/revisions", path)
	require.Contains(t, body, `"note":"pinned ADR Writer to 3.0.2"`)
}

// A publish with no note sends none, so history has no blank captions.
func TestAPublishWithNoNoteSendsNoNoteField(t *testing.T) {
	var body string
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		writeCreated(w, `{"schemaVersion":"1.0.0","revision":1,"gate":"block",
		                  "resolvedAt":"2026-08-31T10:00:00Z","entries":[],"skipped":[],
		                  "targets":[],"profile":{"slug":"example/new","name":"New"}}`)
	})

	require.NoError(t, client.PublishRevision(t.Context(), "example/new", ""))
	require.Equal(t, `{}`, strings.TrimSpace(body))
}

// writeCreated sets the content type before the status line, or net/http sniffs
// one and the generated client won't decode the 201 as JSON.
func writeCreated(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	writeCatalog(w, body)
}

// profileCalls is every profile method, so error-path tests cover all of them.
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
			return c.PublishRevision(ctx, slug, "note")
		},
	}
}
