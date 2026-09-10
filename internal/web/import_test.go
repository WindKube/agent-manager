package web_test

import (
	"bytes"
	"context"
	"html"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/components"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/view"
)

// registrar is a web.Registrar stand-in that records what it was asked to
// register, so a test can assert what the form actually sent rather than only
// that the request succeeded.
type registrar struct {
	got view.Registration
	// refusal makes Register answer the way the api answers a conflict: a result
	// that is not Registered, carrying the problem detail.
	refusal string
}

func (r *registrar) Preview(context.Context, view.Archive) (view.ImportPreview, error) {
	return view.ImportPreview{}, nil
}

func (r *registrar) Register(_ context.Context, registration view.Registration) (view.ImportResult, error) {
	r.got = registration
	if r.refusal != "" {
		return view.ImportResult{Message: r.refusal}, nil
	}
	return view.ImportResult{Registered: true, ID: "example/thing", Version: registration.Version}, nil
}

// postMultipart submits the import form the way a browser does: multipart, not
// urlencoded, which is what the archive field requires.
func postMultipart(t *testing.T, h http.Handler, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for name, value := range fields {
		require.NoError(t, form.WriteField(name, value))
	}
	require.NoError(t, form.Close())

	req := httptest.NewRequest(http.MethodPost, "/catalog/import", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "am_session", Value: "screen-test-session"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The registration modal (T046). What can regress silently is the markup the R7
// budget and FR-055 depend on, which is what this asserts.

func TestTheImportModalIsOnTheCatalogAndCostsNoRoundTrip(t *testing.T) {
	body := get(t, handler(t, fixture.New()), "/catalog").Body.String()

	t.Run("both header buttons open it, each on the tab the design names", func(t *testing.T) {
		require.Contains(t, body, `data-on:click="$_importOpen = true; $_importTab = 'upload'"`)
		require.Contains(t, body, `data-on:click="$_importOpen = true; $_importTab = 'url'"`)
	})

	t.Run("every signal it touches is one datastar never sends", func(t *testing.T) {
		// The underscore prefix is what keeps opening the modal, switching tabs and
		// attaching a file off the wire. Drop it and each of those becomes a round
		// trip, with nothing else looking different.
		for _, signal := range []string{
			"_importOpen", "_importTab", "_importFile",
			"_importURL", "_importRef", "_importSubdir", "_importPublisher", "_importVersion",
		} {
			require.Containsf(t, body, `&#34;`+signal+`&#34;`, "%s is missing from the initial signal state", signal)
			require.NotContainsf(t, body, `&#34;`+strings.TrimPrefix(signal, "_")+`&#34;:`,
				"%s appears without its underscore, which would send it on every patch", signal)
		}

		// And the debounced listener's include filter still names none of them, so
		// there are two independent reasons this markup cannot fetch. The filter is
		// read out of the page rather than compared to a literal, so a signal added
		// to it later is caught here.
		const filterAttr = `data-on-signal-patch-filter="`
		start := strings.Index(body, filterAttr)
		require.GreaterOrEqual(t, start, 0, "the debounced listener's include filter is gone")
		filter := body[start+len(filterAttr):]
		filter = filter[:strings.IndexByte(filter, '"')]
		require.NotContains(t, filter, "_import", "the include filter must not name a modal signal")
		require.Equal(t, "{include: /^(q|kind|status|cats|tags|sort|dir|page)$/}", filter)
	})

	t.Run("its fetch sites are all deliberate acts, never signal-driven", func(t *testing.T) {
		// The modal submits now, so the claim is no longer "it cannot fetch" — it is
		// that nothing it fetches is reachable from a signal patch. One debounced
		// site on the page, and every @post here hangs off a click or a file being
		// attached.
		require.Equal(t, 1, strings.Count(body, "/catalog/results"))

		for _, site := range []string{"/catalog/import/preview", "/catalog/import"} {
			at := strings.Index(body, "@post(&#39;"+site+"&#39;")
			require.GreaterOrEqualf(t, at, 0, "%s is not posted to", site)
			// The nearest preceding data-on: attribute is the one that fires it. An
			// attribute name is the claim being tested, so it is read out of the
			// markup rather than assumed from where the templ source puts it.
			handler := body[strings.LastIndex(body[:at], "data-on:"):]
			handler = handler[:strings.IndexByte(handler, '=')]
			require.Containsf(t, []string{"data-on:click", "data-on:change", "data-on:submit"}, handler,
				"%s is posted from %s, which is not a deliberate act", site, handler)
		}

		// And the browser still never addresses the api: the web role is the hop.
		require.NotContains(t, body, "/v1/packages")
	})

	t.Run("the overlay is hidden before the script runs", func(t *testing.T) {
		// A visible full-viewport backdrop would swallow every click on the catalog
		// underneath it.
		require.Contains(t, body, `class="am-import-backdrop" style="display:none;`)
	})

	t.Run("the curated category vocabulary is on the first render", func(t *testing.T) {
		require.Contains(t, body, `<select id="import-category"`)
		for _, name := range []string{"Infrastructure", "Data", "Documentation"} {
			require.Containsf(t, body, `<option value="`+name+`">`+name+`</option>`, "category %q", name)
		}
		// FR-049: only the curated names, and no way to add one from here.
		require.NotContains(t, body, `id="import-category-new"`)
	})

	t.Run("the tab row is a chip row and not an option list", func(t *testing.T) {
		require.Contains(t, body, `Upload archive`)
		require.Contains(t, body, `Fetch from URL`)
		require.NotContains(t, body, `class="am-opt"`)
	})
}

// FR-055 is the one that a screenshot cannot catch. Every string in the panel
// comes from a manifest — a path, a note, a schema path — and templ escaping is
// what stands between that and stored XSS. internal/archcheck bans templ.Raw
// under internal/web; this proves the escaping actually happens.
func TestManifestDerivedStringsInTheImportPanelAreEscaped(t *testing.T) {
	hostile := `<img src=x onerror="alert(1)">`

	var out bytes.Buffer
	require.NoError(t, components.ImportModal(components.Import{
		Categories: []string{hostile},
		Preview: &view.ImportPreview{
			Valid:   false,
			Kind:    view.KindPlugin,
			Name:    hostile,
			Version: `"><script>alert(2)</script>`,
			Entries: []view.ImportEntry{
				{Path: hostile, Note: hostile, Kept: true, Mark: "kept"},
				{Path: ".github/, README.md", Note: "outside spec, dropped", Mark: "dropped"},
				{Path: "plugin.json", Note: "schema invalid", Mark: "invalid"},
			},
			Problems: []view.ImportProblem{
				{Manifest: "plugin.json", SchemaPath: "/additionalProperties", Message: hostile},
			},
		},
	}).Render(context.Background(), &out))

	rendered := out.String()
	require.NotContains(t, rendered, "<img src=x")
	require.NotContains(t, rendered, "<script>")
	require.NotContains(t, rendered, `onerror="alert(1)"`)
	require.Contains(t, rendered, "&lt;img src=x")

	// The panel still says what it has to say (FR-005, US1 scenario 3).
	require.Contains(t, rendered, "outside spec, dropped")
	require.Contains(t, rendered, "plugin.json /additionalProperties")
	require.Contains(t, rendered, "✓")
	require.Contains(t, rendered, "–")
	require.Contains(t, rendered, "✕")
}

func TestTheEntryMarkAndItsColourCannotDisagree(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry view.ImportEntry
		glyph string
		tone  string
	}{
		{"a kept file", view.ImportEntry{Kept: true, Mark: "kept"}, "✓", "ok"},
		{"a dropped path", view.ImportEntry{Mark: "dropped"}, "–", "fg3"},
		{"the manifest that failed", view.ImportEntry{Mark: "invalid"}, "✕", "dan"},
		{"a manifest that failed is never green even if it was kept",
			view.ImportEntry{Kept: true, Mark: "invalid"}, "✕", "dan"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.glyph, tc.entry.Glyph())
			require.Equal(t, tc.tone, tc.entry.Tone())
			require.Contains(t, components.ImportMarkStyle(tc.entry), "var(--"+tc.tone+")")
		})
	}
}

func TestTheImportFormHasAVersionFieldAndAUsablePublisherPlaceholder(t *testing.T) {
	body := get(t, handler(t, fixture.New()), "/catalog").Body.String()

	require.Contains(t, body, `id="import-version"`)
	require.Contains(t, body, `name="version"`)
	require.Contains(t, body, `placeholder="1.0.0"`)
	// A bare namespace is a legal publisher too, but the placeholder models the
	// more common two-segment shape.
	require.Contains(t, body, `placeholder="example/platform"`)
}

// TestUploadingASkillCanBeRegisteredNowThatVersionIsOnTheForm is GAP 2: a
// SKILL.md manifest carries no version, so the api refuses the upload unless
// the form supplies one.
func TestUploadingASkillCanBeRegisteredNowThatVersionIsOnTheForm(t *testing.T) {
	reg := &registrar{}
	h := web.New(web.Deps{
		Registrar: reg, Viewers: fixture.SignedInViewers(), Log: zerolog.Nop(),
	}, web.Options{}).Handler()

	rec := postMultipart(t, h, map[string]string{
		"publisher": "example/platform",
		"name":      "release-notes",
		"version":   "1.0.0",
		"category":  "Documentation",
	})

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "1.0.0", reg.got.Version)
	require.Contains(t, rec.Body.String(), "1.0.0")
}

func TestTheCatalogStillRendersWithoutAPreview(t *testing.T) {
	// The resting state: no archive has been validated, so FR-005's panel is ABSENT
	// rather than blank. An empty panel would be a report about no tree at all.
	body := get(t, handler(t, fixture.New()), "/catalog").Body.String()
	require.Equal(t, http.StatusOK, get(t, handler(t, fixture.New()), "/catalog").Code)
	require.NotContains(t, body, "Archive contents")
}

// registerHandler is the modal's own handler, wired to a registrar a test can
// steer. handler(t, fixture.New()) cannot register at all.
func registerHandler(t *testing.T, reg *registrar) http.Handler {
	t.Helper()
	return web.New(web.Deps{
		Registrar: reg, Viewers: fixture.SignedInViewers(), Log: zerolog.Nop(),
	}, web.Options{}).Handler()
}

// An accepted registration is finished, and the modal has to go. Leaving it open
// with an acknowledgement in it is what let the same version be submitted twice:
// the second attempt reached a unique index on (package_id, semver) and the
// button read as doing nothing.
func TestAnAcceptedRegistrationClosesTheModalAndSaysSoOnTheScreen(t *testing.T) {
	reg := &registrar{}
	rec := postMultipart(t, registerHandler(t, reg), map[string]string{
		"publisher": "example/platform",
		"name":      "release-notes",
		"version":   "1.0.0",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	require.Contains(t, body, `"_importOpen":false`,
		"the modal stayed open, so the same version can be registered again from it")

	// Resetting matters as much as closing: a modal reopened still holding the
	// last registration's fields is the same defect one press later.
	for _, signal := range []string{
		"_importFile", "_importURL", "_importRef", "_importSubdir",
		"_importPublisher", "_importName", "_importVersion", "_importKind",
	} {
		require.Containsf(t, body, `"`+signal+`":""`, "%s survived a registration", signal)
	}

	t.Run("and the outcome moves to the screen behind it", func(t *testing.T) {
		require.Contains(t, body, `id="catalog-notice"`)
		require.Contains(t, body, "Registered example/thing@1.0.0")
		require.Contains(t, body, "The fetch is queued")
		require.NotContains(t, body, `id="import-result"`,
			"the banner belongs to a modal that is no longer on screen")
	})
}

// The other half: a refusal must NOT close the modal. The fields are still
// wanted, because the person is about to correct one of them.
func TestARefusedRegistrationKeepsTheModalOpenWithTheReason(t *testing.T) {
	reg := &registrar{refusal: "example/thing@1.0.0 is already published and its bytes are immutable"}
	rec := postMultipart(t, registerHandler(t, reg), map[string]string{
		"publisher": "example/platform",
		"name":      "release-notes",
		"version":   "1.0.0",
	})
	body := rec.Body.String()

	require.Contains(t, body, `id="import-result"`)
	require.Contains(t, body, "already published")
	require.NotContains(t, body, "_importOpen", "a refusal closed the modal and took the reason with it")
	require.NotContains(t, body, `id="catalog-notice"`)
}

// Closing the modal is not enough on its own: the button is live for as long as
// the request takes, which is the window the double submit actually happened in.
func TestTheSubmitControlIsDeadWhileItsOwnRequestIsInFlight(t *testing.T) {
	body := get(t, handler(t, fixture.New()), "/catalog").Body.String()

	require.Contains(t, body, `data-indicator="_importBusy"`,
		"nothing reports that the registration is in flight")
	require.Regexp(t, `data-attr:disabled="\$_importBusy \|\|`, body,
		"the submit control does not consult the in-flight signal, so it stays pressable")

	// The signal is underscore-prefixed, which is what keeps it out of every
	// request this modal makes. The signal block is an HTML attribute, so it
	// arrives escaped.
	require.Contains(t, html.UnescapeString(body), `"_importBusy":false`,
		"the in-flight signal has no declared value, so the disabled expression reads it before the plugin sets it")
}

func TestTheFormAsksForANameAndAKindAndForwardsBoth(t *testing.T) {
	body := get(t, handler(t, fixture.New()), "/catalog").Body.String()

	// A repository name is what the api falls back to, and for a repository of
	// many skills that produced "skills".
	require.Contains(t, body, `id="import-name"`)
	require.Contains(t, body, `name="name"`)

	require.Contains(t, body, `id="import-kind"`)
	require.Contains(t, body, `<option value="plugin">Plugin</option>`)
	require.Contains(t, body, `<option value="skill">Skill</option>`)
	require.Contains(t, body, "Detect from the manifest",
		"kind comes from the manifest at the tree root; a selector with no such default would present a guess as a setting")

	reg := &registrar{}
	postMultipart(t, registerHandler(t, reg), map[string]string{
		"publisher": "example/platform",
		"name":      "code-review",
		"version":   "1.2.3",
		"kind":      "skill",
	})
	require.Equal(t, "code-review", reg.got.Name)
	require.Equal(t, "skill", reg.got.Kind)
}
