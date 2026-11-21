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

	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/components"
	"agent-manager/internal/web/fakeapi"
	"agent-manager/internal/web/view"
)

// registerServer answers every registration as accepted: example/thing at
// whatever version the form sent.
func registerServer(t *testing.T) (*fakeapi.API, http.Handler) {
	t.Helper()
	api, h := newServer(t)
	api.Handle("registerPackage", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseMultipartForm(1<<20))
		fakeapi.JSON(w, http.StatusAccepted, apiclient.PackageRegistered{
			Publisher: "example/platform", Name: "thing", Version: r.FormValue("version"),
		})
	})
	return api, h
}

func registered(t *testing.T, api *fakeapi.API) *multipart.Form {
	t.Helper()
	calls := api.Calls("registerPackage")
	require.Len(t, calls, 1)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(calls[0].Body))
	req.Header = calls[0].Header
	require.NoError(t, req.ParseMultipartForm(1<<20))
	return req.MultipartForm
}

// postMultipart submits the import form as multipart, which the archive field requires.
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

func TestTheImportModalIsOnTheCatalogAndCostsNoRoundTrip(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/catalog").Body.String()

	t.Run("both header buttons open it, each on the tab the design names", func(t *testing.T) {
		require.Contains(t, body, `data-on:click="$_importOpen = true; $_importTab = 'upload'"`)
		require.Contains(t, body, `data-on:click="$_importOpen = true; $_importTab = 'url'"`)
	})

	t.Run("every signal it touches is one datastar never sends", func(t *testing.T) {
		// The underscore prefix keeps these off the wire; without it each modal
		// interaction becomes a silent round trip.
		for _, signal := range []string{
			"_importOpen", "_importTab", "_importFile",
			"_importURL", "_importRef", "_importSubdir", "_importPublisher", "_importVersion", "_importTags",
		} {
			require.Containsf(t, body, `&#34;`+signal+`&#34;`, "%s is missing from the initial signal state", signal)
			require.NotContainsf(t, body, `&#34;`+strings.TrimPrefix(signal, "_")+`&#34;:`,
				"%s appears without its underscore, which would send it on every patch", signal)
		}

		// The debounced listener's include filter must name none of them either.
		// It is read out of the page so a later addition is caught.
		const filterAttr = `data-on-signal-patch-filter="`
		start := strings.Index(body, filterAttr)
		require.GreaterOrEqual(t, start, 0, "the debounced listener's include filter is gone")
		filter := body[start+len(filterAttr):]
		filter = filter[:strings.IndexByte(filter, '"')]
		require.NotContains(t, filter, "_import", "the include filter must not name a modal signal")
		require.Equal(t, "{include: /^(q|kind|status|cats|tags|sort|dir|page)$/}", filter)
	})

	t.Run("its fetch sites are all deliberate acts, never signal-driven", func(t *testing.T) {
		// Nothing it fetches is reachable from a signal patch: two catalog query
		// sites, and every @post hangs off a click, change or submit.
		require.Equal(t, 2, strings.Count(body, "/catalog/results"))

		for _, site := range []string{"/catalog/import/preview", "/catalog/import"} {
			at := strings.Index(body, "@post(&#39;"+site+"&#39;")
			require.GreaterOrEqualf(t, at, 0, "%s is not posted to", site)
			// The nearest preceding data-on: attribute is the one that fires it.
			handler := body[strings.LastIndex(body[:at], "data-on:"):]
			handler = handler[:strings.IndexByte(handler, '=')]
			require.Containsf(t, []string{"data-on:click", "data-on:change", "data-on:submit"}, handler,
				"%s is posted from %s, which is not a deliberate act", site, handler)
		}

		// The browser never addresses the api directly.
		require.NotContains(t, body, "/v1/packages")
	})

	t.Run("the overlay is hidden before the script runs", func(t *testing.T) {
		// A visible full-viewport backdrop would swallow every click underneath.
		require.Contains(t, body, `class="am-import-backdrop" style="display:none;`)
	})

	t.Run("the curated category vocabulary is on the first render", func(t *testing.T) {
		require.Contains(t, body, `<select id="import-category"`)
		for _, name := range []string{"Infrastructure", "Data", "Documentation"} {
			require.Containsf(t, body, `<option value="`+name+`">`+name+`</option>`, "category %q", name)
		}
		// Only the curated names, with no way to add one from here.
		require.NotContains(t, body, `id="import-category-new"`)
	})

	t.Run("the tab row is a chip row and not an option list", func(t *testing.T) {
		require.Contains(t, body, `Upload archive`)
		require.Contains(t, body, `Fetch from URL`)
		require.NotContains(t, body, `class="am-opt"`)
	})
}

// Every panel string comes from a manifest, and templ escaping is what stands
// between that and stored XSS. archcheck bans templ.Raw; this proves escaping happens.
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
	_, h := newServer(t)
	body := get(t, h, "/catalog").Body.String()

	require.Contains(t, body, `id="import-version"`)
	require.Contains(t, body, `name="version"`)
	require.Contains(t, body, `placeholder="1.0.0"`)
	require.Contains(t, body, `placeholder="example/platform"`)
}

// A SKILL.md manifest carries no version, so the api refuses an upload unless the
// form supplies one.
func TestUploadingASkillCanBeRegisteredNowThatVersionIsOnTheForm(t *testing.T) {
	api, h := registerServer(t)

	rec := postMultipart(t, h, map[string]string{
		"publisher": "example/platform",
		"name":      "release-notes",
		"version":   "1.0.0",
		"category":  "Documentation",
	})

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, []string{"1.0.0"}, registered(t, api).Value["version"])
	require.Contains(t, rec.Body.String(), "1.0.0")
}

func TestTheCatalogStillRendersWithoutAPreview(t *testing.T) {
	// No archive validated yet, so the panel is absent rather than blank.
	_, h := newServer(t)
	rec := get(t, h, "/catalog")
	body := rec.Body.String()
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, body, "Archive contents")
}

// An open modal after acceptance let the same version be submitted twice, hitting
// the unique (package_id, semver) index.
func TestAnAcceptedRegistrationClosesTheModalAndSaysSoOnTheScreen(t *testing.T) {
	_, h := registerServer(t)
	rec := postMultipart(t, h, map[string]string{
		"publisher": "example/platform",
		"name":      "release-notes",
		"version":   "1.0.0",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	require.Contains(t, body, `"_importOpen":false`,
		"the modal stayed open, so the same version can be registered again from it")

	// A reopened modal holding the last fields is the same defect one press later.
	for _, signal := range []string{
		"_importFile", "_importURL", "_importRef", "_importSubdir",
		"_importPublisher", "_importName", "_importVersion", "_importKind", "_importTags",
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

// A refusal keeps the modal open: the person is about to correct a field.
func TestARefusedRegistrationKeepsTheModalOpenWithTheReason(t *testing.T) {
	api, h := newServer(t)
	api.Fail("registerPackage", http.StatusConflict,
		"example/thing@1.0.0 is already published and its bytes are immutable")
	rec := postMultipart(t, h, map[string]string{
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

// Closing the modal is not enough: the button is live while the request is in flight.
func TestTheSubmitControlIsDeadWhileItsOwnRequestIsInFlight(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/catalog").Body.String()

	require.Contains(t, body, `data-indicator="_importBusy"`,
		"nothing reports that the registration is in flight")
	require.Regexp(t, `data-attr:disabled="\$_importBusy \|\|`, body,
		"the submit control does not consult the in-flight signal, so it stays pressable")

	// The signal block is an HTML attribute, so it arrives escaped.
	require.Contains(t, html.UnescapeString(body), `"_importBusy":false`,
		"the in-flight signal has no declared value, so the disabled expression reads it before the plugin sets it")
}

func TestTheFormAsksForANameAndAKindAndForwardsBoth(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/catalog").Body.String()

	// Without a name the api falls back to the repository name, e.g. "skills".
	require.Contains(t, body, `id="import-name"`)
	require.Contains(t, body, `name="name"`)

	require.Contains(t, body, `id="import-kind"`)
	require.Contains(t, body, `<option value="plugin">Plugin</option>`)
	require.Contains(t, body, `<option value="skill">Skill</option>`)
	require.Contains(t, body, "Detect from the manifest",
		"kind comes from the manifest at the tree root; a selector with no such default would present a guess as a setting")

	api, reg := registerServer(t)
	postMultipart(t, reg, map[string]string{
		"publisher": "example/platform",
		"name":      "code-review",
		"version":   "1.2.3",
		"kind":      "skill",
	})
	form := registered(t, api)
	require.Equal(t, []string{"code-review"}, form.Value["name"])
	require.Equal(t, []string{"skill"}, form.Value["kind"])
}

// Tags forward unparsed: splitting, deduping and validating is the api's job.
func TestTheFormAsksForTagsOnBothTabsAndForwardsThemUnparsed(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/catalog").Body.String()

	require.Contains(t, body, `id="import-tags"`)
	require.Contains(t, body, `name="tags"`)
	require.Contains(t, body, `placeholder="terraform, aws, guardrails"`)

	api, reg := registerServer(t)
	postMultipart(t, reg, map[string]string{
		"publisher": "example/platform",
		"name":      "code-review",
		"version":   "1.2.3",
		"tags":      " terraform, aws ,,terraform",
	})
	require.Equal(t, []string{" terraform, aws ,,terraform"}, registered(t, api).Value["tags"],
		"the web role forwards the raw field; the api is what splits, dedupes and validates it")
}

func TestTheFormWorksWithNoTags(t *testing.T) {
	api, h := registerServer(t)
	rec := postMultipart(t, h, map[string]string{
		"publisher": "example/platform",
		"name":      "release-notes",
		"version":   "1.0.0",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, registered(t, api).Value, "tags")
}

func TestTheImportModalHasNoExplanatoryBannerOrFooterNote(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/catalog").Body.String()

	require.NotContains(t, body, "The hub unpacks the tree",
		"the registration modal's explanatory panel is still on the page")
	require.NotContains(t, body, "Scanner verdict usually lands",
		"the modal's footer note is still on the page")

	require.Contains(t, body, ">Cancel<", "removing the footer note must not take the Cancel button with it")
	require.Contains(t, body, ">Validate and scan<",
		"removing the footer note must not take the submit button with it")
}
