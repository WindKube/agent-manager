package web_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/view"
)

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
			"_importURL", "_importRef", "_importSubdir", "_importPublisher",
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

func TestTheCatalogStillRendersWithoutAPreview(t *testing.T) {
	// The resting state: no archive has been validated, so FR-005's panel is ABSENT
	// rather than blank. An empty panel would be a report about no tree at all.
	body := get(t, handler(t, fixture.New()), "/catalog").Body.String()
	require.Equal(t, http.StatusOK, get(t, handler(t, fixture.New()), "/catalog").Code)
	require.NotContains(t, body, "Archive contents")
}
