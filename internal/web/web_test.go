package web_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/view"
)

func handler(t *testing.T, source web.CatalogSource) http.Handler {
	t.Helper()
	return web.New(web.Deps{Catalog: source, Log: zerolog.Nop()}, web.Options{}).Handler()
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, http.NoBody))
	return rec
}

func TestShell(t *testing.T) {
	h := handler(t, fixture.New())

	t.Run("the catalog renders every sidebar group and badge", func(t *testing.T) {
		body := get(t, h, "/catalog").Body.String()
		for _, want := range []string{
			"Workspace", "Security", "Administration", "Onboarding",
			"Catalog", "Profiles", "Scanner", "Audit log", "Storage", "Organization",
			"Connect the CLI", "am-nav-badge-alert", "Krzysztof W.", "Platform · Admin",
		} {
			require.Containsf(t, body, want, "sidebar is missing %q", want)
		}
	})

	t.Run("no page references an external host", func(t *testing.T) {
		// The image is distroless and the quickstart must work offline: a CDN
		// reference would work on the author's machine and nowhere else.
		for _, path := range []string{"/catalog", "/scanner", "/profiles", "/storage", "/audit", "/cli", "/org"} {
			body := get(t, h, path).Body.String()
			for _, forbidden := range []string{"//fonts.googleapis.com", "//fonts.gstatic.com", "//cdn.", "//unpkg.com", "//esm.sh", "//jsdelivr"} {
				require.NotContainsf(t, body, forbidden, "%s references %s", path, forbidden)
			}
		}
	})

	t.Run("the sidebar routes are all navigable rather than 404", func(t *testing.T) {
		for _, path := range []string{"/", "/catalog", "/profiles", "/profiles/platform-engineer",
			"/scanner", "/audit", "/storage", "/org", "/cli", "/packages/tf-review"} {
			require.Equalf(t, http.StatusOK, get(t, h, path).Code, "%s is not reachable", path)
		}
	})

	t.Run("an unknown path renders the shell with a 404", func(t *testing.T) {
		rec := get(t, h, "/nope")
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Contains(t, rec.Body.String(), "am-sidebar")
	})

	t.Run("healthz answers without any dependency", func(t *testing.T) {
		rec := get(t, h, "/healthz")
		require.Equal(t, http.StatusOK, rec.Code)
		require.JSONEq(t, `{"status":"ok","role":"web"}`, rec.Body.String())
	})
}

func TestTheme(t *testing.T) {
	h := handler(t, fixture.New())

	t.Run("light is the default when nothing is stored", func(t *testing.T) {
		require.Contains(t, get(t, h, "/catalog").Body.String(), `data-sm-theme="light"`)
	})

	t.Run("the query parameter overrides for one render", func(t *testing.T) {
		rec := get(t, h, "/catalog?theme=dark")
		require.Contains(t, rec.Body.String(), `data-sm-theme="dark"`)
		require.Empty(t, rec.Result().Cookies(), "an override must not persist")
	})

	t.Run("an unknown query value falls back rather than rendering an attribute of its own", func(t *testing.T) {
		require.Contains(t, get(t, h, "/catalog?theme=neon").Body.String(), `data-sm-theme="light"`)
	})

	t.Run("the cookie is read server-side, so the first paint is already right", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/catalog", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "am_theme", Value: "dark"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Contains(t, rec.Body.String(), `data-sm-theme="dark"`)
	})

	t.Run("posting a theme persists it and returns to the screen", func(t *testing.T) {
		rec := postTheme(t, h, url.Values{"theme": {"dark"}, "return": {"/catalog?q=aws"}})
		require.Equal(t, http.StatusSeeOther, rec.Code)
		require.Equal(t, "/catalog?q=aws", rec.Header().Get("Location"))

		cookies := rec.Result().Cookies()
		require.Len(t, cookies, 1)
		require.Equal(t, "am_theme", cookies[0].Name)
		require.Equal(t, "dark", cookies[0].Value)
		require.True(t, cookies[0].HttpOnly)
	})

	t.Run("a return target off this origin is refused", func(t *testing.T) {
		for _, hostile := range []string{
			"//evil.example/catalog", "https://evil.example", "/\\evil.example", "catalog", "",
		} {
			rec := postTheme(t, h, url.Values{"theme": {"dark"}, "return": {hostile}})
			require.Equalf(t, "/catalog", rec.Header().Get("Location"),
				"open redirect through %q", hostile)
		}
	})
}

func postTheme(t *testing.T, h http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/theme", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// hostileSource stands in for a package whose manifest was written by an
// attacker. FR-055 is absolute: nothing from a manifest may reach the page as
// markup.
type hostileSource struct{}

func (hostileSource) Catalog(_ context.Context, q view.CatalogQuery) (view.CatalogPage, error) {
	row := view.Row{
		Key:       `../../etc/passwd`,
		ID:        `evil/<script>alert('id')</script>`,
		Name:      `<script>alert('name')</script>`,
		Publisher: `evil/"onmouseover="alert(1)`,
		Category:  `<img src=x onerror=alert('cat')>`,
		Version:   `1.0.0"><script>alert('ver')</script>`,
		Updated:   `<b>now</b>`,
		Kind:      view.KindPlugin,
		Scan:      view.ScanFlagged,
		Tags:      []string{`"><script>alert('tag')</script>`},
	}
	return view.CatalogPage{
		Query:      q.Normalise(),
		Rows:       []view.Row{row},
		Total:      1,
		Page:       1,
		PageSize:   view.DefaultPageSize,
		Categories: []view.FacetOption{{Label: row.Category, Count: 1}},
		Tags:       []view.FacetOption{{Label: row.Tags[0], Count: 1}},
	}, nil
}

func TestPackageDerivedContentIsEscaped(t *testing.T) {
	h := handler(t, hostileSource{})

	bodies := map[string]string{
		"catalog screen":  get(t, h, "/catalog").Body.String(),
		"facet payload":   get(t, h, "/catalog/facet/tag").Body.String(),
		"results patch":   get(t, h, "/catalog/results").Body.String(),
		"category facet":  get(t, h, "/catalog/facet/category").Body.String(),
		"deep-linked row": get(t, h, "/catalog?q=%3Cscript%3E").Body.String(),
	}

	// The payloads below are the hostile values verbatim. Asserting on the raw
	// form is the whole test: an escaped copy of the same bytes is inert, so a
	// looser assertion ("does not contain onerror=") would fail on correct output
	// and teach nothing.
	raw := []string{
		`<script>alert('name')</script>`,
		`<script>alert('id')</script>`,
		`<img src=x onerror=alert('cat')>`,
		`"onmouseover="alert(1)`,
		`1.0.0"><script>alert('ver')</script>`,
		`<b>now</b>`,
		`"><script>alert('tag')</script>`,
	}

	for where, body := range bodies {
		t.Run(where+" emits no unescaped markup", func(t *testing.T) {
			for _, payload := range raw {
				require.NotContainsf(t, body, payload, "unescaped %q reached the page", payload)
			}
		})
	}

	t.Run("the escaped text is still present, so escaping is not silent dropping", func(t *testing.T) {
		require.Contains(t, bodies["catalog screen"], "&lt;script&gt;alert(&#39;name&#39;)&lt;/script&gt;")
		require.Contains(t, bodies["facet payload"], "&lt;script&gt;alert(&#39;tag&#39;)&lt;/script&gt;")
	})

	t.Run("a package key cannot become a javascript: href or escape its path segment", func(t *testing.T) {
		require.NotContains(t, bodies["catalog screen"], "javascript:")
		require.NotContains(t, bodies["catalog screen"], `href="/packages/../`)
		require.Contains(t, bodies["catalog screen"], `href="/packages/..%2F..%2Fetc%2Fpasswd"`)
	})
}

func TestDatastarEndpoints(t *testing.T) {
	h := handler(t, fixture.New())

	t.Run("the results endpoint patches the table, the count and nothing else by default", func(t *testing.T) {
		body := get(t, h, "/catalog/results").Body.String()
		require.Contains(t, body, "event: datastar-patch-elements")
		require.Contains(t, body, "selector #catalog-card")
		require.Contains(t, body, `id="catalog-count"`)
		require.NotContains(t, body, "selector #facet-tag-options")
	})

	t.Run("an open menu also gets its option counts", func(t *testing.T) {
		signals := url.QueryEscape(`{"menu":"tag","tags":"[]","cats":"[]","page":1}`)
		body := get(t, h, "/catalog/results?datastar="+signals).Body.String()
		require.Contains(t, body, "selector #facet-tag-options")
	})

	t.Run("the facet payload carries every option with its count", func(t *testing.T) {
		body := get(t, h, "/catalog/facet/category").Body.String()
		require.Contains(t, body, "selector #facet-category-options")
		for _, name := range []string{"Infrastructure", "Security &amp; compliance", "Data", "Developer workflow", "Documentation"} {
			require.Contains(t, body, name)
		}
	})

	t.Run("an unknown facet is a 404, not an empty menu", func(t *testing.T) {
		require.Equal(t, http.StatusNotFound, get(t, h, "/catalog/facet/publisher").Code)
	})

	t.Run("selections travel as a JSON array in a string signal", func(t *testing.T) {
		signals := url.QueryEscape(`{"tags":"[\"terraform\",\"guardrails\"]","cats":"[]","page":1}`)
		body := get(t, h, "/catalog/results?datastar="+signals).Body.String()
		require.Contains(t, body, "Platform Toolkit")
		require.NotContains(t, body, "Slack Digest")
	})

	t.Run("a hostile signal payload is refused rather than half-applied", func(t *testing.T) {
		require.Equal(t, http.StatusBadRequest, get(t, h, "/catalog/results?datastar=notjson").Code)
	})
}

func TestStatic(t *testing.T) {
	h := handler(t, fixture.New())

	t.Run("the vendored assets are served from this origin with a far-future cache", func(t *testing.T) {
		for _, path := range []string{
			"/static/vendor/datastar.js", "/static/app.js", "/static/app.css",
			"/static/fonts/space-grotesk-latin.woff2", "/static/fonts/ibm-plex-mono-500-latin-ext.woff2",
		} {
			rec := get(t, h, path)
			require.Equalf(t, http.StatusOK, rec.Code, "%s is not served", path)
			require.Equal(t, "public, max-age=31536000, immutable", rec.Header().Get("Cache-Control"))
			require.NotEmpty(t, rec.Body.Bytes())
		}
	})

	t.Run("asset urls are content-addressed, so the cache header is safe", func(t *testing.T) {
		body := get(t, h, "/catalog").Body.String()
		require.Regexp(t, `/static/app\.css\?v=[0-9a-f]{12}`, body)
		require.Regexp(t, `/static/vendor/datastar\.js\?v=[0-9a-f]{12}`, body)
	})

	t.Run("a traversal out of the static tree is refused", func(t *testing.T) {
		for _, path := range []string{"/static/../go.mod", "/static/%2e%2e/go.mod", "/static/nope.js"} {
			require.Equalf(t, http.StatusNotFound, get(t, h, path).Code, "%s escaped the static tree", path)
		}
	})
}

// TestR7Budget is the cheap, container-free half of the R7 gate. The expensive
// half is a real browser session (see the layer's report): 0 requests while
// typing at 61 options, and a p50 of 167 ms from click to table update at 10 000
// rows. What can regress silently is the markup those numbers depend on, and that
// is what this asserts.
func TestR7Budget(t *testing.T) {
	body := get(t, handler(t, fixture.New()), "/catalog").Body.String()

	t.Run("both facet filter boxes bind to a signal datastar never sends", func(t *testing.T) {
		// datastar excludes signals whose name begins with an underscore from every
		// request. Drop the underscore and typing starts costing a round trip per
		// keystroke, with nothing else looking different.
		require.Contains(t, body, `data-bind="_catQuery"`)
		require.Contains(t, body, `data-bind="_tagQuery"`)
		require.NotContains(t, body, `data-bind="catQuery"`)
		require.NotContains(t, body, `data-bind="tagQuery"`)
	})

	t.Run("options are filtered client-side against the element's own label", func(t *testing.T) {
		// The label is read from the DOM rather than interpolated into the
		// expression: a manifest keyword can be escaped into an attribute, but not
		// into a JavaScript string literal.
		payload := get(t, handler(t, fixture.New()), "/catalog/facet/tag").Body.String()
		require.Contains(t, payload, `data-show="amFuzzy($_tagQuery, el.dataset.label)"`)
		require.Contains(t, payload, `data-on:click="$tags = amToggle($tags, el.dataset.label); $page = 1"`)
	})

	t.Run("the first render ships no option list, so the payload is what the menu opens", func(t *testing.T) {
		require.NotContains(t, body, `class="am-opt"`)
		require.Contains(t, body, `if ($menu === &#39;tag&#39;) @get(&#39;/catalog/facet/tag&#39;)`)
	})

	t.Run("one debounced listener issues the round trip, and only for server-side signals", func(t *testing.T) {
		require.Contains(t, body, `data-on-signal-patch__debounce.150ms="@get('/catalog/results')"`)
		require.Contains(t, body,
			`data-on-signal-patch-filter="{include: /^(q|kind|status|cats|tags|sort|dir|page)$/}"`)
		require.NotContains(t, body, "_catQuery|", "the filter signals must stay out of the include filter")
	})

	t.Run("nothing else on the page fetches on its own", func(t *testing.T) {
		// One fetch site, so the interaction budget is auditable by reading the page.
		require.Equal(t, 1, strings.Count(body, "/catalog/results"))
	})

	t.Run("overlays are hidden before the script runs", func(t *testing.T) {
		// A visible full-viewport backdrop would swallow every click on a slow load.
		require.Contains(t, body, `class="am-backdrop" style="display:none"`)
		require.Contains(t, body, `class="am-facet-menu" style="display:none"`)
	})
}

func TestFuzzyIsWhatTheMenuUses(t *testing.T) {
	// The Go matcher and the browser's must agree; app.js is the other half and is
	// asserted in the R7 browser measurement. This case only fixes the contract.
	require.True(t, web.Fuzzy("sec com", "Security & compliance"))
	require.False(t, web.Fuzzy("zzz", "Security & compliance"))
}

func TestReadBodyDoesNotLeak(t *testing.T) {
	h := handler(t, fixture.New())
	rec := get(t, h, "/catalog")
	_, err := io.Copy(io.Discard, rec.Body)
	require.NoError(t, err)
}
