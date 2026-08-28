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

	deps := web.Deps{Catalog: source, Log: zerolog.Nop()}
	// A source that can also answer for one package backs the detail screen. The
	// hostile source below deliberately cannot, which is what makes /packages/...
	// a 404 rather than a nil dereference in the escaping test.
	if packages, ok := source.(web.PackageSource); ok {
		deps.Packages = packages
	}
	return web.New(deps, web.Options{}).Handler()
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
			"/scanner", "/audit", "/storage", "/org", "/cli",
			"/packages/example/terraform-module-review"} {
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

	// A package id is `namespace/name`, so the link has to keep that slash as a
	// separator — which rules out escaping the id whole, and escaping the halves
	// separately leaves `..` intact because `.` is a legal path character that
	// url.PathEscape does not touch. So each half is VALIDATED against the same
	// segment pattern internal/blob holds an object key to, and a row whose id
	// fails it is not linked to a package at all.
	t.Run("a package id that is not two valid segments is not linked to a package", func(t *testing.T) {
		require.NotContains(t, bodies["catalog screen"], "javascript:")
		require.NotContains(t, bodies["catalog screen"], `href="/packages/../`)
		require.NotContains(t, bodies["catalog screen"], `href="/packages/`)
		require.Contains(t, bodies["catalog screen"], `<a class="am-row" href="/catalog">`)
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

// hostileDetail is a package whose manifest, components and dependent profiles
// were all written by an attacker. It is a separate source from hostileSource
// because that one deliberately implements only CatalogSource — which is what
// makes /packages/... a 404 there — and the detail screen renders strings the
// catalog row never carries: the manifest body, the component tree, the
// capability targets and the dependent profiles' slugs.
type hostileDetail struct{ hostileSource }

func (hostileDetail) Package(_ context.Context, namespace, name string) (view.Package, error) {
	return view.Package{
		ID:             namespace + "/" + name,
		Name:           `<script>alert('detailname')</script>`,
		Kind:           view.KindPlugin,
		Publisher:      `evil/"onmouseover="alert('pub')`,
		Category:       `<img src=x onerror=alert('cat')>`,
		Description:    `<script>alert('desc')</script>`,
		Version:        `1.0.0"><script>alert('ver')</script>`,
		SpecVersion:    `1.0.0"><script>alert('spec')</script>`,
		ManifestObject: `plugin.json"><script>alert('object')</script>`,
		Manifest:       `{"name":"<script>alert('manifest')</script>"}`,
		Tags:           []string{`"><script>alert('tag')</script>`},
		Components: []view.Component{{
			Kind: "skill",
			Name: `<script>alert('component')</script>`,
			Path: `skills/<script>alert('path')</script>`,
			Note: `<b>note</b>`,
		}},
		Capabilities: view.Capabilities{
			Scanned: true,
			Rows: []view.CapabilityRow{{
				Name:     `<script>alert('cap')</script>`,
				Inferred: view.CapabilityFacet{Present: true, Level: "review", Detail: []string{`<script>alert('target')</script>`}},
			}},
		},
		Versions: []view.PackageVersion{{
			Version:   `1.0.0"><script>alert('vrow')</script>`,
			ObjectKey: `skills/<script>alert('key')</script>/bundle.tar.zst`,
			Digest:    `sha256:<script>alert('digest')</script>`,
		}},
		Dependents: []view.Dependent{{
			Slug: `../../etc/passwd`,
			Name: `<script>alert('profile')</script>`,
			Mode: "pinned",
			Pin:  `1.0.0"><script>alert('pin')</script>`,
		}},
	}, nil
}

func TestDetailDerivedContentIsEscaped(t *testing.T) {
	body := get(t, handler(t, hostileDetail{}), "/packages/evil/thing").Body.String()

	// Each payload is asserted BOTH ways: the raw bytes are absent AND the escaped
	// bytes are present. The second half is not decoration. A NotContains alone
	// passes when the field is never rendered at all, and one of these fields
	// genuinely is not — Component.Path, which the tree builds from names, so it
	// carries no payload here and is not in this table. Without the positive half
	// there would be no way to tell that case from a field that is escaped, and a
	// panel quietly dropped in a later edit would take its assertion with it.
	for _, tc := range []struct{ raw, escaped string }{
		{`<script>alert('detailname')</script>`, `&lt;script&gt;alert(&#39;detailname&#39;)&lt;/script&gt;`},
		{`<script>alert('desc')</script>`, `&lt;script&gt;alert(&#39;desc&#39;)&lt;/script&gt;`},
		{`<script>alert('manifest')</script>`, `&lt;script&gt;alert(&#39;manifest&#39;)&lt;/script&gt;`},
		{`<script>alert('component')</script>`, `&lt;script&gt;alert(&#39;component&#39;)&lt;/script&gt;`},
		{`<script>alert('cap')</script>`, `&lt;script&gt;alert(&#39;cap&#39;)&lt;/script&gt;`},
		{`<script>alert('target')</script>`, `&lt;script&gt;alert(&#39;target&#39;)&lt;/script&gt;`},
		{`<script>alert('key')</script>`, `&lt;script&gt;alert(&#39;key&#39;)&lt;/script&gt;`},
		{`<script>alert('digest')</script>`, `&lt;script&gt;alert(&#39;digest&#39;)&lt;/script&gt;`},
		{`<script>alert('profile')</script>`, `&lt;script&gt;alert(&#39;profile&#39;)&lt;/script&gt;`},
		{`<script>alert('spec')</script>`, `&lt;script&gt;alert(&#39;spec&#39;)&lt;/script&gt;`},
		{`<script>alert('vrow')</script>`, `&lt;script&gt;alert(&#39;vrow&#39;)&lt;/script&gt;`},
		{`<script>alert('pin')</script>`, `&lt;script&gt;alert(&#39;pin&#39;)&lt;/script&gt;`},
		{`<script>alert('object')</script>`, `&lt;script&gt;alert(&#39;object&#39;)&lt;/script&gt;`},
		{`"onmouseover="alert('pub')`, `onmouseover=&#34;alert(&#39;pub&#39;)`},
	} {
		require.NotContainsf(t, body, tc.raw, "unescaped %q reached the detail screen", tc.raw)
		require.Containsf(t, body, tc.escaped,
			"%q is neither escaped nor rendered — the assertion above is passing vacuously", tc.raw)
	}

	// A dependent profile's slug reaches the page as data too, and `..` inside one
	// would climb out of /profiles/.
	require.NotContains(t, body, `href="/profiles/../`)
}

// T062, the rendering half. Driven off the fixture's own id list rather than a
// list written here, so a package added to the fixtures cannot skip this by
// omission — and it asserts the STRUCTURAL difference between the variants,
// which is the one thing a per-package screenshot would not catch.
func TestBothVariantsRenderForEverySeededPackage(t *testing.T) {
	source := fixture.New()
	h := handler(t, source)

	ids := source.IDs()
	require.Len(t, ids, 10, "the design seeds ten packages")

	var plugins, skills int
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			rec := get(t, h, "/packages/"+id)
			require.Equal(t, http.StatusOK, rec.Code)
			body := rec.Body.String()

			namespace, name, _ := strings.Cut(id, "/")
			detail, err := source.Package(t.Context(), namespace, name)
			require.NoError(t, err)

			require.Contains(t, body, "am-detail")
			require.Contains(t, body, detail.ManifestPanelTitle())

			// The variant split is STRUCTURAL: a standalone skill has no
			// package-contents section at all, rather than an empty one. An empty
			// section would say the tree was inspected and found nothing, which is
			// a different claim from "this kind of package has no tree".
			if detail.Kind == view.KindPlugin {
				plugins++
				require.Contains(t, body, "Package contents")
				require.Contains(t, body, detail.Tree())
			} else {
				skills++
				require.NotContains(t, body, "Package contents")
			}

			// Whichever branch the capability panel took, exactly one of the three
			// is present — the unscanned notice, the scanned-and-empty notice, or
			// the comparison table. Two of them would mean the panel is showing a
			// version's state and its absence at once.
			states := 0
			for _, marker := range []string{
				`id="capability-unscanned"`, `id="capability-none"`, `class="am-cap-head"`,
			} {
				if strings.Contains(body, marker) {
					states++
				}
			}
			require.Equal(t, 1, states, "the capability panel must be in exactly one state")
		})
	}

	require.Positive(t, plugins, "the fixtures must contain a plugin")
	require.Positive(t, skills, "and a standalone skill, or this test proves one variant")
}
