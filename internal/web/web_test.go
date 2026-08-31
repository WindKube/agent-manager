package web_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/components"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/view"
)

func handler(t *testing.T, source web.CatalogSource) http.Handler {
	t.Helper()

	// A screen test must say who is looking, because Deps.Viewers fails closed when
	// nil and the guard would send every route here to the sign-in screen. The
	// signed-out and no-role variants are exercised by the tests that are about
	// those states, with their own source.
	deps := web.Deps{Catalog: source, Viewers: fixture.SignedInViewers(), Log: zerolog.Nop()}
	// A source that can also answer for one package backs the detail screen. The
	// hostile source below deliberately cannot, which is what makes /packages/...
	// a 404 rather than a nil dereference in the escaping test.
	if packages, ok := source.(web.PackageSource); ok {
		deps.Packages = packages
	}
	// Same shape for the two governance screens, and for the sidebar counts. The
	// fixture answers all three reads and deliberately cannot answer a decision, so
	// deps.Reviewer stays nil here and the screen renders what a hub with no
	// reviewer wired renders.
	if scanner, ok := source.(web.ScannerSource); ok {
		deps.Scanner = scanner
	}
	if audit, ok := source.(web.AuditSource); ok {
		deps.Audit = audit
	}
	if badges, ok := source.(web.BadgeSource); ok {
		deps.Badges = badges
	}
	return web.New(deps, web.Options{}).Handler()
}

// get is an ordinary request from somebody who is signed in.
//
// It carries a session cookie because the guard reads one BEFORE it asks the
// viewer source who this is — no cookie is not "a viewer to resolve", it is a
// visitor with nothing to resolve, and the guard redirects without calling the
// api. The value is opaque here: the api is what would recognise it, and the
// fixture source answers the same viewer whatever it is handed.
func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, http.NoBody)
	req.AddCookie(&http.Cookie{Name: "am_session", Value: "screen-test-session"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// getSignedOut is the same request from somebody with no session at all, for the
// tests that are about that state rather than about a screen.
func getSignedOut(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
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
			"Connect the CLI", "am-nav-badge-alert",
		} {
			require.Containsf(t, body, want, "sidebar is missing %q", want)
		}
	})

	// This subtest used to assert "Krzysztof W." and "Platform · Admin" were on the
	// page. They were compiled into shell.templ, so it asserted that the shell
	// claimed an identity no request had resolved — the defect this feature exists
	// to remove (FR-116, SC-106).
	//
	// The component-level form of that property is asserted exhaustively next door
	// in identity_test.go: every screen, in both viewer states, plus a scan of the
	// source for the literal that is only rendered in a state no test enters. What
	// is left for a ROUTER test is the half none of those can see — that the
	// identity on a routed page came from the viewer source this router was handed.
	//
	// So two routers are built over two different viewers and each page must carry
	// its own and not the other's. An identity compiled into the router could not
	// vary that way, and neither could one the router substituted when a source
	// answered something it did not like.
	t.Run("the chip on a routed page is the viewer that request resolved", func(t *testing.T) {
		ada, bo := fixture.SignedInViewer(), fixture.UnmappedViewer()

		for _, who := range []struct {
			viewers web.ViewerSource
			mine    *view.Viewer
			theirs  *view.Viewer
		}{
			{fixture.SignedInViewers(), ada, bo},
			// Signed in holding no role still resolves an identity, and the FR-117
			// screen the guard renders instead of the catalog carries the same chip.
			{fixture.UnmappedViewers(), bo, ada},
		} {
			own := web.New(web.Deps{
				Catalog: fixture.New(),
				Viewers: who.viewers,
				Log:     zerolog.Nop(),
			}, web.Options{}).Handler()
			body := get(t, own, "/catalog").Body.String()

			require.Contains(t, body, `<div class="am-avatar">`+who.mine.Initials()+`</div>`)
			require.Contains(t, body, who.mine.DisplayName)
			require.NotContainsf(t, body, who.theirs.DisplayName,
				"a page resolved for %q carries %q, so something other than the request "+
					"decided who is looking", who.mine.DisplayName, who.theirs.DisplayName)
		}
	})

	// And the other side of it: with nobody resolved there is no chip, because no
	// screen is reached at all. A chip with empty fields would be the compiled-in
	// chip with its literals deleted.
	t.Run("a request that resolved nobody reaches no shell at all", func(t *testing.T) {
		signedOut := web.New(web.Deps{
			Catalog: fixture.New(),
			Viewers: fixture.SignedOutViewers(),
			Log:     zerolog.Nop(),
		}, web.Options{}).Handler()

		body := getSignedOut(t, signedOut, "/catalog").Body.String()
		for _, forbidden := range []string{"am-avatar", "am-viewer-name", "am-viewer-role", "am-signout", "am-sidebar"} {
			require.NotContainsf(t, body, forbidden, "the router rendered %q without a resolved session", forbidden)
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
		req.AddCookie(&http.Cookie{Name: "am_session", Value: "screen-test-session"})
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
	// The toggle lives in the shell, so the only person who can submit this form is
	// one the guard already resolved.
	req.AddCookie(&http.Cookie{Name: "am_session", Value: "screen-test-session"})
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

// ---- the viewer, sign-in and the no-role state (US2) -------------------------

// These render the components directly rather than through the router. The shell's
// viewer is a prop with no default (FR-116), so a signed-in page is a page a
// caller supplied a viewer to, and driving it through the router would test how
// this layer's handler resolves one instead of what the shell does with it.

func shellBody(t *testing.T, viewer *view.Viewer, body templ.Component) string {
	t.Helper()

	shell := components.Shell{
		Title: "Catalog", Theme: "light", Next: "dark", Active: "catalog", Return: "/catalog",
		AppCSS: "/static/app.css", AppJS: "/static/app.js", VendorJS: "/static/vendor/datastar.js",
		Viewer: viewer,
	}

	var out strings.Builder
	ctx := templ.WithChildren(context.Background(), body)
	require.NoError(t, components.Layout(shell).Render(ctx, &out))
	return out.String()
}

func TestTheShellRendersTheResolvedViewerAndNothingWhenThereIsNone(t *testing.T) {
	screen := components.Placeholder("Catalog", "Everything registered in this hub.")

	t.Run("a resolved viewer reaches the chip, initials included", func(t *testing.T) {
		viewer := fixture.SignedInViewer()
		body := shellBody(t, viewer, screen)

		require.Contains(t, body, viewer.DisplayName)
		require.Contains(t, body, `<div class="am-avatar">AF</div>`,
			"the avatar must be derived from the resolved name, not carried beside it")
		require.Contains(t, body, "Catalog admin", "the chip's role is the resolved role, humanised")
	})

	t.Run("a viewer holding no role is labelled as holding none rather than left blank", func(t *testing.T) {
		body := shellBody(t, fixture.UnmappedViewer(), screen)
		require.Contains(t, body, `<div class="am-viewer-role">No role</div>`)
	})

	t.Run("signed out renders no chip at all — no placeholder, no initials, no Guest", func(t *testing.T) {
		body := shellBody(t, fixture.SignedOutViewer(), screen)

		for _, forbidden := range []string{"am-avatar", "am-viewer-id", "am-viewer-name", "am-viewer-role"} {
			require.NotContainsf(t, body, forbidden, "the signed-out shell rendered %q", forbidden)
		}
		require.NotContains(t, body, "Guest")
		// The theme toggle is not part of the viewer's identity and must survive.
		require.Contains(t, body, "am-theme-toggle")
	})

	t.Run("sign-out is offered to a viewer and is a POST form rather than a link", func(t *testing.T) {
		signedIn := shellBody(t, fixture.SignedInViewer(), screen)
		require.Contains(t, signedIn, `<form method="post" action="/auth/logout">`)
		require.NotContains(t, signedIn, `href="/auth/logout"`,
			"a GET sign-out is triggerable by any image tag on any page")

		require.NotContains(t, shellBody(t, fixture.SignedOutViewer(), screen), "/auth/logout",
			"there is nothing to sign out of")
	})
}

func signInBody(t *testing.T, in view.SignIn) string {
	t.Helper()

	shell := components.Shell{
		Title: "Sign in", Theme: "light", Next: "dark", Return: "/auth/signin",
		AppCSS: "/static/app.css", AppJS: "/static/app.js", VendorJS: "/static/vendor/datastar.js",
	}

	var out strings.Builder
	require.NoError(t, components.SignInScreen(shell, in).Render(context.Background(), &out))
	return out.String()
}

func TestTheSignInScreenOffersOneActionAndNoAccountOfItsOwn(t *testing.T) {
	in := view.SignIn{Provider: "the corporate directory", Return: "/scanner"}
	body := signInBody(t, in)

	t.Run("it names the hub, names the provider and offers one way in", func(t *testing.T) {
		require.Contains(t, body, components.ProductName)
		require.Contains(t, body, "the corporate directory")
		require.Contains(t, body, `href="/auth/login?return=%2Fscanner"`)
		require.Equal(t, 1, strings.Count(body, "/auth/login"),
			"one action, so there is no second path a person can be led down")
	})

	// FR-109. A password field on this screen would be a password this hub holds,
	// and a registration form would be an account this hub owns; there is neither,
	// and both are the kind of thing a copy edit adds back without noticing.
	t.Run("it holds no password field and no way to create an account", func(t *testing.T) {
		require.NotContains(t, body, `type="password"`)
		require.NotContains(t, body, `name="password"`)

		// Asserted by counting rather than by absence: this page has exactly one form
		// and it is the theme toggle, so a second one is a field somebody added for a
		// credential this hub is not allowed to hold.
		require.Equal(t, 1, strings.Count(body, "<form"))
		require.Contains(t, body, `<form method="post" action="/theme">`)

		for _, forbidden := range []string{"Sign up", "Register", "Create account", "Create an account"} {
			require.NotContainsf(t, body, forbidden, "the sign-in screen offers %q", forbidden)
		}
	})

	t.Run("an unreachable provider is stated and no failing button is offered", func(t *testing.T) {
		unavailable := signInBody(t, view.SignIn{Provider: "the corporate directory", Unavailable: true})
		require.Contains(t, unavailable, `id="signin-unavailable"`)
		require.NotContains(t, unavailable, "/auth/login")
	})

	t.Run("a provider's own words reach the page escaped", func(t *testing.T) {
		hostile := signInBody(t, view.SignIn{
			Provider: `<script>alert('provider')</script>`,
			Notice:   `The provider refused: <img src=x onerror=alert('why')>`,
		})
		require.NotContains(t, hostile, `<script>alert('provider')</script>`)
		require.NotContains(t, hostile, `<img src=x onerror=alert('why')>`)
		require.Contains(t, hostile, `&lt;script&gt;alert(&#39;provider&#39;)&lt;/script&gt;`)
		require.Contains(t, hostile, `&lt;img src=x onerror=alert(&#39;why&#39;)&gt;`)
	})
}

// FR-119: the hint is switched on explicitly or it is not switched on. The
// negative case is the whole requirement — a hint that appears because a list
// happened to be populated is a hint that appears in production.
func TestLocalCredentialsAppearOnlyBehindTheExplicitFlag(t *testing.T) {
	credentials := []view.Credential{
		{Username: "someone@local.invalid", Password: "a-local-only-password", Role: "catalog-admin"},
	}

	t.Run("with the flag set, the accounts are on the page", func(t *testing.T) {
		body := signInBody(t, view.SignIn{DevCredentialHint: true, Credentials: credentials})
		require.Contains(t, body, `id="signin-dev-credentials"`)
		require.Contains(t, body, "someone@local.invalid")
		require.Contains(t, body, "a-local-only-password")
	})

	t.Run("credentials supplied without the flag render nothing", func(t *testing.T) {
		body := signInBody(t, view.SignIn{Credentials: credentials})
		require.NotContains(t, body, `id="signin-dev-credentials"`)
		require.NotContains(t, body, "someone@local.invalid")
		require.NotContains(t, body, "a-local-only-password")
	})

	t.Run("the flag set with nothing to show renders nothing", func(t *testing.T) {
		require.NotContains(t, signInBody(t, view.SignIn{DevCredentialHint: true}),
			`id="signin-dev-credentials"`)
	})
}

// FR-117. The assertion that matters is the last one: this screen must not be
// mistakable for a hub with nothing in it, because the two ask their reader for
// completely different things.
func TestTheNoRoleStateSaysSoRatherThanRenderingAnEmptyHub(t *testing.T) {
	viewer := fixture.UnmappedViewer()
	body := shellBody(t, viewer, components.NoRoleScreen(view.NoRole{Viewer: *viewer, Groups: viewer.Groups}))

	require.Contains(t, body, `id="no-mapped-role"`)
	require.Contains(t, body, viewer.Email, "they are signed in, and as whom is what they have to quote")
	require.Contains(t, body, "contractors-eu", "the groups are what they have to ask about")
	require.Contains(t, body, "This is not an empty hub")

	// The signed-out empty state and this one are different markup as well as
	// different copy, so neither a reader nor a test can take one for the other.
	require.NotContains(t, body, `id="catalog-signed-out"`)
	require.NotContains(t, body, "am-empty")

	t.Run("a viewer whose provider sent no groups is told that specifically", func(t *testing.T) {
		bare := view.Viewer{DisplayName: "No Groups", Email: "none@fixture.invalid"}
		body := shellBody(t, &bare, components.NoRoleScreen(view.NoRole{Viewer: bare, Groups: bare.Groups}))
		require.Contains(t, body, "sent no group membership")
		require.NotContains(t, body, "am-tagrow", "there is nothing to list")
	})
}
