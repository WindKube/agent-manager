package web_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web"
	"agent-manager/internal/web/components"
	"agent-manager/internal/web/fakeapi"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// newServer is the web role in front of a fresh fakeapi, signed in as the
// seed's catalog admin.
func newServer(t *testing.T) (*fakeapi.API, http.Handler) {
	t.Helper()
	return newServerWith(t, web.Options{})
}

func newServerWith(t *testing.T, opts web.Options) (*fakeapi.API, http.Handler) {
	t.Helper()
	api := fakeapi.New(t)
	client, err := hub.New(api.URL)
	require.NoError(t, err)
	return api, web.New(web.Deps{Hub: client, Log: zerolog.Nop()}, opts).Handler()
}

// get is a signed-in request. Without a session cookie the guard redirects
// before asking the api; the fake api accepts any value.
func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, http.NoBody)
	req.AddCookie(&http.Cookie{Name: "am_session", Value: "screen-test-session"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func getSignedOut(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, http.NoBody))
	return rec
}

func post(t *testing.T, h http.Handler, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "am_session", Value: "screen-test-session"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestShell(t *testing.T) {
	_, h := newServer(t)

	t.Run("the catalog renders every sidebar group and badge", func(t *testing.T) {
		body := get(t, h, "/catalog").Body.String()
		for _, want := range []string{
			"Workspace", "Security", "Administration", "Onboarding",
			"Catalog", "Profiles", "Scanner", "Audit log", "Storage", "Organization", "Webhooks",
			"Connect the CLI", "am-nav-badge-alert",
		} {
			require.Containsf(t, body, want, "sidebar is missing %q", want)
		}
	})

	// identity_test.go covers components; this checks that a routed page's identity
	// came from the viewer source, by building two routers over two viewers.
	t.Run("the chip on a routed page is the viewer that request resolved", func(t *testing.T) {
		ada, bo := signedInViewer(), unmappedViewer()

		for _, who := range []struct {
			unmapped bool
			mine     *view.Viewer
			theirs   *view.Viewer
		}{
			{false, ada, bo},
			// The no-role screen carries the same chip.
			{true, bo, ada},
		} {
			api, own := newServer(t)
			if who.unmapped {
				api.Data.Unmapped()
			}
			body := get(t, own, "/catalog").Body.String()

			require.Contains(t, body, `<div class="am-avatar">`+who.mine.Initials()+`</div>`)
			require.Contains(t, body, who.mine.DisplayName)
			require.NotContainsf(t, body, who.theirs.DisplayName,
				"a page resolved for %q carries %q, so something other than the request "+
					"decided who is looking", who.mine.DisplayName, who.theirs.DisplayName)
		}
	})

	t.Run("a request that resolved nobody reaches no shell at all", func(t *testing.T) {
		api, signedOut := newServer(t)
		api.Data.SignedOut()

		body := getSignedOut(t, signedOut, "/catalog").Body.String()
		for _, forbidden := range []string{"am-avatar", "am-viewer-name", "am-viewer-role", "am-signout", "am-sidebar"} {
			require.NotContainsf(t, body, forbidden, "the router rendered %q without a resolved session", forbidden)
		}
	})

	t.Run("no page references an external host", func(t *testing.T) {
		// The quickstart must work offline.
		for _, path := range []string{"/catalog", "/scanner", "/profiles", "/storage", "/audit", "/cli", "/org", "/webhooks"} {
			body := get(t, h, path).Body.String()
			for _, forbidden := range []string{"//fonts.googleapis.com", "//fonts.gstatic.com", "//cdn.", "//unpkg.com", "//esm.sh", "//jsdelivr"} {
				require.NotContainsf(t, body, forbidden, "%s references %s", path, forbidden)
			}
		}
	})

	t.Run("the sidebar routes are all navigable rather than 404", func(t *testing.T) {
		for _, path := range []string{"/", "/catalog", "/profiles", "/profiles/platform-engineer",
			"/scanner", "/audit", "/storage", "/org", "/webhooks", "/cli",
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
	_, h := newServer(t)

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
	req.AddCookie(&http.Cookie{Name: "am_session", Value: "screen-test-session"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// hostileCatalog makes the api answer one package whose manifest was written
// by an attacker; nothing from a manifest may reach the page as markup.
func hostileCatalog(api *fakeapi.API) {
	category := `<img src=x onerror=alert('cat')>`
	api.Data.Categories = []string{category}
	api.Data.Packages = []apiclient.CatalogPackage{{
		Id:         `evil/<script>alert('id')</script>`,
		Name:       `<script>alert('name')</script>`,
		Publisher:  `evil/"onmouseover="alert(1)`,
		Category:   &category,
		Version:    `1.0.0"><script>alert('ver')</script>`,
		UpdatedAt:  time.Now(),
		Kind:       apiclient.CatalogPackageKindPlugin,
		Verdict:    apiclient.CatalogPackageVerdictFlagged,
		Visibility: apiclient.CatalogPackageVisibilityOrganisation,
		Tags:       []string{`"><script>alert('tag')</script>`},
	}}
}

func TestPackageDerivedContentIsEscaped(t *testing.T) {
	api, h := newServer(t)
	hostileCatalog(api)

	bodies := map[string]string{
		"catalog screen":  get(t, h, "/catalog").Body.String(),
		"facet payload":   get(t, h, "/catalog/facet/tag").Body.String(),
		"results patch":   get(t, h, "/catalog/results").Body.String(),
		"category facet":  get(t, h, "/catalog/facet/category").Body.String(),
		"deep-linked row": get(t, h, "/catalog?q=%3Cscript%3E").Body.String(),
	}

	// Asserted on the raw form: an escaped copy is inert, so a looser assertion
	// like "does not contain onerror=" would fail on correct output.
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

	// Escaping cannot neutralise `..` (url.PathEscape leaves `.` alone), so each id
	// segment is validated and an invalid id is not linked at all.
	t.Run("a package id that is not two valid segments is not linked to a package", func(t *testing.T) {
		require.NotContains(t, bodies["catalog screen"], "javascript:")
		require.NotContains(t, bodies["catalog screen"], `href="/packages/../`)
		require.NotContains(t, bodies["catalog screen"], `href="/packages/`)
		require.Contains(t, bodies["catalog screen"], `<a class="am-row" href="/catalog">`)
	})
}

func TestDatastarEndpoints(t *testing.T) {
	_, h := newServer(t)

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
	_, h := newServer(t)

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

// TestR7Budget asserts the markup the measured browser performance depends on,
// since that is what can regress silently.
func TestR7Budget(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/catalog").Body.String()

	t.Run("both facet filter boxes bind to a signal datastar never sends", func(t *testing.T) {
		// datastar never sends underscore-prefixed signals; without it every
		// keystroke costs a round trip.
		require.Contains(t, body, `data-bind="_catQuery"`)
		require.Contains(t, body, `data-bind="_tagQuery"`)
		require.NotContains(t, body, `data-bind="catQuery"`)
		require.NotContains(t, body, `data-bind="tagQuery"`)
	})

	t.Run("options are filtered client-side against the element's own label", func(t *testing.T) {
		// Read from the DOM: a manifest keyword can be escaped into an attribute,
		// but not into a JavaScript string literal.
		payload := get(t, h, "/catalog/facet/tag").Body.String()
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
		// The debounced listener and the header's refresh button.
		require.Equal(t, 2, strings.Count(body, "/catalog/results"))
	})

	t.Run("overlays are hidden before the script runs", func(t *testing.T) {
		// A visible full-viewport backdrop would swallow every click on a slow load.
		require.Contains(t, body, `class="am-backdrop" style="display:none"`)
		require.Contains(t, body, `class="am-facet-menu" style="display:none"`)
	})
}

func TestFuzzyIsWhatTheMenuUses(t *testing.T) {
	// The Go matcher and app.js must agree.
	require.True(t, web.Fuzzy("sec com", "Security & compliance"))
	require.False(t, web.Fuzzy("zzz", "Security & compliance"))
}

func TestReadBodyDoesNotLeak(t *testing.T) {
	_, h := newServer(t)
	rec := get(t, h, "/catalog")
	_, err := io.Copy(io.Discard, rec.Body)
	require.NoError(t, err)
}

// hostileDetail makes the api answer evil/thing with attacker-written detail
// fields that the catalog row never carries.
func hostileDetail(api *fakeapi.API) {
	category := `<img src=x onerror=alert('cat')>`
	description := `<script>alert('desc')</script>`
	spec := `1.0.0"><script>alert('spec')</script>`
	note := `<b>note</b>`
	digest := `sha256:<script>alert('digest')</script>`
	pin := `1.0.0"><script>alert('pin')</script>`
	hookTarget := `<script>alert('hook')</script>`
	api.Data.Details["evil/thing"] = apiclient.PackageDetail{
		Id:             "evil/thing",
		Name:           `<script>alert('detailname')</script>`,
		Kind:           apiclient.PackageDetailKindPlugin,
		Publisher:      apiclient.PackagePublisher{Slug: `evil/"onmouseover="alert('pub')`},
		Category:       &category,
		Description:    &description,
		Version:        `1.0.0"><script>alert('ver')</script>`,
		Origin:         apiclient.PackageOrigin{SpecVersion: &spec},
		ManifestObject: apiclient.PackageDetailManifestObject(`plugin.json"><script>alert('object')</script>`),
		Manifest:       `{"name":"<script>alert('manifest')</script>"}`,
		Tags:           []string{`"><script>alert('tag')</script>`},
		Components: []apiclient.PackageComponent{{
			Kind: apiclient.PackageComponentKindSkill,
			Name: `<script>alert('component')</script>`,
			Path: `skills/<script>alert('path')</script>`,
			Note: &note,
		}, {
			Kind:   apiclient.PackageComponentKindHook,
			Name:   "PreToolUse",
			Path:   "hooks.json#/hooks/PreToolUse/0/hooks/0",
			Target: &hookTarget,
		}},
		Capabilities: apiclient.PackageCapabilities{
			Scanned: true,
			Inferred: []apiclient.PackageCapability{{
				Name:   apiclient.PackageCapabilityName(`<script>alert('cap')</script>`),
				Level:  apiclient.PackageCapabilityLevelReview,
				Detail: []string{`<script>alert('target')</script>`},
			}},
		},
		Versions: []apiclient.PackageVersion{{
			Version:   `1.0.0"><script>alert('vrow')</script>`,
			ObjectKey: `skills/<script>alert('key')</script>/bundle.tar.zst`,
			Digest:    &digest,
		}},
		Dependents: []apiclient.PackageDependent{{
			Slug:    `../../etc/passwd`,
			Name:    `<script>alert('profile')</script>`,
			Mode:    apiclient.PackageDependentModePinned,
			Version: &pin,
		}},
	}
}

func TestDetailDerivedContentIsEscaped(t *testing.T) {
	api, h := newServer(t)
	hostileDetail(api)
	body := get(t, h, "/packages/evil/thing").Body.String()

	// Asserted both ways: NotContains alone passes vacuously when a field is not
	// rendered at all, e.g. after a panel is dropped.
	for _, tc := range []struct{ raw, escaped string }{
		{`<script>alert('detailname')</script>`, `&lt;script&gt;alert(&#39;detailname&#39;)&lt;/script&gt;`},
		{`<script>alert('desc')</script>`, `&lt;script&gt;alert(&#39;desc&#39;)&lt;/script&gt;`},
		{`<script>alert('manifest')</script>`, `&lt;script&gt;alert(&#39;manifest&#39;)&lt;/script&gt;`},
		{`<script>alert('component')</script>`, `&lt;script&gt;alert(&#39;component&#39;)&lt;/script&gt;`},
		{`<script>alert('hook')</script>`, `&lt;script&gt;alert(&#39;hook&#39;)&lt;/script&gt;`},
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

	require.NotContains(t, body, `href="/profiles/../`)
}

// Driven off the seed's package list so a new package cannot skip it by omission.
func TestBothVariantsRenderForEverySeededPackage(t *testing.T) {
	api, h := newServer(t)
	client, err := hub.New(api.URL)
	require.NoError(t, err)
	ctx := view.WithToken(t.Context(), "screen-test-session")

	require.Len(t, api.Data.Packages, 10, "the design seeds ten packages")

	var plugins, skills int
	for _, row := range api.Data.Packages {
		id := row.Id
		t.Run(id, func(t *testing.T) {
			rec := get(t, h, "/packages/"+id)
			require.Equal(t, http.StatusOK, rec.Code)
			body := rec.Body.String()

			namespace, name, _ := strings.Cut(id, "/")
			detail, err := client.Package(ctx, namespace, name)
			require.NoError(t, err)

			require.Contains(t, body, "am-detail")
			require.Contains(t, body, detail.ManifestPanelTitle())

			// A standalone skill has no contents section at all, not an empty one.
			if detail.Kind == view.KindPlugin {
				plugins++
				require.Contains(t, body, "Package contents")
				require.Contains(t, body, detail.Tree())
			} else {
				skills++
				require.NotContains(t, body, "Package contents")
			}

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

	require.Positive(t, plugins, "the seed must contain a plugin")
	require.Positive(t, skills, "and a standalone skill, or this test proves one variant")
}

// In the seed, platform-engineer already holds platform-toolkit and sre-oncall
// may not curate it.
func TestAddToProfileTellsAHeldProfileApartFromACuratableOne(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/packages/example/platform-toolkit").Body.String()

	require.Contains(t, body, `id="add-to-profile"`)
	require.Contains(t, body, "Add to profile")

	require.Contains(t, body, `<div class="am-add-group-label">Organisation</div>`)
	require.Contains(t, body, `<div class="am-add-group-label">Shared</div>`)

	require.Contains(t, body,
		`<a class="am-dep-name" href="/profiles/platform-engineer">Platform Engineer</a> `+
			`<span class="am-dep-pin">Already in this profile</span>`)

	// Not curatable: shown disabled with a visible reason, never hidden.
	require.Contains(t, body,
		`<button type="button" class="am-btn" disabled aria-disabled="true" `+
			`title="`+view.CurateDisabledReason+`">Add</button>`)
	require.Contains(t, body, `<span class="am-toggle-note">`+view.CurateDisabledReason+`</span>`)
	require.Contains(t, body, view.CurateDisabledReason)
}

func TestAddToProfileOffersAPlainFormToACuratableProfile(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/packages/community/postgres-migration-guard").Body.String()

	require.Contains(t, body, `<form method="post" action="/profiles/entries/add">`+
		`<input type="hidden" name="slug" value="platform-engineer"> `+
		`<input type="hidden" name="id" value="community/postgres-migration-guard"> `+
		`<button type="submit" class="am-btn">Add</button></form>`)
}

func TestPackageContentsGroupComponentsByKind(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/packages/example/platform-toolkit").Body.String()

	require.Contains(t, body, `<div class="am-comp-group">Hooks</div>`)
	require.Contains(t, body, "PreToolUse · matcher Bash · ${CLAUDE_PLUGIN_ROOT}/hooks/guard.sh")
	require.Less(t, strings.Index(body, ">Skills<"), strings.Index(body, ">Hooks<"))
}

func TestAddToProfileWithNoProfilesPointsAtProfiles(t *testing.T) {
	api, h := newServer(t)
	api.Data.Profiles = nil
	body := get(t, h, "/packages/example/platform-toolkit").Body.String()

	require.Contains(t, body, "You have no profiles yet")
	require.Contains(t, body, `href="/profiles"`)
	require.NotContains(t, body, "could not be read", "zero profiles is not the same fact as a failed read")
}

func TestAddToProfileWhenTheReadFailsSaysSoRatherThanClaimingThereAreNone(t *testing.T) {
	api, h := newServer(t)
	api.Fail("listProfiles", http.StatusServiceUnavailable)
	body := get(t, h, "/packages/example/platform-toolkit").Body.String()

	require.Contains(t, body, "could not be read")
	require.NotContains(t, body, "You have no profiles yet")
}

func TestFilesPanelListsFilesButStaysClosedUntilOneIsChosen(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/packages/example/adr-writer").Body.String()

	require.Contains(t, body, `id="files-panel"`)
	require.Contains(t, body, `am-file-path">SKILL.md<`)
	require.Contains(t, body, `am-file-path">references/template.md<`)

	require.NotContains(t, body, `aria-label="File content"`,
		"the file panel must not be open on a plain page load")
	require.NotContains(t, body, "<h1 class=\"am-md-h\">ADR writer",
		"no file's content should render before one is selected")
}

// The heading arriving as real markup proves the markdown pipeline ran.
func TestFilesPanelSelectsTheFileTheQueryNames(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/packages/example/adr-writer?file=references%2Ftemplate.md").Body.String()

	require.Contains(t, body, "<h1 class=\"am-md-h\">Template")
	// "/adr new" is unique to SKILL.md's body; its opening sentence is also the
	// package description.
	require.NotContains(t, body, "/adr new",
		"only the selected file's content is shown, not every file at once")
}

// The clean URL must not pick a default file, or closing looks like it did nothing.
func TestFilesPanelCloseLinkActuallyClosesRatherThanReopeningTheDefault(t *testing.T) {
	_, h := newServer(t)

	opened := get(t, h, "/packages/example/adr-writer?file=SKILL.md").Body.String()
	require.Contains(t, opened, `aria-label="File content"`)
	require.Contains(t, opened, `class="am-audit-panel-close" aria-label="Close" href="/packages/example/adr-writer"`)

	closed := get(t, h, "/packages/example/adr-writer").Body.String()
	require.NotContains(t, closed, `aria-label="File content"`,
		"following the close link's own href must not reopen the panel on the default file")
}

func TestFilesPanelNamesAStalePathAsMissingRatherThanAsAnEmptyPanel(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/packages/example/adr-writer?file=no-such-file.md").Body.String()

	require.Contains(t, body, `id="file-missing"`)
}

func TestFilesPanelIsHonestlyEmptyForAPackageWithNoFiles(t *testing.T) {
	api, h := newServer(t)
	api.Data.Files["community/release-toolkit"] = apiclient.PackageFileList{Files: []apiclient.PackageFile{}}
	body := get(t, h, "/packages/community/release-toolkit").Body.String()

	require.Contains(t, body, `id="files-empty"`)
}

// The viewer tests below render components directly: going through the router
// would test how the handler resolves a viewer rather than what the shell does
// with it.

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
		viewer := signedInViewer()
		body := shellBody(t, viewer, screen)

		require.Contains(t, body, viewer.DisplayName)
		require.Contains(t, body, `<div class="am-avatar">AF</div>`,
			"the avatar must be derived from the resolved name, not carried beside it")
		require.Contains(t, body, "Catalog admin", "the chip's role is the resolved role, humanised")
	})

	t.Run("a viewer holding no role is labelled as holding none rather than left blank", func(t *testing.T) {
		body := shellBody(t, unmappedViewer(), screen)
		require.Contains(t, body, `<div class="am-viewer-role">No role</div>`)
	})

	t.Run("signed out renders no chip at all — no placeholder, no initials, no Guest", func(t *testing.T) {
		body := shellBody(t, signedOutViewer(), screen)

		for _, forbidden := range []string{"am-avatar", "am-viewer-id", "am-viewer-name", "am-viewer-role"} {
			require.NotContainsf(t, body, forbidden, "the signed-out shell rendered %q", forbidden)
		}
		require.NotContains(t, body, "Guest")
		require.Contains(t, body, "am-theme-toggle")
	})

	t.Run("sign-out is offered to a viewer and is a POST form rather than a link", func(t *testing.T) {
		signedIn := shellBody(t, signedInViewer(), screen)
		require.Contains(t, signedIn, `<form method="post" action="/auth/logout">`)
		require.NotContains(t, signedIn, `href="/auth/logout"`,
			"a GET sign-out is triggerable by any image tag on any page")

		require.NotContains(t, shellBody(t, signedOutViewer(), screen), "/auth/logout",
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

	// The hub holds no passwords and owns no accounts.
	t.Run("it holds no password field and no way to create an account", func(t *testing.T) {
		require.NotContains(t, body, `type="password"`)
		require.NotContains(t, body, `name="password"`)

		// The only form is the theme toggle.
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

// A hint that appears because a list happened to be populated would appear in
// production; only the explicit flag may switch it on.
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

func TestTheNoRoleStateSaysSoRatherThanRenderingAnEmptyHub(t *testing.T) {
	viewer := unmappedViewer()
	body := shellBody(t, viewer, components.NoRoleScreen(view.NoRole{Viewer: *viewer, Groups: viewer.Groups}))

	require.Contains(t, body, `id="no-mapped-role"`)
	require.Contains(t, body, viewer.Email, "they are signed in, and as whom is what they have to quote")
	require.Contains(t, body, "contractors-eu", "the groups are what they have to ask about")
	require.Contains(t, body, "This is not an empty hub")

	// Must not be mistakable for an empty hub.
	require.NotContains(t, body, `id="catalog-signed-out"`)
	require.NotContains(t, body, "am-empty")

	t.Run("a viewer whose provider sent no groups is told that specifically", func(t *testing.T) {
		bare := view.Viewer{DisplayName: "No Groups", Email: "none@fixture.invalid"}
		body := shellBody(t, &bare, components.NoRoleScreen(view.NoRole{Viewer: bare, Groups: bare.Groups}))
		require.Contains(t, body, "sent no group membership")
		require.NotContains(t, body, "am-tagrow", "there is nothing to list")
	})
}
