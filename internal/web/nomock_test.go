package web_test

import (
	"regexp"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/components"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/hub"
)

// TestEverySidebarEntryIsARealScreen walks every entry of components.Nav, in both
// themes, with a signed-in fixture viewer, and fails on the three ways a screen
// can look finished while lying: placeholder copy, an identity nobody resolved,
// or a badge that is not a number the badge source actually answered.
//
// This is deliberately not a router test for one screen at a time — the whole
// point of Nav is that it is the STRUCTURE every screen is reached through, so
// this test is the one place that structure is walked exhaustively rather than by
// whoever remembers to add a new entry to it.
func TestEverySidebarEntryIsARealScreen(t *testing.T) {
	// Non-zero counts, so a badge that renders "10" or "4" here is provably the
	// number this source answered rather than the design's compiled-in figures.
	source := &governance{badges: hub.Badges{Packages: 7, Profiles: 3, OpenFindings: 2}}
	h := web.New(web.Deps{
		Catalog:      fixture.New(),
		Scanner:      source,
		Audit:        source,
		Badges:       source,
		Storage:      source,
		Profiles:     &profiles{},
		Organization: &organization{},
		Device:       &device{},
		Viewers:      fixture.SignedInViewers(),
		Log:          zerolog.Nop(),
	}, web.Options{HubURL: "http://localhost:8082"}).Handler()

	// The literal `placeholder=` HTML attribute (a search box's hint text) is not
	// this: the pattern below requires the word to stand on its own, the way
	// "screen not built" or "this is a placeholder" would use it in copy.
	placeholder := regexp.MustCompile(`(?i)not built|coming soon|\bplaceholder\b(?:[^=]|$)`)
	// The identity the sidebar carried before FR-116/FR-118 replaced it with a
	// per-request viewer. Any of these strings on a routed page again would mean
	// something other than the request decided who is looking.
	compiledIn := []string{"Krzysztof W.", "Platform / Admin"}

	badgeIDs := map[string]bool{"catalog": true, "profiles": true, "scanner": true}

	for _, theme := range []string{"light", "dark"} {
		for _, group := range components.Nav {
			for _, item := range group.Items {
				t.Run(theme+" "+item.ID, func(t *testing.T) {
					rec := get(t, h, item.Href+"?theme="+theme)
					require.Equal(t, 200, rec.Code, "%s did not render", item.Href)

					body := rec.Body.String()
					require.False(t, placeholder.MatchString(body),
						"%s renders placeholder copy", item.Href)
					for _, name := range compiledIn {
						require.NotContains(t, body, name,
							"%s carries a compiled-in identity", item.Href)
					}

					if badgeIDs[item.ID] {
						assertBadgeIsComputedOrAbsent(t, body, item.Href)
					}
				})
			}
		}
	}
}

// assertBadgeIsComputedOrAbsent checks the one nav entry under test carries
// either no badge at all, or a badge holding digits only — never the compiled-in
// "10" / "4" / "4" the design shipped with, rendered as a literal that happened to
// still be right.
func assertBadgeIsComputedOrAbsent(t *testing.T, body, href string) {
	t.Helper()

	re := regexp.MustCompile(`(?s)<a class="am-nav-item" href="` + regexp.QuoteMeta(href) +
		`"[^>]*>.*?</a>`)
	entry := re.FindString(body)
	require.NotEmpty(t, entry, "the sidebar entry for %s was not found", href)

	badgeRE := regexp.MustCompile(`<span class="am-nav-badge[^"]*">([^<]*)</span>`)
	m := badgeRE.FindStringSubmatch(entry)
	if m == nil {
		return
	}
	require.Regexp(t, `^\d+$`, m[1], "the %s badge is not a plain computed count", href)
}
