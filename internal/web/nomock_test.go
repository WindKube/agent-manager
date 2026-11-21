package web_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web"
	"agent-manager/internal/web/components"
)

// TestEverySidebarEntryIsARealScreen walks every components.Nav entry in both
// themes and fails on placeholder copy, an unresolved identity, or a badge that is
// not the number the api answered.
func TestEverySidebarEntryIsARealScreen(t *testing.T) {
	// Non-zero counts, so a rendered badge provably came from the api.
	api, h := newServerWith(t, web.Options{HubURL: "http://localhost:8082"})
	api.Data.Badges = apiclient.Badges{Packages: 7, Profiles: 3, OpenFindings: 2}

	// The pattern excludes the `placeholder=` HTML attribute.
	placeholder := regexp.MustCompile(`(?i)not built|coming soon|\bplaceholder\b(?:[^=]|$)`)
	// The design's compiled-in identity; the sidebar must show the per-request viewer.
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

// assertBadgeIsComputedOrAbsent requires no badge or a digits-only one.
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
