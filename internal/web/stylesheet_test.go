package web_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/fixture"
)

// A class name in the markup with no rule behind it costs nothing at build time
// and nothing in any other test here: the element simply renders unstyled. That
// is how am-notice-ok shipped, and how the identity-provider card's connection
// banner came out as an unstyled box.
//
// This asserts that every am-* class written literally into a templ source has a
// rule in the stylesheet the pages actually load.

// unstyledHooks are am-* names deliberately carrying no rule. Each is a
// selector for something other than CSS, and each states what.
var unstyledHooks = map[string]string{
	// The registration modal's overlay is positioned and painted inline, because
	// it must be display:none before the script runs. The class is how
	// import_test.go finds the element.
	"am-import-backdrop": "test selector; the overlay is styled inline",
}

var (
	classAttrPattern = regexp.MustCompile(`class="([^"]*)"`)
	ruleNamePattern  = regexp.MustCompile(`\.(am-[a-zA-Z0-9_-]+)`)
)

func TestEveryClassInTheMarkupHasARuleInTheStylesheet(t *testing.T) {
	defined := definedClasses(t)

	sources, err := filepath.Glob("components/*.templ")
	require.NoError(t, err)
	require.NotEmpty(t, sources, "no templ sources found, so this test is not checking anything")

	for _, source := range sources {
		t.Run(filepath.Base(source), func(t *testing.T) {
			body, err := os.ReadFile(source)
			require.NoError(t, err)

			for _, attr := range classAttrPattern.FindAllStringSubmatch(string(body), -1) {
				for _, name := range strings.Fields(attr[1]) {
					if !strings.HasPrefix(name, "am-") {
						continue
					}
					if reason, hook := unstyledHooks[name]; hook {
						t.Logf("%s carries no rule on purpose: %s", name, reason)
						continue
					}
					require.Truef(t, defined[name],
						"%s is in the markup with no rule in static/app.css, so it renders unstyled", name)
				}
			}
		})
	}
}

// definedClasses reads the BUILT stylesheet rather than assets/input.css: what
// the pages load is the built one, and a rule Tailwind dropped is exactly the
// failure this test is for.
func definedClasses(t *testing.T) map[string]bool {
	t.Helper()

	sheet, err := os.ReadFile("static/app.css")
	require.NoError(t, err, "the built stylesheet is what the pages load; run `task gen:css`")

	names := make(map[string]bool)
	for _, match := range ruleNamePattern.FindAllStringSubmatch(string(sheet), -1) {
		names[match[1]] = true
	}
	require.Truef(t, names["am-page"], "no am-* rules were read out of the stylesheet")
	return names
}

// am-gov-card is the frame only, so content that does not bring its own gutter
// has to be wrapped. These are the cards where that was missing and the rows sat
// flush against the border: the key layout and bucket settings on Storage, the
// identity provider and policy cards on Organisation, and both cards on Connect
// the CLI.
func TestCardsWhoseContentNeedsAGutterHaveOne(t *testing.T) {
	handler := handler(t, fixture.New())

	for path, cards := range map[string]int{
		"/storage": 2,
		"/org":     2,
		"/cli":     1,
	} {
		t.Run(path, func(t *testing.T) {
			body := get(t, handler, path).Body.String()
			require.GreaterOrEqualf(t, strings.Count(body, `class="am-gov-body`), cards,
				"a card body on %s lost its gutter, so its rows render flush against the border", path)
		})
	}
}
