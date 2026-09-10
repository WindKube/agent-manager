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

// The main column has no padding, so a screen whose content is not inside a
// wrapper that carries the page gutter renders flush against both window edges.
// That is how Connect the CLI shipped: its form and cards were direct children
// of am-main, so the lookup button sat against the right edge of the window.
func TestEveryScreenSitsInsideThePageGutter(t *testing.T) {
	gutter := gutterClasses(t)
	handler := handler(t, fixture.New())

	for _, path := range []string{"/catalog", "/scanner", "/profiles", "/storage", "/org", "/cli", "/audit"} {
		t.Run(path, func(t *testing.T) {
			body := get(t, handler, path).Body.String()

			found := ""
			for _, attr := range classAttrPattern.FindAllStringSubmatch(body, -1) {
				for _, name := range strings.Fields(attr[1]) {
					// The header brings its own; it is not the screen's content.
					if name != "am-header" && gutter[name] {
						found = name
					}
				}
			}
			require.NotEmptyf(t, found,
				"nothing on %s carries the page gutter, so its content runs to the window edges", path)
		})
	}
}

// gutterClasses are the rules that inset a screen's content from the window by
// the page's side margin. Read out of the stylesheet rather than listed here, so
// a new wrapper counts the moment it carries the margin.
func gutterClasses(t *testing.T) map[string]bool {
	t.Helper()

	sheet, err := os.ReadFile("static/app.css")
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, rule := range rulePattern.FindAllStringSubmatch(string(sheet), -1) {
		for _, box := range boxPattern.FindAllStringSubmatch(rule[2], -1) {
			if strings.Contains(box[1], pageGutter) {
				names[rule[1]] = true
			}
		}
	}
	require.Truef(t, names["am-org"], "no rule was read as carrying the %s page gutter", pageGutter)
	return names
}

// pageGutter is the side margin every screen is inset by. It is a literal here
// because the point of the test is that screens agree on one value.
const pageGutter = "44px"

var (
	rulePattern     = regexp.MustCompile(`\.(am-[a-zA-Z0-9_-]+)\s*\{([^}]*)\}`)
	boxPattern      = regexp.MustCompile(`(?:padding|margin)\s*:\s*([^;}]+)`)
	minWidthPattern = regexp.MustCompile(`min-width\s*:\s*([^;}]+)`)
)

// The registration modal is 580px wide and lays its fields out in columns. A
// control that declares a minimum width wider than its column cannot shrink into
// it, so it paints over its neighbour and past the dialog's edge — which is what
// am-search's 240px toolbar minimum did to the publisher, category and
// visibility fields.
func TestNoControlInTheRegistrationModalDeclaresAMinimumWidth(t *testing.T) {
	minWidths := declaredMinWidths(t)

	source, err := os.ReadFile("components/import.templ")
	require.NoError(t, err)

	controls := controlClassPattern.FindAllStringSubmatch(string(source), -1)
	require.NotEmpty(t, controls, "no controls were read out of the modal, so this test is not checking anything")

	for _, control := range controls {
		classes := strings.Fields(control[1])
		t.Run(strings.Join(classes, " "), func(t *testing.T) {
			// Every one of these is a single class deep, so the last declaration
			// in the stylesheet is the one that applies.
			effective, from := "0px", "no rule"
			for _, name := range classes {
				if declared, ok := minWidths[name]; ok {
					effective, from = declared.value, name
				}
			}
			require.Equalf(t, "0px", effective,
				"%s declares min-width %s, so the control cannot shrink into a column of the dialog", from, effective)
		})
	}
}

type declaration struct {
	value string
	order int
}

// declaredMinWidths keeps the LAST min-width declared for each class, which for
// selectors one class deep is the one the cascade applies.
func declaredMinWidths(t *testing.T) map[string]declaration {
	t.Helper()

	sheet, err := os.ReadFile("static/app.css")
	require.NoError(t, err)

	out := make(map[string]declaration)
	for order, rule := range rulePattern.FindAllStringSubmatch(string(sheet), -1) {
		found := minWidthPattern.FindStringSubmatch(rule[2])
		if found == nil {
			continue
		}
		value := strings.TrimSpace(found[1])
		if value == "0" || value == "auto" {
			value = "0px"
		}
		if prior, seen := out[rule[1]]; !seen || order > prior.order {
			out[rule[1]] = declaration{value: value, order: order}
		}
	}
	require.Contains(t, out, "am-search", "am-search declares the minimum this test is about")
	return out
}

// controlClassPattern reads the class list off an input or a select in a templ
// source. Both spellings appear: an attribute on its own line, and one inline in
// a tag.
var controlClassPattern = regexp.MustCompile(`(?s)<(?:input|select)\b[^>]*?class="([^"]*)"`)
