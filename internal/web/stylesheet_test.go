package web_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A class with no rule behind it fails nowhere else: the element just renders
// unstyled. Every am-* class in a templ source must have a rule in the built sheet.

// unstyledHooks are am-* names deliberately carrying no rule.
var unstyledHooks = map[string]string{
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

// definedClasses reads the built stylesheet, not assets/input.css, because a rule
// Tailwind dropped is exactly the failure this test is for.
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

// am-gov-card is the frame only, so content without its own gutter must be wrapped
// in am-gov-body.
func TestCardsWhoseContentNeedsAGutterHaveOne(t *testing.T) {
	_, handler := newServer(t)

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
// gutter-carrying wrapper runs to both window edges. Detail routes are included
// because they lay out differently from list screens.
func TestEveryScreenSitsInsideThePageGutter(t *testing.T) {
	gutter := gutterClasses(t)
	_, handler := newServer(t)

	for _, path := range []string{
		"/catalog", "/scanner", "/profiles", "/storage", "/org", "/cli", "/audit", "/runtime",
		"/river",
		"/profiles/platform-engineer", "/packages/example/terraform-module-review",
	} {
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

// TestProfileDetailDescriptionSitsInsideTheGutter checks nesting, not mere
// presence: the page's am-card panels carry their own inset, so the sweep above
// passes even when the description sits outside any gutter wrapper.
func TestProfileDetailDescriptionSitsInsideTheGutter(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/profiles/platform-engineer").Body.String()

	wrapper := strings.Index(body, `class="am-screen-body"`)
	require.GreaterOrEqualf(t, wrapper, 0, "the profile detail screen has no am-screen-body wrapper")

	description := strings.Index(body, `class="am-section"`)
	require.Greaterf(t, description, -1, "the description section is missing from the seeded profile")
	require.Greaterf(t, description, wrapper,
		"the description sits outside am-screen-body, so it renders edge to edge against the window")
}

// gutterClasses reads the gutter-carrying rules out of the stylesheet, so a new
// wrapper counts the moment it carries the margin.
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

// pageGutter is a literal because the point is that every screen agrees on one value.
const pageGutter = "44px"

var (
	rulePattern     = regexp.MustCompile(`\.(am-[a-zA-Z0-9_-]+)\s*\{([^}]*)\}`)
	boxPattern      = regexp.MustCompile(`(?:padding|margin)\s*:\s*([^;}]+)`)
	minWidthPattern = regexp.MustCompile(`min-width\s*:\s*([^;}]+)`)
)

// The registration modal lays fields out in narrow columns; a control with a
// min-width wider than its column paints over its neighbour and past the dialog.
func TestNoControlInTheRegistrationModalDeclaresAMinimumWidth(t *testing.T) {
	minWidths := declaredMinWidths(t)

	source, err := os.ReadFile("components/import.templ")
	require.NoError(t, err)

	controls := controlClassPattern.FindAllStringSubmatch(string(source), -1)
	require.NotEmpty(t, controls, "no controls were read out of the modal, so this test is not checking anything")

	for _, control := range controls {
		classes := strings.Fields(control[1])
		t.Run(strings.Join(classes, " "), func(t *testing.T) {
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

var controlClassPattern = regexp.MustCompile(`(?s)<(?:input|select)\b[^>]*?class="([^"]*)"`)

// TestRuntimeQueuePanelsHaveAClosingGutterBeforeRunHistory: an .am-card has
// margin-top:0 by convention, so the element before it must close the gap. Reads
// assets/input.css because the rule is hand-authored, not a Tailwind utility.
func TestRuntimeQueuePanelsHaveAClosingGutterBeforeRunHistory(t *testing.T) {
	sheet, err := os.ReadFile("../../assets/input.css")
	require.NoError(t, err)

	var box []string
	for _, rule := range rulePattern.FindAllStringSubmatch(string(sheet), -1) {
		if rule[1] == "am-runtime-queues" {
			box = boxPattern.FindStringSubmatch(rule[2])
			break
		}
	}
	require.NotNil(t, box, "no padding or margin rule found for am-runtime-queues")

	require.NotEqualf(t, "0", paddingBottom(box[1]),
		"am-runtime-queues has no bottom padding, so it renders flush against the Run history "+
			"card below it, which supplies no top margin of its own")
}

// paddingBottom returns the bottom component of a CSS padding/margin shorthand.
func paddingBottom(value string) string {
	parts := strings.Fields(value)
	switch len(parts) {
	case 1, 2:
		return parts[0]
	default:
		return parts[2]
	}
}
