package web_test

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// WCAG AA contrast, both themes. Reads assets/input.css rather than a copy of the
// palette, so editing the real one can't leave the test passing. 4.5:1 is applied
// throughout so the test does not depend on the type scale.
const aa = 4.5

// surfaces are every background a token's text can land on. --bd is not one: it
// is a border colour and never a text background.
var surfaces = []string{"bg", "surface", "surface2", "sel"}

func TestPaletteMeetsWCAGAA(t *testing.T) {
	light, dark := palettes(t)

	for _, theme := range []struct {
		name   string
		tokens map[string]string
	}{
		{"light", light},
		{"dark", dark},
	} {
		t.Run(theme.name, func(t *testing.T) {
			for _, fg := range []string{"fg", "fg2", "fg3"} {
				for _, bg := range surfaces {
					got := contrast(t, theme.tokens[fg], theme.tokens[bg])
					require.GreaterOrEqualf(t, got, aa,
						"--%s (%s) on --%s (%s) is %.2f:1, below AA's %.1f:1",
						fg, theme.tokens[fg], bg, theme.tokens[bg], got, aa)
				}
			}

			// A pill is `background: var(--Xbg); color: var(--X)`.
			for _, pair := range [][2]string{{"ok", "okbg"}, {"warn", "warnbg"}, {"dan", "danbg"}} {
				got := contrast(t, theme.tokens[pair[0]], theme.tokens[pair[1]])
				require.GreaterOrEqualf(t, got, aa,
					"--%s (%s) on --%s (%s) is %.2f:1, below AA's %.1f:1",
					pair[0], theme.tokens[pair[0]], pair[1], theme.tokens[pair[1]], got, aa)
			}
		})
	}
}

// TestAStatusColourIsReadableOnEveryPlainSurfaceItIsPaintedOn covers status
// colours painted as text on untinted surfaces. --sel is excluded on purpose:
// --ok and --warn fall under AA on it in the light theme, so a status colour must
// never be painted directly on a selection.
func TestAStatusColourIsReadableOnEveryPlainSurfaceItIsPaintedOn(t *testing.T) {
	light, dark := palettes(t)

	plain := []string{"bg", "surface", "surface2"}

	for name, tokens := range map[string]map[string]string{"light": light, "dark": dark} {
		t.Run(name, func(t *testing.T) {
			for _, status := range []string{"ok", "warn", "dan"} {
				for _, bg := range plain {
					got := contrast(t, tokens[status], tokens[bg])
					require.GreaterOrEqualf(t, got, aa,
						"--%s (%s) on --%s (%s) is %.2f:1, below AA's %.1f:1",
						status, tokens[status], bg, tokens[bg], got, aa)
				}
			}
		})
	}
}

// TestEveryColourInTheStylesheetComesFromThePalette puts every screen in the
// contrast sweep by construction: text and background colours must name a custom
// property, and literals belong only in the :root token blocks. Shadows and the
// modal's translucent scrim are out of scope.
func TestEveryColourInTheStylesheetComesFromThePalette(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "assets", "input.css"))
	require.NoError(t, err)

	css := string(raw)
	for _, block := range []*regexp.Regexp{rootRE, darkRE} {
		if found := block.FindString(css); found != "" {
			css = strings.Replace(css, found, "", 1)
		}
	}

	declarations := regexp.MustCompile(`(?m)^\s*(color|background|background-color|border-color)\s*:\s*([^;]+);`)
	checked := 0
	for _, declaration := range declarations.FindAllStringSubmatch(css, -1) {
		value := strings.TrimSpace(declaration[2])
		switch value {
		case "none", "transparent", "inherit", "currentColor", "0 0":
			continue
		}
		checked++
		require.Containsf(t, value, "var(--",
			"`%s: %s` is a colour this stylesheet chose rather than one from the palette, "+
				"so no contrast assertion in this file covers it", declaration[1], value)
	}
	require.Greater(t, checked, 40, "the stylesheet was not read")
}

// TestTheTextRampStaysARamp: meeting AA by collapsing --fg3 onto --fg2 would pass
// the tests above and destroy the name/id hierarchy.
func TestTheTextRampStaysARamp(t *testing.T) {
	light, dark := palettes(t)

	for name, tokens := range map[string]map[string]string{"light": light, "dark": dark} {
		t.Run(name, func(t *testing.T) {
			var previous float64
			for i, token := range []string{"fg", "fg2", "fg3"} {
				got := contrast(t, tokens[token], tokens["surface"])
				if i > 0 {
					require.Lessf(t, got, previous,
						"--%s must read lighter than the token before it", token)
				}
				previous = got
			}
		})
	}
}

var (
	rootRE  = regexp.MustCompile(`(?s):root\s*\{(.*?)\}`)
	darkRE  = regexp.MustCompile(`(?s):root\[data-sm-theme="dark"\]\s*\{(.*?)\}`)
	tokenRE = regexp.MustCompile(`--([a-z0-9]+):\s*(#[0-9a-fA-F]{6})`)
)

func palettes(t *testing.T) (light, dark map[string]string) {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "assets", "input.css"))
	require.NoError(t, err, "assets/input.css is the palette; this test is meaningless without it")

	css := string(raw)
	dark = tokens(t, darkRE, css, "dark")
	// The dark selector also matches rootRE, so cut it out first.
	light = tokens(t, rootRE, strings.Replace(css, darkRE.FindString(css), "", 1), "light")

	for _, want := range append(append([]string{}, surfaces...), "fg", "fg2", "fg3", "ok", "okbg", "warn", "warnbg", "dan", "danbg") {
		require.Containsf(t, light, want, "light palette is missing --%s", want)
		require.Containsf(t, dark, want, "dark palette is missing --%s", want)
	}
	return light, dark
}

func tokens(t *testing.T, re *regexp.Regexp, css, which string) map[string]string {
	t.Helper()

	block := re.FindStringSubmatch(css)
	require.Lenf(t, block, 2, "could not find the %s token block in assets/input.css", which)

	found := map[string]string{}
	for _, m := range tokenRE.FindAllStringSubmatch(block[1], -1) {
		found[m[1]] = strings.ToLower(m[2])
	}
	require.NotEmptyf(t, found, "%s token block parsed but held no colours", which)
	return found
}

// contrast is the WCAG 2.x ratio: (Llighter + 0.05) / (Ldarker + 0.05).
func contrast(t *testing.T, a, b string) float64 {
	t.Helper()

	la, lb := luminance(t, a), luminance(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func luminance(t *testing.T, hex string) float64 {
	t.Helper()

	require.Len(t, hex, 7, "expected #rrggbb, got %q", hex)
	channel := func(offset int) float64 {
		v, err := strconv.ParseUint(hex[offset:offset+2], 16, 8)
		require.NoError(t, err, fmt.Sprintf("parse %q", hex))

		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(1) + 0.7152*channel(3) + 0.0722*channel(5)
}
