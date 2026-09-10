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

// SC-009: WCAG AA contrast, both themes.
//
// This reads assets/input.css rather than a copy of the hex values, because a
// test carrying its own palette would keep passing after someone edited the real
// one.
//
// AA is 4.5:1 for text below 18.66px bold / 24px regular, which is every use of
// --fg2 and --fg3 in this design (package ids, counts, badges, notes), and 3:1
// for larger text. The stricter number is applied throughout: nothing in the
// palette needs the concession, and applying it per-element would make the test
// depend on the type scale.
//
// This sweep is over the palette, not any one screen, so it covers all ten
// screens (catalog, package detail, scanner, audit, profiles list, profile
// detail, cli, org, storage, sign-in) by construction: every one of them paints
// with these tokens and nothing else, which is what
// TestEveryColourInTheStylesheetComesFromThePalette enforces below.
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

			// The badge pairs: a pill is `background: var(--Xbg); color: var(--X)`,
			// so each status colour is only ever read on its own tinted background.
			for _, pair := range [][2]string{{"ok", "okbg"}, {"warn", "warnbg"}, {"dan", "danbg"}} {
				got := contrast(t, theme.tokens[pair[0]], theme.tokens[pair[1]])
				require.GreaterOrEqualf(t, got, aa,
					"--%s (%s) on --%s (%s) is %.2f:1, below AA's %.1f:1",
					pair[0], theme.tokens[pair[0]], pair[1], theme.tokens[pair[1]], got, aa)
			}
		})
	}
}

// TestAStatusColourIsReadableOnEveryPlainSurfaceItIsPaintedOn extends the sweep
// to the pairs US4's two screens introduced.
//
// The governance screens paint --ok, --warn and --dan as TEXT on an untinted card
// as well as inside a tinted pill: the headline figures are coloured numbers on
// --surface, and the check matrix's glyphs are coloured marks on the same. The
// sweep above only ever checked each status colour against its own tinted
// background, so those pairs were outside it until now.
//
// --sel is not in this list, and its absence is the finding rather than an
// oversight: --ok reaches 4.44:1 and --warn 4.32:1 on --sel in the light theme,
// both under AA. That is why the selected row on the Scanner screen tints only the
// row and every status on it carries its own background — a status colour must
// never be painted directly on a selection.
func TestAStatusColourIsReadableOnEveryPlainSurfaceItIsPaintedOn(t *testing.T) {
	light, dark := palettes(t)

	// The three surfaces a coloured figure or glyph actually lands on. --sel is
	// excluded deliberately; see this test's comment.
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

// TestEveryColourInTheStylesheetComesFromThePalette is what puts a screen in the
// sweep by construction rather than by somebody remembering to add it.
//
// The two tests above prove the PALETTE meets AA. They say nothing about a rule
// that reaches past the palette for a literal, and a screen painted with one is
// outside every assertion in this file while still looking finished. So the
// declarations that carry text and background colour are required to name a
// custom property; the tokens themselves, defined in the two :root blocks, are the
// only place a literal belongs.
//
// Shadows and overlays are not in scope: a box-shadow is not a text pair, and the
// modal's scrim is deliberately a translucent literal.
func TestEveryColourInTheStylesheetComesFromThePalette(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "assets", "input.css"))
	require.NoError(t, err)

	css := string(raw)
	// The token blocks are where the literals live. Cut them out and every
	// remaining colour declaration must be a var().
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

// TestTheTextRampStaysARamp guards the reason --fg3 exists. Meeting AA by
// collapsing it onto --fg2 would pass the test above and destroy the hierarchy
// the design uses to separate a package name from its id.
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

// palettes reads the two token blocks out of the real stylesheet.
func palettes(t *testing.T) (light, dark map[string]string) {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "assets", "input.css"))
	require.NoError(t, err, "assets/input.css is the palette; this test is meaningless without it")

	css := string(raw)
	dark = tokens(t, darkRE, css, "dark")
	// The dark block's selector contains ":root", so it also matches rootRE. Cut
	// it out before looking for the light block.
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
