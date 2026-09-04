package web_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/view"
)

// T051 — FR-116 and SC-106: no identity is compiled into this product.
//
// The defect this replaces was three strings in shell.templ: an avatar reading
// "KW", a name reading "Krzysztof W." and a role reading "Platform · Admin", on
// every page, for every visitor, verified by nothing. The obvious test is a grep
// for those three strings, and it is worthless: it passes the moment somebody
// writes a fourth name somewhere else, which is the same defect and the same
// afternoon's work.
//
// So the property asserted here is the general one — every person-shaped and
// every address-shaped thing this product renders is a value the caller handed in
// — and it is asserted three ways, because each way has a hole the next one
// covers:
//
//  1. Rendered, signed out. Every screen, with no viewer. Nothing that looks like
//     a person or an address may appear at all, and the chip's classes must be
//     absent rather than empty. This is the state a compiled-in identity is
//     visible in, and it needs no knowledge of where the literal lives.
//  2. Rendered, signed in. Every screen, with a viewer whose every field is a
//     sentinel. Every person-shaped and address-shaped fragment on the page must
//     be one of those sentinels or one of its derivations. A fourth hard-coded
//     name in a panel nobody thought about is caught here: it is person-shaped
//     text that is not the sentinel.
//  3. Lexical, over the source. The two above only see states a test enters. A
//     name behind a branch this file does not reach is invisible to them and is
//     still compiled in, so the source is scanned too.
//
// internal/web/fixture is excluded from (3) by name, and that exclusion is the
// point rather than a convenience: SC-106 makes a display name in the product a
// defect and the same display name in a test's input a fixture. The exclusion is
// what gives the fixture package its meaning, and it is why the two viewer
// variants live there and nowhere else.

// The two shapes. Neither is clever, and both are checked against known values
// below so a regexp edit cannot quietly stop matching anything.
var (
	// personShaped is "Firstname Lastname" or "Firstname L." — two adjacent
	// capitalised words, the second optionally an initial. It is unanchored, so it
	// catches a name inside a sentence, which is where the second one gets written.
	personShaped = regexp.MustCompile(`\p{Lu}\p{Ll}+ \p{Lu}(?:\p{Ll}+|\.)`)
	// addressShaped is deliberately loose about the domain: what matters is that
	// somebody's address is on the page, not whether it would deliver.
	addressShaped = regexp.MustCompile(`[\p{L}0-9._%+\-]+@[\p{L}0-9.\-]+\.[\p{L}]{2,}`)
)

// productVocabulary is every pair of capitalised words this product renders that
// is not a person. Each is the name of the product or of a specification it
// implements, which is exactly why a reader cannot tell them apart from a name by
// shape alone and a test has to be told.
//
// Adding to this list is how a compiled-in identity would get past every
// assertion in this file, so an entry needs a reason a reviewer would accept:
// these three are a product name and two published specification names, and none
// of them is a claim about who is looking at the page.
var productVocabulary = []string{
	components.ProductName,
	"Agent Plugins",
	"Agent Skills",
	// The agent directory convention a sync target writes to, not a claim about
	// who is looking at the page.
	"Claude Code",
}

// identityClasses are the design's three identity elements. They are asserted on
// as well as the text, because "the chip renders with an empty name" and "the chip
// does not render" are different pages and only one of them is honest (FR-116,
// contracts/auth.md's signed-out contract).
var identityClasses = []string{"am-avatar", "am-viewer-name", "am-viewer-role"}

// The sentinel viewer. Its values are shaped like the things being hunted — a
// two-word name, an address, a hyphenated role the shell humanises into a second
// two-word string — so that they are found by the same patterns the defect would
// be, and the assertion is about WHICH match was found rather than whether one was.
func sentinelViewer() *view.Viewer {
	return &view.Viewer{
		DisplayName: "Sentinel Viewername",
		Email:       "sentinel@viewer.invalid",
		Role:        "sentinel-role",
		HasRole:     true,
		Groups:      []string{"sentinel-group"},
	}
}

func sentinelValues(v *view.Viewer) []string {
	return []string{v.DisplayName, v.Email, v.RoleLabel(), v.Initials()}
}

// sweptScreen is one component rendered in both viewer states.
type sweptScreen struct {
	name string
	// hostsShell is false for a component that is its own document or a fragment
	// patched into one, so the chip is not expected in it even signed in.
	hostsShell bool
	render     func(t *testing.T, viewer *view.Viewer) string
}

func sweep() []sweptScreen {
	// No package data anywhere in this list. A package's own title-cased display
	// name — "Platform Toolkit", "Slack Digest" — is indistinguishable from a
	// person's by shape, and it arrives from a source rather than from this
	// package, so feeding the fixture's ten rows in would mean weakening the
	// patterns to accommodate data that was never the risk. What is swept is the
	// chrome, in every state, which is where an identity gets written.
	emptyPage := view.CatalogPage{Query: view.CatalogQuery{}.Normalise(), Page: 1, PageSize: view.DefaultPageSize}

	inShell := func(name string, body func() templ.Component) sweptScreen {
		return sweptScreen{name: name, hostsShell: true, render: func(t *testing.T, viewer *view.Viewer) string {
			return shellBody(t, viewer, body())
		}}
	}

	return []sweptScreen{
		inShell("Placeholder", func() templ.Component {
			return components.Placeholder("Organization", "Identity provider, group-to-role mapping and policy.")
		}),
		inShell("CatalogScreen", func() templ.Component {
			return components.CatalogScreen(components.Catalog{Page: emptyPage})
		}),
		inShell("CatalogTable", func() templ.Component { return components.CatalogTable(emptyPage) }),
		inShell("CatalogCount", func() templ.Component { return components.CatalogCount(emptyPage) }),
		inShell("FacetOptions", func() templ.Component {
			return components.FacetOptions(components.Facet{Name: "tag", Label: "Tags"})
		}),
		inShell("ImportModal", func() templ.Component { return components.ImportModal(components.Import{}) }),
		inShell("ImportPreviewPanel", func() templ.Component { return components.ImportPreviewPanel(nil) }),
		inShell("ImportResultBanner", func() templ.Component { return components.ImportResultBanner(nil) }),
		inShell("PackageScreen", func() templ.Component { return components.PackageScreen(view.Package{}) }),
		inShell("CapabilityPanel", func() templ.Component { return components.CapabilityPanel(view.Capabilities{}) }),
		inShell("VersionsPanel", func() templ.Component { return components.VersionsPanel(view.Package{}) }),
		inShell("DependentsPanel", func() templ.Component { return components.DependentsPanel(view.Package{}) }),
		// The two governance screens (US4). They are swept EMPTY on purpose: the
		// actor column of an audit row and the reviewer on an override are both
		// person-shaped by nature and both arrive from a source, so feeding rows in
		// would mean weakening the patterns to accommodate data that was never the
		// risk. What is swept is the chrome — the copy, the empty states and the
		// refusal wording — which is where a name gets written by hand.
		inShell("ScannerScreen", func() templ.Component { return components.ScannerScreen(view.Scanner{}) }),
		inShell("AuditScreen", func() templ.Component { return components.AuditScreen(view.Audit{}) }),
		// The profile screens, swept empty for the same reason: a member's display
		// name and a revision's publisher are both person-shaped by nature and both
		// arrive from a source, so feeding rows in would weaken the patterns to
		// accommodate data that was never the risk.
		inShell("ProfilesScreen", func() templ.Component { return components.ProfilesScreen(view.Profiles{}) }),
		inShell("ProfileScreen", func() templ.Component { return components.ProfileScreen(view.Profile{}) }),
		// The Connect-the-CLI screen (US6). Swept empty for the same reason: the
		// requesting host is machine-shaped data from a source, not chrome, so the
		// pattern is checked against the copy around it and not against a fixture host.
		inShell("CLIScreen", func() templ.Component { return components.CLIScreen(view.CLI{}) }),
		{
			name: "NoRoleScreen",
			// The one screen whose body renders the viewer itself. Signed out there is
			// no such screen — an unmapped role is something only a signed-in identity
			// can have — so that state is swept as the shell around an ordinary screen.
			hostsShell: true,
			render: func(t *testing.T, viewer *view.Viewer) string {
				if viewer == nil {
					return shellBody(t, nil, components.Placeholder("Catalog", "Nothing to show."))
				}
				return shellBody(t, viewer, components.NoRoleScreen(view.NoRole{Viewer: *viewer, Groups: viewer.Groups}))
			},
		},
		{
			name: "SignInScreen",
			// Its own document, so it carries no chip in either state — and it is swept
			// with the credential hint OFF, which is how it is served. The credentials
			// the hint prints are the caller's data rather than this package's
			// literals, and the state that prints them has its own test next door.
			render: func(t *testing.T, _ *view.Viewer) string {
				return signInBody(t, view.SignIn{
					Provider: "the corporate directory", Return: "/scanner",
				})
			},
		},
	}
}

func TestNoScreenRendersAnIdentityWhenNoSessionResolvedOne(t *testing.T) {
	for _, screen := range sweep() {
		t.Run(screen.name, func(t *testing.T) {
			body := screen.render(t, fixture.SignedOutViewer())

			for _, class := range identityClasses {
				require.NotContainsf(t, body, class,
					"%s renders %q with no viewer. A chip with empty fields is the compiled-in "+
						"chip with its literals deleted: still an identity the page asserts and "+
						"nothing verified", screen.name, class)
			}
			require.NotContains(t, body, "Guest")

			for _, chunk := range renderedText(t, body) {
				requireNoIdentityIn(t, screen.name+" (signed out)", chunk, nil)
			}
		})
	}
}

func TestEveryIdentityAScreenRendersIsTheViewersOwn(t *testing.T) {
	viewer := sentinelViewer()
	allowed := sentinelValues(viewer)

	var chipsSeen int
	for _, screen := range sweep() {
		t.Run(screen.name, func(t *testing.T) {
			body := screen.render(t, viewer)

			for _, chunk := range renderedText(t, body) {
				requireNoIdentityIn(t, screen.name, chunk, allowed)
			}

			if screen.hostsShell {
				chipsSeen++
				require.Contains(t, body, viewer.DisplayName,
					"the shell did not render the viewer it was given, so this sweep is passing "+
						"over a page with no identity on it at all")
				require.Contains(t, body, `<div class="am-avatar">`+viewer.Initials()+`</div>`)
				require.Contains(t, body, `<div class="am-viewer-role">`+viewer.RoleLabel()+`</div>`)
			}
		})
	}
	require.Positive(t, chipsSeen, "no screen in the sweep hosts the shell")
}

// TestEveryComponentIsInTheIdentitySweep is the anti-omission half. Both sweeps
// above walk a list written by hand, and a list written by hand is a list a new
// screen is not on — which is how the next compiled-in name would arrive with
// every test still green. So the list is checked against the components package
// itself: every exported templ in it is either swept or named below with a reason.
func TestEveryComponentIsInTheIdentitySweep(t *testing.T) {
	// Layout is the shell the sweep renders everything else inside, so it is
	// covered by every entry rather than by one of its own.
	notScreens := map[string]string{"Layout": "the shell every swept screen is rendered in"}

	swept := map[string]bool{}
	for _, screen := range sweep() {
		swept[screen.name] = true
	}

	declared := exportedComponents(t)
	require.Greater(t, len(declared), 10, "the components package was not read")

	for _, name := range declared {
		if _, excused := notScreens[name]; excused {
			continue
		}
		require.Truef(t, swept[name],
			"components.%s is not in the identity sweep. Add it to sweep(), or to notScreens "+
				"with the reason it cannot render an identity — an unswept component is where "+
				"the next hard-coded name lives without failing anything", name)
	}
}

var exportedTemplPattern = regexp.MustCompile(`(?m)^templ ([A-Z]\w*)\(`)

func exportedComponents(t *testing.T) []string {
	t.Helper()

	files, err := filepath.Glob(filepath.Join("components", "*.templ"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	var names []string
	for _, file := range files {
		raw, err := os.ReadFile(file)
		require.NoError(t, err)
		for _, match := range exportedTemplPattern.FindAllStringSubmatch(string(raw), -1) {
			names = append(names, match[1])
		}
	}
	return names
}

// TestTheIdentityPatternsCatchTheDefectTheyWereWrittenFor is the guard against
// the sweeps above passing because the patterns stopped matching. The first value
// is the string that was in shell.templ; the rest are the ones a grep for it would
// have let through.
func TestTheIdentityPatternsCatchTheDefectTheyWereWrittenFor(t *testing.T) {
	for _, name := range []string{"Krzysztof W.", "Ada Lovelace", "shared with Jane Roe today", "Sentinel Viewername"} {
		require.Regexpf(t, personShaped, name, "%q is no longer recognised as a person's name", name)
	}
	for _, address := range []string{"kwiatrzyk@example.com", "a.b+c@sub.example.co.uk"} {
		require.Regexpf(t, addressShaped, address, "%q is no longer recognised as an address", address)
	}

	// And the negatives, because a pattern that matches the product's own copy gets
	// weakened by whoever hits it next, and a weakened pattern is worse than none.
	for _, copy := range []string{
		"Connect the CLI", "Audit log", "Not found", "No role", "Sign out",
		"Nothing matches these filters. Clear a tag or widen the category.",
	} {
		require.NotRegexpf(t, personShaped, copy, "%q reads as a person's name", copy)
	}
}

// requireNoIdentityIn is the rule both rendered sweeps apply to one text node.
func requireNoIdentityIn(t *testing.T, where, chunk string, allowed []string) {
	t.Helper()

	for _, pattern := range []*regexp.Regexp{personShaped, addressShaped} {
		for _, found := range pattern.FindAllString(chunk, -1) {
			if permitted(found, allowed) {
				continue
			}
			require.Failf(t, "an identity nothing resolved reached the page",
				"%s renders %q, in %q.\n\n"+
					"Every name, address, role and avatar on a page must come from the viewer the "+
					"request resolved (FR-116). A literal here is the hard-coded chip this feature "+
					"exists to delete, in a new place. If this is a product or specification name "+
					"rather than a person, it belongs in productVocabulary with the reason.",
				where, found, chunk)
		}
	}
}

func permitted(found string, allowed []string) bool {
	for _, value := range append(productVocabulary, allowed...) {
		if value != "" && strings.Contains(value, found) {
			return true
		}
	}
	return false
}

// renderedText is the page's text nodes, each kept separate.
//
// Separate matters: joining them would put the end of one element beside the start
// of the next and invent "Storage Organization" out of two sidebar links. Attribute
// values are dropped, which is a hole the source scan below covers — this half is
// about what a person reads.
func renderedText(t *testing.T, body string) []string {
	t.Helper()

	require.NotEmpty(t, body, "nothing was rendered")

	// Script and style bodies are not text a person reads, and the vendored
	// datastar bundle is not on the page anyway — only a src for it.
	for _, tag := range []string{"script", "style"} {
		body = regexp.MustCompile(`(?s)<`+tag+`[^>]*>.*?</`+tag+`>`).ReplaceAllString(body, "")
	}
	return textChunks(body)
}

// textChunks splits HTML-ish source on its tags and returns the whitespace-collapsed
// text between them. It is shared with the .templ scan, where the same split
// isolates a template's literal text from its markup and its Go expressions.
func textChunks(markup string) []string {
	var out []string
	for _, piece := range regexp.MustCompile(`<[^>]*>`).Split(markup, -1) {
		text := strings.Join(strings.Fields(html.UnescapeString(piece)), " ")
		if text != "" {
			out = append(out, text)
		}
	}
	return out
}

// TestNoIdentityLiteralIsCompiledIntoTheWebRole is the third pass: the source
// itself, for the name that is only rendered in a state no test enters.
//
// String literals and template text, not whole files. A comment naming a person is
// a different thing from a page rendering one — the reference to
// internal/seed/groups.go's directory users two files away is a comment that has to
// name them — and scanning comments here would either fail on those or teach
// whoever hits it to delete the explanation.
func TestNoIdentityLiteralIsCompiledIntoTheWebRole(t *testing.T) {
	files := webSourceFiles(t)
	require.Contains(t, files, filepath.Join("components", "shell.templ"),
		"the file the defect was in is not being scanned")
	require.Greater(t, len(files), 15)

	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			for _, literal := range literalsIn(t, filepath.Join(".", name)) {
				requireNoIdentityIn(t, name, literal, nil)
			}
		})
	}
}

// webSourceFiles is every non-test source file under internal/web, read from the
// tree rather than from a list so a file added later is scanned without anybody
// remembering to add it here.
//
// Two exclusions, both deliberate. internal/web/fixture is the declared stand-in
// and holds the viewer variants the tests render with. `*_templ.go` is generated
// from the `.templ` file beside it, which IS scanned: reading both would double
// every finding and report the generated line number.
func webSourceFiles(t *testing.T) []string {
	t.Helper()

	var names []string
	require.NoError(t, filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "fixture" || entry.Name() == "static" {
				return fs.SkipDir
			}
			return nil
		}
		name := entry.Name()
		switch {
		case strings.HasSuffix(name, "_test.go"), strings.HasSuffix(name, "_templ.go"):
			return nil
		case strings.HasSuffix(name, ".go"), strings.HasSuffix(name, ".templ"):
			names = append(names, path)
		}
		return nil
	}))
	return names
}

func literalsIn(t *testing.T, name string) []string {
	t.Helper()

	raw, err := os.ReadFile(name)
	require.NoError(t, err)

	if strings.HasSuffix(name, ".templ") {
		return textChunks(string(raw))
	}

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, name, raw, parser.SkipObjectResolution)
	require.NoError(t, err)

	var out []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if value, err := strconv.Unquote(lit.Value); err == nil {
			out = append(out, value)
		}
		return true
	})
	return out
}
