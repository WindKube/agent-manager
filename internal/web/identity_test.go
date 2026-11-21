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
	"agent-manager/internal/web/view"
)

// No identity is compiled into this product: every person-shaped or
// address-shaped thing rendered must come from the viewer the caller passed in.
// Asserted three ways (rendered signed out, rendered signed in with a sentinel
// viewer, and a lexical scan of the source), since each covers a hole in the
// others. Test files and fakeapi are excluded from the scan: there a name is a
// fixture, not a defect. Fixture addresses use `.invalid` (RFC 2606).

func signedInViewer() *view.Viewer {
	return &view.Viewer{
		SignedIn:    true,
		DisplayName: "Ada Fixture",
		Email:       "ada@fixture.invalid",
		Role:        "catalog-admin",
		HasRole:     true,
		Groups:      []string{"eng-platform", "eng-all"},
	}
}

// unmappedViewer is signed in and holds no role, which is neither signed out
// nor an empty hub.
func unmappedViewer() *view.Viewer {
	return &view.Viewer{
		SignedIn:    true,
		DisplayName: "Bo Fixture",
		Email:       "bo@fixture.invalid",
		Groups:      []string{"contractors-eu"},
	}
}

func signedOutViewer() *view.Viewer { return nil }

// Both patterns are checked against known values below so a regexp edit cannot
// quietly stop matching.
var (
	// personShaped is unanchored so it catches a name inside a sentence.
	personShaped  = regexp.MustCompile(`\p{Lu}\p{Ll}+ \p{Lu}(?:\p{Ll}+|\.)`)
	addressShaped = regexp.MustCompile(`[\p{L}0-9._%+\-]+@[\p{L}0-9.\-]+\.[\p{L}]{2,}`)
)

// productVocabulary is every capitalised word pair this product renders that is
// not a person. Adding to it is how a compiled-in identity would slip past every
// assertion here, so each entry needs a reason a reviewer would accept.
var productVocabulary = []string{
	components.ProductName,
	"Agent Plugins",
	"Agent Skills",
	"Claude Code",
	"River Dashboard",
}

// identityClasses are asserted on as well as the text: a chip with an empty name
// and no chip at all are different pages, and only the latter is honest.
var identityClasses = []string{"am-avatar", "am-viewer-name", "am-viewer-role"}

// sentinelViewer's values match the same patterns the defect would, so the
// assertion is about which match was found rather than whether one was.
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

type sweptScreen struct {
	name string
	// hostsShell is false for a component that is its own document, so no chip is
	// expected even signed in.
	hostsShell bool
	render     func(t *testing.T, viewer *view.Viewer) string
}

func sweep() []sweptScreen {
	// Screens are swept empty: source data such as package names, audit actors or
	// token creators is person-shaped by nature and was never the risk. What is
	// swept is the chrome, which is where an identity gets hand-written.
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
		inShell("CatalogNotice", func() templ.Component { return components.CatalogNotice(nil) }),
		inShell("PackageScreen", func() templ.Component { return components.PackageScreen(view.Package{}) }),
		inShell("CapabilityPanel", func() templ.Component { return components.CapabilityPanel(view.Capabilities{}) }),
		inShell("PackageScanPanel", func() templ.Component { return components.PackageScanPanel(view.PackageScan{}) }),
		inShell("VersionsPanel", func() templ.Component { return components.VersionsPanel(view.Package{}) }),
		inShell("DependentsPanel", func() templ.Component { return components.DependentsPanel(view.Package{}) }),
		inShell("FilesPanel", func() templ.Component { return components.FilesPanel(view.Package{}) }),
		// Empty rather than nil: production never passes nil, and nil would panic.
		inShell("MarkdownBody", func() templ.Component { return components.MarkdownBody(view.ParseMarkdown(nil)) }),
		inShell("ScannerScreen", func() templ.Component { return components.ScannerScreen(view.Scanner{}) }),
		inShell("AuditScreen", func() templ.Component { return components.AuditScreen(view.Audit{}) }),
		inShell("ProfilesScreen", func() templ.Component { return components.ProfilesScreen(view.Profiles{}) }),
		inShell("ProfileScreen", func() templ.Component { return components.ProfileScreen(view.Profile{}) }),
		inShell("CLIScreen", func() templ.Component { return components.CLIScreen(view.CLI{}) }),
		inShell("ServiceTokensScreen", func() templ.Component {
			return components.ServiceTokensScreen(view.ServiceTokens{})
		}),
		inShell("WebhooksScreen", func() templ.Component { return components.WebhooksScreen(view.Webhooks{}) }),
		inShell("MachinesScreen", func() templ.Component { return components.MachinesScreen(view.Machines{}) }),
		inShell("MachineScreen", func() templ.Component { return components.MachineScreen(view.MachineDetail{}) }),
		inShell("AffectedMachinesPanel", func() templ.Component {
			return components.AffectedMachinesPanel(view.AffectedMachines{Package: "a/b", Total: 2})
		}),
		inShell("StorageScreen", func() templ.Component { return components.StorageScreen(view.Storage{}) }),
		inShell("OrgScreen", func() templ.Component { return components.OrgScreen(view.Org{}) }),
		inShell("RuntimeScreen", func() templ.Component { return components.RuntimeScreen(view.Runtime{}) }),
		// The embedded state, not the gated one, so the sweep sees actual content.
		inShell("RiverScreen", func() templ.Component {
			return components.RiverScreen(view.River{EmbedPath: view.RiverEmbedPrefix + "/"})
		}),
		{
			name: "NoRoleScreen",
			// Only a signed-in identity can be unmapped, so signed out is swept as the
			// shell around an ordinary screen.
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
			// Swept with the credential hint off, which is how it is served; the hint
			// prints caller data and has its own test.
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
			body := screen.render(t, signedOutViewer())

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

// TestEveryComponentIsInTheIdentitySweep guards the hand-written sweep list:
// every exported templ must be swept or excused with a reason.
func TestEveryComponentIsInTheIdentitySweep(t *testing.T) {
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

// TestTheIdentityPatternsCatchTheDefectTheyWereWrittenFor guards against the
// sweeps passing because the patterns stopped matching.
func TestTheIdentityPatternsCatchTheDefectTheyWereWrittenFor(t *testing.T) {
	for _, name := range []string{"Krzysztof W.", "Ada Lovelace", "shared with Jane Roe today", "Sentinel Viewername"} {
		require.Regexpf(t, personShaped, name, "%q is no longer recognised as a person's name", name)
	}
	for _, address := range []string{"kwiatrzyk@example.com", "a.b+c@sub.example.co.uk"} {
		require.Regexpf(t, addressShaped, address, "%q is no longer recognised as an address", address)
	}

	// A pattern that matches the product's own copy gets weakened by whoever hits it next.
	for _, copy := range []string{
		"Connect the CLI", "Audit log", "Not found", "No role", "Sign out",
		"Nothing matches these filters. Clear a tag or widen the category.",
	} {
		require.NotRegexpf(t, personShaped, copy, "%q reads as a person's name", copy)
	}
}

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
					"request resolved. A literal here is the hard-coded chip this feature "+
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

// renderedText is the page's text nodes, kept separate so adjacent elements
// cannot invent a name like "Storage Organization". Attribute values are dropped;
// the source scan covers them.
func renderedText(t *testing.T, body string) []string {
	t.Helper()

	require.NotEmpty(t, body, "nothing was rendered")

	for _, tag := range []string{"script", "style"} {
		body = regexp.MustCompile(`(?s)<`+tag+`[^>]*>.*?</`+tag+`>`).ReplaceAllString(body, "")
	}
	return textChunks(body)
}

// textChunks returns the whitespace-collapsed text between tags. Also used for
// the .templ scan.
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

// TestNoIdentityLiteralIsCompiledIntoTheWebRole scans string literals and
// template text in the source, for a name only rendered in a state no test
// enters. Comments are not scanned: naming a person there is not rendering one.
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

// webSourceFiles walks the tree so new files are scanned automatically. fakeapi
// holds test fixtures; `*_templ.go` is skipped because its `.templ` source is
// scanned instead.
func webSourceFiles(t *testing.T) []string {
	t.Helper()

	var names []string
	require.NoError(t, filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "fakeapi" || entry.Name() == "static" {
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
