package web_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/fixture"
)

// A datastar attribute is <plugin>:<key>, and an attribute naming a plugin that
// is not registered is dropped in SILENCE — no console error, no thrown
// exception, no failing assertion anywhere else in this suite. That is how
// `data-style-display` shipped: it resolves to a plugin named "style-display",
// so the registration modal stayed at its inline display:none however
// $_importOpen moved, and both header buttons looked dead.
//
// This asserts the property rather than the one attribute: every data- attribute
// the rendered pages carry either names a registered plugin or is on the short
// list of plain HTML data attributes this project reads itself.

// plainDataAttributes are data- attributes that are NOT datastar's. Each one is
// read by this project or by its stylesheet, and datastar ignores them.
var plainDataAttributes = map[string]bool{
	// The theme the server writes from the cookie; the stylesheet selects on it.
	"data-sm-theme": true,
	// The facet option label the filter box matches against.
	"data-label": true,
	// Read by the on-signal-patch plugin off the same element, not dispatched as
	// a plugin of its own.
	"data-on-signal-patch-filter": true,
}

var (
	dataAttrPattern   = regexp.MustCompile(`\bdata-[a-zA-Z][a-zA-Z0-9:._-]*`)
	pluginNamePattern = regexp.MustCompile(`name:"([a-zA-Z][a-zA-Z-]*)"`)
)

func TestEveryDatastarAttributeNamesARegisteredPlugin(t *testing.T) {
	plugins := registeredPlugins(t)

	handler := handler(t, fixture.New())
	for _, path := range []string{"/catalog", "/scanner", "/profiles", "/storage", "/org", "/cli", "/audit"} {
		t.Run(path, func(t *testing.T) {
			body := get(t, handler, path).Body.String()

			for _, attr := range dataAttrPattern.FindAllString(body, -1) {
				if plainDataAttributes[attr] {
					continue
				}
				// Modifiers hang off __, and the key off the first colon.
				plugin := strings.SplitN(strings.SplitN(attr, "__", 2)[0], ":", 2)[0]
				require.Truef(t, plugins[strings.TrimPrefix(plugin, "data-")],
					"%s names no registered datastar plugin, so it is dropped in silence; "+
						"a plugin key is colon-delimited (data-style:display, not data-style-display)", attr)
			}
		})
	}
}

// registeredPlugins reads the names out of the vendored bundle so this test
// cannot drift from the datastar the pages actually load.
func registeredPlugins(t *testing.T) map[string]bool {
	t.Helper()

	source, err := os.ReadFile("static/vendor/datastar.js")
	require.NoError(t, err, "the vendored datastar bundle is what the pages load")

	names := make(map[string]bool)
	for _, match := range pluginNamePattern.FindAllStringSubmatch(string(source), -1) {
		names[match[1]] = true
	}

	// The bundle is minified, so the names are read by pattern. These anchors
	// fail the test loudly if that pattern ever stops matching, rather than
	// leaving an empty set that admits every attribute.
	for _, anchor := range []string{"on", "style", "show", "text", "bind", "signals", "attr", "class"} {
		require.Truef(t, names[anchor],
			"the plugin names could not be read out of the bundle: %q is missing, so this test is not checking anything",
			anchor)
	}

	if testing.Verbose() {
		listed := make([]string, 0, len(names))
		for name := range names {
			listed = append(listed, name)
		}
		sort.Strings(listed)
		t.Logf("registered datastar plugins: %s", strings.Join(listed, " "))
	}
	return names
}
