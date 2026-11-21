package web_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// An attribute naming an unregistered datastar plugin is dropped silently (that is
// how `data-style-display` shipped and left the modal dead), so every data-
// attribute must name a registered plugin or be a known plain one.

// plainDataAttributes are data- attributes read by this project or its stylesheet,
// not datastar.
var plainDataAttributes = map[string]bool{
	"data-sm-theme": true,
	"data-label":    true,
	// Read by the on-signal-patch plugin off the same element.
	"data-on-signal-patch-filter": true,
}

var (
	dataAttrPattern   = regexp.MustCompile(`\bdata-[a-zA-Z][a-zA-Z0-9:._-]*`)
	pluginNamePattern = regexp.MustCompile(`name:"([a-zA-Z][a-zA-Z-]*)"`)
)

func TestEveryDatastarAttributeNamesARegisteredPlugin(t *testing.T) {
	plugins := registeredPlugins(t)

	_, handler := newServer(t)
	for _, path := range []string{"/catalog", "/scanner", "/profiles", "/storage", "/org", "/cli", "/audit", "/runtime"} {
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

// registeredPlugins reads names out of the vendored bundle so this cannot drift
// from the datastar the pages load.
func registeredPlugins(t *testing.T) map[string]bool {
	t.Helper()

	source, err := os.ReadFile("static/vendor/datastar.js")
	require.NoError(t, err, "the vendored datastar bundle is what the pages load")

	names := make(map[string]bool)
	for _, match := range pluginNamePattern.FindAllStringSubmatch(string(source), -1) {
		names[match[1]] = true
	}

	// The bundle is minified, so names are read by pattern; the anchors fail loudly
	// rather than leave an empty set that admits everything.
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
