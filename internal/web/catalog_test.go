package web_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/fixture"
)

// The header's refresh control (owner request: "this rotating circle") must
// reuse the catalog's own filter round trip rather than a second fetch path,
// must be a real named button rather than an icon-only div, and must show it
// is working through datastar's own indicator signal rather than a hand-rolled
// fetch tracker.

func TestCatalogRefreshButtonFiresTheSameRoundTripAsTheFilters(t *testing.T) {
	body := get(t, handler(t, fixture.New()), "/catalog").Body.String()

	const debouncedSite = `data-on-signal-patch__debounce.150ms="@get('/catalog/results')"`
	require.Contains(t, body, debouncedSite, "the debounced filter round trip must still be present")

	const refreshSite = `data-on:click="@get('/catalog/results')"`
	require.Contains(t, body, refreshSite,
		"nothing on the page fires the catalog's own round trip on a click; "+
			"the refresh button must call the same endpoint the filters do")
}

func TestCatalogRefreshButtonIsANamedButtonBeforeTheHeaderActions(t *testing.T) {
	body := get(t, handler(t, fixture.New()), "/catalog").Body.String()

	const refreshSite = `data-on:click="@get('/catalog/results')"`
	at := strings.Index(body, refreshSite)
	require.GreaterOrEqual(t, at, 0, "the refresh control is missing")

	buttonStart := strings.LastIndex(body[:at], "<button")
	require.GreaterOrEqual(t, buttonStart, 0, "the refresh control is not a <button>")
	buttonEnd := strings.Index(body[buttonStart:], "</button>") + buttonStart + len("</button>")
	button := body[buttonStart:buttonEnd]

	require.Contains(t, button, `aria-label="Refresh catalog"`,
		"an icon-only control needs a name a screen reader can announce")

	uploadAt := strings.Index(body, "Upload package")
	require.Greater(t, uploadAt, at, "the refresh control must sit left of the two existing header actions")
}

func TestCatalogRefreshButtonShowsItIsWorkingViaDatastarsOwnIndicator(t *testing.T) {
	body := get(t, handler(t, fixture.New()), "/catalog").Body.String()

	// data-indicator is the plugin datastar ships for exactly this: it flips a
	// signal true for the duration of a request the same element fires. Anything
	// else here would be a second, hand-rolled way to track an in-flight fetch.
	const attr = `data-indicator="`
	at := strings.Index(body, attr)
	require.GreaterOrEqual(t, at, 0, "the refresh button has no data-indicator")
	rest := body[at+len(attr):]
	signal := rest[:strings.IndexByte(rest, '"')]

	// The underscore is load-bearing, not a style preference (see the _import*
	// signals in props.go): datastar excludes underscore-prefixed signals from
	// every request it sends. Without it, this signal would ride along on every
	// /catalog/results and facet request, widening the wire contract of handlers
	// that have no use for it.
	require.Truef(t, strings.HasPrefix(signal, "_"),
		"the indicator signal %q must be underscore-prefixed so datastar never sends it to the server", signal)

	require.Contains(t, body, `data-class="{'am-spin': $`+signal+`}"`,
		"the icon must toggle a spin class off the same indicator signal while the request is in flight")
}
