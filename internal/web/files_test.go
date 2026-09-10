package web_test

import (
	"bytes"
	"context"
	"html"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

// TestMarkdownRenderingNeverLetsAScriptTagAnEventHandlerAJavascriptLinkOrAnIframeSurvive
// is the one test a screenshot cannot catch, for US3/US5's "read a skill's
// files before using it": a SKILL.md is a file a PUBLISHER wrote, not this
// hub's own copy, so this is exactly the FR-055 threat the import panel's
// own escaping test guards against, aimed at the new renderer instead.
//
// It goes through the REAL path start to finish: view.ParseMarkdown (the
// real goldmark parser, unsafe HTML rendering never even linked in) into
// components.MarkdownBody (the real templ component), rendered to bytes the
// same way the package screen renders it. Nothing here is mocked, and
// nothing here is bluemonday or any other HTML sanitiser cleaning up after
// the fact — see view.MarkdownDoc's doc comment for why: this renderer never
// builds an HTML string in the first place, so there is nothing for a
// sanitiser to have missed something in.
func TestMarkdownRenderingNeverLetsAScriptTagAnEventHandlerAJavascriptLinkOrAnIframeSurvive(t *testing.T) {
	source := "# A skill worth reading first\n\n" +
		"Some real instructions a person should still see.\n\n" +
		"<script>alert(document.cookie)</script>\n\n" +
		"<img src=\"x\" onerror=\"alert(2)\">\n\n" +
		"[a helpful link](javascript:alert(3))\n\n" +
		"<iframe src=\"javascript:alert(4)\"></iframe>\n"

	doc := view.ParseMarkdown([]byte(source))

	var out bytes.Buffer
	require.NoError(t, components.MarkdownBody(doc).Render(context.Background(), &out))
	rendered := out.String()

	for _, banned := range []string{"<script", "</script", "onerror=", "javascript:", "<iframe"} {
		require.NotContainsf(t, rendered, banned,
			"the rendered file still carries %q — a publisher's SKILL.md just executed in a "+
				"viewer's browser:\n%s", banned, rendered)
	}

	// FR-055's other half: a sanitiser that strips something must not leave the
	// file looking empty. The heading and the plain sentence survive, and the
	// two stripped blocks leave a visible placeholder rather than nothing.
	require.Contains(t, rendered, "A skill worth reading first")
	require.Contains(t, rendered, "Some real instructions a person should still see.")
	require.Contains(t, rendered, "markup omitted")
}

// TestMarkdownLinkDestinationIsSanitisedNotJustEscaped is narrower than the
// test above: a javascript: URL that survived ESCAPING (as text) but not
// SANITISATION (as an href) would still not execute, so this pins down that
// the destination is refused as a link target and not merely rendered inert
// as a string.
func TestMarkdownLinkDestinationIsSanitisedNotJustEscaped(t *testing.T) {
	doc := view.ParseMarkdown([]byte("[click me](javascript:alert(1))"))

	var out bytes.Buffer
	require.NoError(t, components.MarkdownBody(doc).Render(context.Background(), &out))
	rendered := out.String()

	require.Contains(t, rendered, "click me")
	require.NotContains(t, rendered, `href="javascript:`)
	// templ's own URL sanitiser replaces a disallowed scheme with this
	// inert placeholder rather than dropping the href attribute outright.
	require.Contains(t, rendered, "about:invalid#TemplFailedSanitizationURL")
}

// A scheme check that only catches the lowercase spelling of one scheme is not
// a scheme check. These are the shapes a publisher would reach for next, and an
// image is included because its destination goes through the same path as a
// link's: this hub renders one as the other rather than fetching bytes.
//
// The assertion is on the href VALUES, not on the whole page: an autolink
// renders its own destination as its visible text, and `javascript:alert(1)`
// sitting inertly between two tags is not a finding — the same string inside an
// href is.
func TestNoMarkdownDestinationSchemeSurvivesBesidesTheAllowedOnes(t *testing.T) {
	for _, source := range []string{
		"[x](JaVaScRiPt:alert(1))",
		"[x](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)",
		"[x](vbscript:msgbox(1))",
		"![x](javascript:alert(1))",
		"<javascript:alert(1)>",
	} {
		t.Run(source, func(t *testing.T) {
			var out bytes.Buffer
			require.NoError(t, components.MarkdownBody(view.ParseMarkdown([]byte(source))).
				Render(context.Background(), &out))

			hrefs := hrefValues(out.String())
			require.NotEmpty(t, hrefs, "the destination did not render as a link at all:\n%s", out.String())
			for _, href := range hrefs {
				require.Equal(t, "about:invalid#TemplFailedSanitizationURL", href,
					"a disallowed scheme reached an href from %q", source)
			}
		})
	}
}

// hrefValues is every href this markup carries, so a test can assert on the
// attribute rather than on the page's text.
func hrefValues(rendered string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(rendered, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// An allowed scheme has to survive, or the test above would pass on a renderer
// that refused every link ever written.
func TestAnOrdinaryLinkSurvivesTheSchemeCheck(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, components.MarkdownBody(
		view.ParseMarkdown([]byte("[docs](https://example.com/a?b=c#d) and <mailto:a@b.example>"))).
		Render(context.Background(), &out))

	require.Equal(t, []string{"https://example.com/a?b=c#d", "mailto:a@b.example"}, hrefValues(out.String()))
}

// A fenced block is the one place a publisher may legitimately WRITE
// `<script>` — documenting one. It has to read back as text, not run.
func TestScriptInsideACodeFenceIsShownAsTextRatherThanExecuted(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, components.MarkdownBody(
		view.ParseMarkdown([]byte("```html\n<script>alert(1)</script>\n```\n"))).
		Render(context.Background(), &out))

	rendered := out.String()
	require.NotContains(t, rendered, "<script>")
	require.Contains(t, rendered, "&lt;script&gt;alert(1)&lt;/script&gt;",
		"a documented script tag has to survive as readable text")
}
