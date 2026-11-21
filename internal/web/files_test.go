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

// A SKILL.md is publisher-written, so it goes through the real parser and templ
// component unmocked. No sanitiser is involved: the renderer never builds an HTML
// string, so there is nothing for one to have missed.
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

	// Stripped blocks must leave a visible placeholder, not an empty-looking file.
	require.Contains(t, rendered, "A skill worth reading first")
	require.Contains(t, rendered, "Some real instructions a person should still see.")
	require.Contains(t, rendered, "markup omitted")
}

// TestMarkdownLinkDestinationIsSanitisedNotJustEscaped: the javascript: target
// must be refused as an href, not merely rendered inert as text.
func TestMarkdownLinkDestinationIsSanitisedNotJustEscaped(t *testing.T) {
	doc := view.ParseMarkdown([]byte("[click me](javascript:alert(1))"))

	var out bytes.Buffer
	require.NoError(t, components.MarkdownBody(doc).Render(context.Background(), &out))
	rendered := out.String()

	require.Contains(t, rendered, "click me")
	require.NotContains(t, rendered, `href="javascript:`)
	// templ's URL sanitiser substitutes this placeholder rather than dropping the href.
	require.Contains(t, rendered, "about:invalid#TemplFailedSanitizationURL")
}

// Mixed-case and alternative schemes, plus an image (rendered as a link here). The
// assertion is on href values because an autolink shows its destination as inert text.
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

func hrefValues(rendered string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(rendered, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// An allowed scheme must survive, or the test above passes on a renderer that refuses every link.
func TestAnOrdinaryLinkSurvivesTheSchemeCheck(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, components.MarkdownBody(
		view.ParseMarkdown([]byte("[docs](https://example.com/a?b=c#d) and <mailto:a@b.example>"))).
		Render(context.Background(), &out))

	require.Equal(t, []string{"https://example.com/a?b=c#d", "mailto:a@b.example"}, hrefValues(out.String()))
}

// A fenced block is the one place a publisher legitimately writes `<script>`.
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

// Read by goldmark alone, YAML frontmatter's opening "---" is a thematic break and
// the fields merge into one paragraph.
func TestFrontmatterRendersAsAStructuredBlockRatherThanARunTogetherParagraph(t *testing.T) {
	source := "---\n" +
		"name: pii-redactor\n" +
		"description: Finds and masks personal data in logs, fixtures and support transcripts.\n" +
		"license: Apache-2.0\n" +
		"allowed-tools:\n  - Read\n  - Write\n" +
		"---\n\n" +
		"# pii-redactor\n\nRedacts personal data on the way out.\n"

	var out bytes.Buffer
	require.NoError(t, components.MarkdownBody(view.ParseMarkdown([]byte(source))).
		Render(context.Background(), &out))
	rendered := out.String()

	require.NotContains(t, rendered, "<hr",
		"the opening --- must not be parsed as a CommonMark thematic break")
	require.NotContains(t, rendered, "name: pii-redactor description:",
		"the frontmatter fields must not be merged into one run-together paragraph")
	require.Contains(t, rendered, `class="am-md-frontmatter`,
		"the frontmatter must render as its own structured block")
	require.Contains(t, rendered, "<h1 class=\"am-md-h\">pii-redactor",
		"the document's real first heading must still render as a heading")
	require.Contains(t, rendered, "Redacts personal data on the way out.")
}

// The frontmatter is shown verbatim, never parsed as YAML, so templ's `{ expr }`
// escaping is its only path to the page.
func TestFrontmatterCannotEscapeEscapingEvenWithHostileValues(t *testing.T) {
	source := "---\n" +
		"name: pii-redactor\n" +
		"description: <script>alert(1)</script>\n" +
		"payload: <img src=x onerror=\"alert(2)\">\n" +
		"link: javascript:alert(3)\n" +
		"---\n\n" +
		"# pii-redactor\n\nBody text.\n"

	var out bytes.Buffer
	require.NoError(t, components.MarkdownBody(view.ParseMarkdown([]byte(source))).
		Render(context.Background(), &out))
	rendered := out.String()

	// Bare "onerror=" may survive as escaped text; the raw "<img" must not.
	for _, banned := range []string{"<script>", "</script>", "<img src=x"} {
		require.NotContainsf(t, rendered, banned,
			"the rendered frontmatter still carries the raw %q:\n%s", banned, rendered)
	}
	require.Contains(t, rendered, "&lt;script&gt;alert(1)&lt;/script&gt;")
	require.Contains(t, rendered, "&lt;img src=x onerror=&#34;alert(2)&#34;&gt;")
	require.Contains(t, rendered, "javascript:alert(3)",
		"the frontmatter is shown as text, not a link, so this string is not a live href")
	require.NotContains(t, rendered, `href="javascript:alert(3)"`)
}

func TestAFileWithNoFrontmatterRendersUnchanged(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, components.MarkdownBody(
		view.ParseMarkdown([]byte("# A skill with no frontmatter\n\nJust a body.\n"))).
		Render(context.Background(), &out))
	rendered := out.String()

	require.NotContains(t, rendered, "am-md-frontmatter")
	require.Contains(t, rendered, "<h1 class=\"am-md-h\">A skill with no frontmatter")
}
