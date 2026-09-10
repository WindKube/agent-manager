package view

import (
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

// MarkdownDoc is a parsed markdown file, kept as goldmark's own AST rather
// than rendered to an HTML string. internal/archcheck's
// TestWebNeverBypassesTemplEscaping bans every templ entry point that would
// let a pre-built HTML blob reach the page unescaped (templ.Raw and its
// three siblings), anywhere under internal/web, with no exception — and a
// sanitiser's job is only ever to clean such a blob up after the fact.
// components.MarkdownBody walks this tree node by node instead, through
// templ's ordinary `{ expr }` escaping and its automatic href scheme check,
// so there is never an HTML string for a sanitiser to have missed something
// in, and nothing here needs an exception to the ban.
type MarkdownDoc struct {
	Root   ast.Node
	Source []byte
	// Frontmatter is a leading YAML block's lines, verbatim — see
	// splitFrontmatter. Empty when the file has none. Never parsed as YAML:
	// components.MarkdownBody shows it as plain text, through the same
	// escaping as every other node here.
	Frontmatter string
}

// ParseMarkdown parses source as CommonMark with no extensions and no HTML
// rendering: goldmark's parser is reused (nobody hand-rolls CommonMark), but
// only its AST crosses into this hub. A construct this hub's renderer does
// not specifically handle falls back to rendering its children in place —
// never to inventing markup, and never to dropping it silently.
//
// A leading YAML frontmatter block is pulled out first, by splitFrontmatter,
// and never reaches goldmark: CommonMark has no such construct, so the
// parser would otherwise read the opening "---" as a thematic break and
// everything up to the closing "---" as one run-together paragraph (or a
// setext heading, if a line in it happens to look like one).
func ParseMarkdown(source []byte) MarkdownDoc {
	frontmatter, body := splitFrontmatter(source)
	root := goldmark.DefaultParser().Parse(text.NewReader(body))
	return MarkdownDoc{Root: root, Source: body, Frontmatter: frontmatter}
}

// frontmatterDelim is the standalone line that opens and closes a YAML
// frontmatter block, the convention a SKILL.md follows.
const frontmatterDelim = "---"

// splitFrontmatter returns a leading frontmatter block's lines verbatim and
// the remaining document with the block (both delimiter lines included)
// removed. It never parses the block as YAML — decoding untrusted YAML into
// anything but inert text is a risk this simple text split has no need to
// take, and the caller renders the result as-is, which is honest about what
// this hub actually knows about the block: its lines, not its meaning.
//
// The source is returned unchanged when the first line is not exactly the
// delimiter, or when no closing delimiter follows — a bare "---" a
// publisher meant as a thematic break is left for goldmark to parse as one.
func splitFrontmatter(source []byte) (frontmatter string, body []byte) {
	lines := strings.Split(string(source), "\n")
	if len(lines) == 0 || strings.TrimRight(lines[0], " \t\r") != frontmatterDelim {
		return "", source
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimRight(lines[i], " \t\r") != frontmatterDelim {
			continue
		}
		return strings.Join(lines[1:i], "\n"), []byte(strings.Join(lines[i+1:], "\n"))
	}
	return "", source
}

// BlockText is a raw block node's own source lines, verbatim — a code
// block's body is stored as line segments, not as child nodes, so it is not
// reachable through Node.Text.
func BlockText(n ast.Node, source []byte) string {
	return string(n.Lines().Value(source))
}
