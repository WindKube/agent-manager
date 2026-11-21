package view

import (
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

// MarkdownDoc is a parsed markdown file kept as goldmark's AST, never rendered to an HTML string:
// internal/archcheck bans templ.Raw and friends under internal/web, so components.MarkdownBody renders it
// node by node through templ's ordinary escaping.
type MarkdownDoc struct {
	Root   ast.Node
	Source []byte
	// Frontmatter is the leading YAML block's lines verbatim, never parsed as YAML.
	Frontmatter string
}

// ParseMarkdown parses source as CommonMark with no extensions. Frontmatter is split off first, since
// goldmark would read its "---" as a thematic break and mangle the block.
func ParseMarkdown(source []byte) MarkdownDoc {
	frontmatter, body := splitFrontmatter(source)
	root := goldmark.DefaultParser().Parse(text.NewReader(body))
	return MarkdownDoc{Root: root, Source: body, Frontmatter: frontmatter}
}

const frontmatterDelim = "---"

// splitFrontmatter returns a leading frontmatter block's lines verbatim and the rest of the document. It
// never decodes the untrusted YAML. Without a closing delimiter the source is returned unchanged.
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

// BlockText is a raw block node's source lines; a code block's body is not reachable through Node.Text.
func BlockText(n ast.Node, source []byte) string {
	return string(n.Lines().Value(source))
}
