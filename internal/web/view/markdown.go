package view

import (
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
}

// ParseMarkdown parses source as CommonMark with no extensions and no HTML
// rendering: goldmark's parser is reused (nobody hand-rolls CommonMark), but
// only its AST crosses into this hub. A construct this hub's renderer does
// not specifically handle falls back to rendering its children in place —
// never to inventing markup, and never to dropping it silently.
func ParseMarkdown(source []byte) MarkdownDoc {
	root := goldmark.DefaultParser().Parse(text.NewReader(source))
	return MarkdownDoc{Root: root, Source: source}
}

// BlockText is a raw block node's own source lines, verbatim — a code
// block's body is stored as line segments, not as child nodes, so it is not
// reachable through Node.Text.
func BlockText(n ast.Node, source []byte) string {
	return string(n.Lines().Value(source))
}
