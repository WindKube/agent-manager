package checks

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"agent-manager/internal/domain/capability"
)

// This file parses shell rather than text-matching it, so it can tell a real
// command from prose or a comment describing one. It never evaluates
// anything: an expansion like `$HOST` arrives as its own text, and
// internal/domain/capability grades that indefinite target as Review.

// Command is one parsed command with the source it came from.
type Command struct {
	capability.Command

	// Node is the source text of the statement, redirections included, for
	// `evidence.quote: matched-node`.
	Node string
	// Text is the whole source line the command starts on, for
	// `evidence.quote: matched-line`.
	Text string
}

// maxCommandsPerScript bounds one script's contribution; reaching it is
// recorded as a blind spot by the caller.
const maxCommandsPerScript = 20000

// parseShell walks one script's syntax tree and returns the commands in it.
func parseShell(filePath string, src []byte) ([]Command, error) {
	// LangBash, not LangPOSIX: bundles ship bash.
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(false))
	file, err := parser.Parse(bytes.NewReader(src), filePath)
	if err != nil {
		return nil, fmt.Errorf("parse %s as shell: %w", filePath, err)
	}

	lines := strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n")
	out := make([]Command, 0, 16)

	syntax.Walk(file, func(node syntax.Node) bool {
		if len(out) >= maxCommandsPerScript {
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			// A bare assignment (`FOO=bar`) is a CallExpr with no Args.
			return true
		}

		name := commandName(call.Args[0])
		if name == "" {
			return true
		}

		command := Command{
			Command: capability.Command{
				File: filePath,
				Line: int(call.Args[0].Pos().Line()),
				Name: name,
				Args: wordTexts(call.Args[1:]),
			},
			Node: sourceRange(src, stmt.Pos(), stmt.End()),
		}
		command.Redirects = redirectsOf(stmt)
		command.Text = lineAt(lines, command.Line)
		out = append(out, command)
		return true
	})
	return out, nil
}

// commandName is the command word with its directory dropped: `/usr/bin/curl`
// is `curl`.
func commandName(word *syntax.Word) string {
	text := wordText(word)
	if text == "" {
		return ""
	}
	// An expansion is returned as its own text, so it is graded indefinite
	// rather than silently matched.
	if strings.ContainsAny(text, "$`") {
		return text
	}
	return path.Base(text)
}

func wordTexts(words []*syntax.Word) []string {
	out := make([]string, 0, len(words))
	for _, word := range words {
		if text := wordText(word); text != "" {
			out = append(out, text)
		}
	}
	return out
}

// wordText renders one word as the shell would see it, minus quoting.
// Expansions are rendered back with their `$`, read as "indefinite".
func wordText(word *syntax.Word) string {
	if word == nil {
		return ""
	}
	var out strings.Builder
	for _, part := range word.Parts {
		out.WriteString(partText(part))
	}
	return out.String()
}

func partText(part syntax.WordPart) string {
	switch value := part.(type) {
	case *syntax.Lit:
		return value.Value
	case *syntax.SglQuoted:
		return value.Value
	case *syntax.DblQuoted:
		var out strings.Builder
		for _, inner := range value.Parts {
			out.WriteString(partText(inner))
		}
		return out.String()
	case *syntax.ParamExp:
		if value.Param == nil {
			return "$"
		}
		return "$" + value.Param.Value
	case *syntax.CmdSubst:
		return "$(…)"
	case *syntax.ArithmExp:
		return "$((…))"
	case *syntax.ProcSubst:
		return "$(…)"
	case *syntax.ExtGlob:
		return value.Pattern.Value
	default:
		// Anything not rendered explicitly still carries a `$`, so it grades
		// indefinite rather than as no target at all.
		return "$"
	}
}

func redirectsOf(stmt *syntax.Stmt) []capability.Redirect {
	out := make([]capability.Redirect, 0, len(stmt.Redirs))
	for _, redirect := range stmt.Redirs {
		target := wordText(redirect.Word)
		if target == "" {
			continue
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.ClbOut:
			out = append(out, capability.Redirect{Path: target, Write: true})
		case syntax.RdrIn, syntax.DplIn, syntax.RdrInOut:
			out = append(out, capability.Redirect{Path: target, Write: false})
		default:
			// Here-documents, here-strings and duplicated descriptors name no path.
		}
	}
	return out
}

func sourceRange(src []byte, from, to syntax.Pos) string {
	start, end := int(from.Offset()), int(to.Offset())
	if start < 0 || start > len(src) {
		return ""
	}
	if end <= start || end > len(src) {
		end = len(src)
	}
	return string(src[start:end])
}

func lineAt(lines []string, line int) string {
	if line < 1 || line > len(lines) {
		return ""
	}
	return lines[line-1]
}
