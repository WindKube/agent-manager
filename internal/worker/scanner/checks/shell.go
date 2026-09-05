package checks

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"agent-manager/internal/domain/capability"
)

// The shell audit parses, and this file is the whole of what that buys. A
// text match cannot tell `curl https://evil.example` from a line of prose
// documenting it, a commented-out example, or the same string inside a
// here-doc that is never run — the parser can, because it reports the tokens
// the shell itself would see.
//
// It never evaluates anything. An expansion arrives as its own text — `$HOST`
// stays four characters, `$(cat f)` stays a command substitution — because
// resolving one means running the script. An unresolved expansion is
// information: internal/domain/capability grades an indefinite target as
// Review rather than as absent.

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

// maxCommandsPerScript bounds one script's contribution: a generated
// 200 000-line script is a legitimate bundle, and the cap is per file so a
// bundle of many small scripts is still fully analysed. Reaching it is
// recorded as a blind spot by the caller, so the truncation cannot read as a
// clean script.
const maxCommandsPerScript = 20000

// parseShell walks one script's syntax tree and returns the commands in it.
func parseShell(filePath string, src []byte) ([]Command, error) {
	// LangBash rather than LangPOSIX: bundles ship bash, and a bash-only
	// construct under a POSIX parser would turn the most common shape of
	// real script into an unanalysed blind spot.
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
			// A bare assignment (`FOO=bar`) is a CallExpr with no Args, and
			// every other command type is walked into rather than recorded:
			// the commands inside it are what act.
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
// is `curl`, so a rule naming a command does not have to enumerate the paths
// it might be invoked through.
func commandName(word *syntax.Word) string {
	text := wordText(word)
	if text == "" {
		return ""
	}
	// A command reached through an expansion is returned as its own text so
	// a rule matching command names does not silently match it, and the
	// `shell` capability records it as indefinite.
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

// wordText renders one word as the shell would see it, minus expansion.
// Quotes are removed — `"$HOME/x"` is `$HOME/x` — since a quote is syntax and
// not part of the target. Expansions are rendered back with their `$`, which
// internal/domain/capability reads as "indefinite".
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
		// Anything not rendered explicitly still carries a `$`, read as an
		// expansion and graded indefinite. Returning "" would grade an
		// unrecognised construct as no target at all — the one direction
		// this must not fail in.
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
			// Here-documents and here-strings name no file, and a duplicated
			// descriptor names no path either.
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
