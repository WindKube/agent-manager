package checks

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/capability"
	"agent-manager/internal/domain/pkgspec"
)

// Bundle is one version's bytes as the checks see them: the file tree, the
// shell syntax the parser recovered from it, the URLs its instruction files
// name, and the capability set its publisher declared. Nothing here
// executes, sources, imports or evaluates any of it.
type Bundle struct {
	Kind pkgspec.Kind

	// Manifest is the root manifest rendered as json, the same shape
	// `version.manifest` holds.
	Manifest       json.RawMessage
	ManifestObject string

	// ManifestProblems is why the manifest failed its published schema, read
	// out of the BUNDLE rather than the catalog row.
	ManifestProblems []pkgspec.Problem

	// Expected is the capability set the publisher recorded. Nil means none
	// was recorded.
	Expected []capability.Capability

	// Artefacts is what internal/domain/capability infers from.
	Artefacts capability.Artefacts

	// Commands is Artefacts.Commands with the source text each one came from.
	Commands []Command

	// Unparsed names the scripts the shell parser could not read — reported
	// as a warning by the shell audit, never a pass.
	Unparsed []string

	files map[string]bundle.File
	paths []string
	lines map[string][]string
}

// Inspect derives everything the checks read from an unpacked bundle. It
// never fails on hostile content: an unreadable tree becomes a recorded
// problem or blind spot rather than an error, since a scan that errors
// leaves the version with no verdict at all.
func Inspect(tree *bundle.Bundle) (*Bundle, error) {
	if tree == nil {
		return nil, errors.New("inspect: no tree")
	}

	out := &Bundle{lines: make(map[string][]string)}

	// pkgspec is the same layout filter, manifest validator and kind
	// derivation the ingestion path ran, so checks scan the filtered tree.
	scanned := tree
	pkg, manifestErr := pkgspec.Inspect(tree, "")
	if pkg != nil && pkg.Files != nil {
		scanned = pkg.Files
	}
	out.files = make(map[string]bundle.File, scanned.Len())
	for _, file := range scanned.Files() {
		out.files[file.Path] = file
		out.paths = append(out.paths, file.Path)
	}

	if pkg == nil {
		out.ManifestProblems = []pkgspec.Problem{{
			SchemaPath: "/", Message: layoutMessage(manifestErr),
		}}
	} else {
		out.Kind = pkg.Kind
		out.ManifestObject = pkg.ManifestObject
		out.Manifest = pkg.ManifestJSON
		if manifestErr != nil {
			out.ManifestProblems = manifestProblems(manifestErr)
		}
	}

	if len(out.Manifest) > 0 {
		expected, err := capability.Expected(out.Manifest)
		if err != nil {
			// A malformed expectation is a manifest problem, not an empty
			// expected set — an empty set would suppress nothing that
			// resembles a declaration.
			out.ManifestProblems = append(out.ManifestProblems, pkgspec.Problem{
				SchemaPath:   "/properties/extensions",
				InstancePath: "/extensions/" + pkgspec.ExtensionNamespace,
				Message:      err.Error(),
			})
		}
		out.Expected = expected
	}

	out.classify()
	return out, nil
}

// Paths are the bundle's file paths in sorted order.
func (b *Bundle) Paths() []string { return append([]string(nil), b.paths...) }

// File returns one file of the tree.
func (b *Bundle) File(filePath string) (bundle.File, bool) {
	file, ok := b.files[filePath]
	return file, ok
}

// Lines returns a file split into lines, cached because several rules read the
// same instruction file.
func (b *Bundle) Lines(filePath string) []string {
	if cached, ok := b.lines[filePath]; ok {
		return cached
	}
	file, ok := b.files[filePath]
	if !ok {
		return nil
	}
	split := strings.Split(strings.ReplaceAll(string(file.Data), "\r\n", "\n"), "\n")
	b.lines[filePath] = split
	return split
}

// Line returns one 1-based line of a file, or "" when there is none.
func (b *Bundle) Line(filePath string, line int) string {
	all := b.Lines(filePath)
	if line < 1 || line > len(all) {
		return ""
	}
	return all[line-1]
}

// ExpectedDetail is the declared target list for one capability name, and
// whether a declaration exists at all.
func (b *Bundle) ExpectedDetail(name string) (targets []string, declared bool) {
	for _, row := range b.Expected {
		if row.Name == name {
			return row.Detail, true
		}
	}
	return nil, false
}

// classify walks the tree once and fills Artefacts: which file is what, which
// commands the scripts hold, which URLs the instruction files name.
func (b *Bundle) classify() {
	for _, filePath := range b.paths {
		file := b.files[filePath]
		class := classOf(filePath, file.Data)
		b.Artefacts.Files = append(b.Artefacts.Files, capability.File{Path: filePath, Class: class})

		switch class {
		case capability.ClassScript:
			commands, err := parseShell(filePath, file.Data)
			if err != nil {
				b.Unparsed = append(b.Unparsed, filePath)
				continue
			}
			b.Commands = append(b.Commands, commands...)
			for _, command := range commands {
				b.Artefacts.Commands = append(b.Artefacts.Commands, command.Command)
			}
		case capability.ClassInstruction:
			b.Artefacts.URLs = append(b.Artefacts.URLs, urlsIn(filePath, b.Lines(filePath))...)
		case capability.ClassManifest, capability.ClassOther:
		}
	}
}

// scriptExtensions are the files read as shell.
var scriptExtensions = map[string]struct{}{
	".sh": {}, ".bash": {}, ".zsh": {}, ".ksh": {},
}

// instructionExtensions are the files an agent reads as prose.
var instructionExtensions = map[string]struct{}{
	".md": {}, ".txt": {}, ".rst": {},
}

// classOf decides what a file is from its path, its extension and — only for
// a shebang — its first line; never from sniffing content otherwise.
//
// SKILL.md is classified as an INSTRUCTION even though its frontmatter is the
// manifest, so a prompt-injection rule still sees its body.
func classOf(filePath string, data []byte) capability.Class {
	base := path.Base(filePath)
	ext := strings.ToLower(path.Ext(base))

	switch base {
	case pkgspec.PluginManifest, pkgspec.MCPConfigFile:
		return capability.ClassManifest
	}
	if _, ok := scriptExtensions[ext]; ok {
		return capability.ClassScript
	}
	if _, ok := instructionExtensions[ext]; ok {
		return capability.ClassInstruction
	}
	if hasShellShebang(data) {
		return capability.ClassScript
	}
	return capability.ClassOther
}

var shellShebang = regexp.MustCompile(`^#!\s*\S*/(?:env\s+)?(?:ba|z|k|da)?sh\b`)

func hasShellShebang(data []byte) bool {
	line := data
	if idx := strings.IndexByte(string(data), '\n'); idx >= 0 {
		line = data[:idx]
	}
	return shellShebang.Match(line)
}

// urlPattern finds absolute http(s) URLs in prose, excluding trailing
// punctuation that ends a sentence or closes a markdown link.
var urlPattern = regexp.MustCompile(`https?://[^\s"'<>)\]}]+`)

func urlsIn(filePath string, lines []string) []capability.URL {
	var out []capability.URL
	for i, line := range lines {
		for _, raw := range urlPattern.FindAllString(line, -1) {
			out = append(out, capability.URL{File: filePath, Line: i + 1, Raw: strings.TrimRight(raw, ".,;:")})
		}
	}
	return out
}

func manifestProblems(err error) []pkgspec.Problem {
	var manifestErr *pkgspec.ManifestError
	if errors.As(err, &manifestErr) && len(manifestErr.Problems) > 0 {
		return manifestErr.Problems
	}
	return []pkgspec.Problem{{SchemaPath: "/", Message: err.Error()}}
}

func layoutMessage(err error) string {
	if err == nil {
		return "the stored bundle holds no package layout"
	}
	return fmt.Sprintf("the stored bundle holds no readable package layout: %v", err)
}
