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

// Bundle is one version's bytes as the checks see them. Nothing here executes,
// sources or evaluates any of it.
type Bundle struct {
	Kind pkgspec.Kind

	// Manifest has the same shape as `version.manifest`.
	Manifest       json.RawMessage
	ManifestObject string

	// ManifestProblems is read from the bundle, not the catalog row.
	ManifestProblems []pkgspec.Problem

	// Expected is the declared capability set; nil means none was declared.
	Expected []capability.Capability

	Artefacts capability.Artefacts

	Commands []Command

	// Unparsed scripts are reported as a warning by the shell audit, never a pass.
	Unparsed []string

	Surfaces *pkgspec.Surfaces

	files map[string]bundle.File
	paths []string
	lines map[string][]string
}

// Inspect never fails on hostile content: an unreadable tree becomes a recorded
// problem or blind spot, since an erroring scan leaves no verdict at all.
func Inspect(tree *bundle.Bundle) (*Bundle, error) {
	if tree == nil {
		return nil, errors.New("inspect: no tree")
	}

	out := &Bundle{lines: make(map[string][]string)}

	// Same layout filter the ingestion path ran, so checks scan the filtered tree.
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
			// A malformed expectation is a manifest problem, not an empty set.
			out.ManifestProblems = append(out.ManifestProblems, pkgspec.Problem{
				SchemaPath:   "/properties/extensions",
				InstancePath: "/extensions/" + pkgspec.ExtensionNamespace,
				Message:      err.Error(),
			})
		}
		out.Expected = expected
	}

	out.Surfaces = pkgspec.ReadSurfaces(scanned)
	out.classify()
	out.classifySurfaces()
	return out, nil
}

// Paths returns the bundle's file paths in sorted order.
func (b *Bundle) Paths() []string { return append([]string(nil), b.paths...) }

// File returns one file of the tree.
func (b *Bundle) File(filePath string) (bundle.File, bool) {
	file, ok := b.files[filePath]
	return file, ok
}

// Lines returns a file split into lines, cached because several rules read it.
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

// ExpectedDetail returns the declared targets for one capability and whether it
// was declared at all.
func (b *Bundle) ExpectedDetail(name string) (targets []string, declared bool) {
	for _, row := range b.Expected {
		if row.Name == name {
			return row.Detail, true
		}
	}
	return nil, false
}

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

// classifySurfaces parses hook commands and stdio MCP command lines as scripts
// at `file#/pointer` paths, so shell rules see what a client actually runs.
func (b *Bundle) classifySurfaces() {
	b.Unparsed = append(b.Unparsed, b.Surfaces.Unreadable...)
	for _, hook := range b.Surfaces.Hooks {
		if hook.Command != "" {
			b.addSynthetic(hook.Location()+"/command", hook.Command)
		}
	}
	for i := range b.Surfaces.Servers {
		server := &b.Surfaces.Servers[i]
		if server.Transport == pkgspec.TransportStdio && server.Command != "" {
			b.addSynthetic(server.Location(), server.CommandLine())
		}
	}
}

func (b *Bundle) addSynthetic(location, line string) {
	commands, err := parseShell(location, []byte(line))
	if err != nil {
		b.Unparsed = append(b.Unparsed, location)
		return
	}
	for i := range commands {
		// A synthetic script has no lines of its own to point at.
		commands[i].Line = 0
		b.Commands = append(b.Commands, commands[i])
		b.Artefacts.Commands = append(b.Artefacts.Commands, commands[i].Command)
	}
}

var scriptExtensions = map[string]struct{}{
	".sh": {}, ".bash": {}, ".zsh": {}, ".ksh": {},
}

var instructionExtensions = map[string]struct{}{
	".md": {}, ".txt": {}, ".rst": {},
}

// classOf uses the path, extension and shebang only, never content sniffing.
// SKILL.md is an instruction, not a manifest, so prompt-injection rules see its body.
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

// urlPattern excludes trailing punctuation that closes a markdown link.
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
