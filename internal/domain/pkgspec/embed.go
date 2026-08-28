package pkgspec

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// The published schemas are compiled into the binary rather than fetched.
// Validation has to work offline, must not depend on a third party's uptime, and
// must not change under a released version of this hub. schemas/PROVENANCE.md
// records where each file came from and its sha256; skill-frontmatter.schema.json
// is project-authored because agentskills.io publishes no schema at all.
//
//go:embed schemas/*.schema.json
var schemaFS embed.FS

// The `$id` of every schema this package validates against. Dispatch is on the
// document's own `$schema` value matching one of these exactly — a manifest that
// names a schema we do not hold is refused rather than validated against a guess.
const (
	PluginSchema100 = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
	PluginSchema110 = "https://agent-plugins.org/schemas/1.1.0/plugin.schema.json"
	MCPSchema100    = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
	MCPSchema110    = "https://agent-plugins.org/schemas/1.1.0/mcp.schema.json"

	// SkillFrontmatterSchema is project-authored. The host is deliberately
	// unresolvable so nothing can mistake it for a published document.
	SkillFrontmatterSchema = "https://agent-manager.invalid/schemas/agent-skills/skill-frontmatter.schema.json"
)

// schemaFiles maps each `$id` to the embedded file carrying it. Written out by
// hand rather than derived by scanning the directory: a file that stops declaring
// the `$id` this project dispatches on must be a build failure, and a loop over
// whatever happens to be in the directory cannot notice.
var schemaFiles = map[string]string{
	PluginSchema100:        "schemas/1.0.0-plugin.schema.json",
	PluginSchema110:        "schemas/1.1.0-plugin.schema.json",
	MCPSchema100:           "schemas/1.0.0-mcp.schema.json",
	MCPSchema110:           "schemas/1.1.0-mcp.schema.json",
	SkillFrontmatterSchema: "schemas/skill-frontmatter.schema.json",
}

// pluginSchemaIDs and mcpSchemaIDs are the accepted `$schema` values per manifest
// kind, in the order an error message lists them.
var (
	pluginSchemaIDs = []string{PluginSchema100, PluginSchema110}
	mcpSchemaIDs    = []string{MCPSchema100, MCPSchema110}
)

// SchemaIDs returns every `$id` this package can validate against, sorted.
func SchemaIDs() []string {
	out := make([]string, 0, len(schemaFiles))
	for id := range schemaFiles {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// RawSchema returns the embedded bytes for one `$id`, exactly as vendored. The
// lookahead transform below is applied to a decoded copy at compile time and
// never to these bytes, so a caller that wants to verify a sha256 against
// PROVENANCE.md gets the file that was fetched.
func RawSchema(id string) ([]byte, error) {
	name, ok := schemaFiles[id]
	if !ok {
		return nil, fmt.Errorf("no embedded schema for %q", id)
	}
	raw, err := fs.ReadFile(schemaFS, name)
	if err != nil {
		return nil, fmt.Errorf("read embedded schema %s: %w", name, err)
	}
	return raw, nil
}

// liftNameLookahead rewrites the published `name` pattern to its RE2-expressible
// remainder, in a decoded schema document.
//
// It replaces the exact published string and nothing else, and reports how many
// replacements it made so the caller can refuse a schema where the rule went
// missing instead of quietly validating against a weaker one. See name.go for why
// this is necessary at all and where the removed half is re-applied.
func liftNameLookahead(doc any) (lifted any, replaced int) {
	switch node := doc.(type) {
	case map[string]any:
		count := 0
		for key, value := range node {
			if key == "pattern" {
				if pattern, ok := value.(string); ok && pattern == lookaheadNamePattern {
					node[key] = re2NamePattern
					count++
					continue
				}
			}
			child, n := liftNameLookahead(value)
			node[key] = child
			count += n
		}
		return node, count
	case []any:
		count := 0
		for i, value := range node {
			child, n := liftNameLookahead(value)
			node[i] = child
			count += n
		}
		return node, count
	default:
		return doc, 0
	}
}

// carriesNameLookahead reports whether the vendored bytes still hold the pattern
// the transform expects. Used to state which schemas must yield a replacement.
func carriesNameLookahead(raw []byte) bool {
	// The pattern appears in JSON with its backslashes doubled.
	escaped := strings.ReplaceAll(lookaheadNamePattern, `\`, `\\`)
	return bytes.Contains(raw, []byte(escaped))
}
