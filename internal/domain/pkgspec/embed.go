package pkgspec

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// Schemas are embedded so validation works offline and is fixed per release.
// skill-frontmatter.schema.json is project-authored; agentskills.io publishes
// none.
//
//go:embed schemas/*.schema.json
var schemaFS embed.FS

// Schema `$id`s. A document's `$schema` must match one exactly; anything else
// is refused rather than validated against a guess.
const (
	PluginSchema100 = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
	PluginSchema110 = "https://agent-plugins.org/schemas/1.1.0/plugin.schema.json"
	MCPSchema100    = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
	MCPSchema110    = "https://agent-plugins.org/schemas/1.1.0/mcp.schema.json"

	// SkillFrontmatterSchema's host is deliberately unresolvable so nothing
	// mistakes it for a published document.
	SkillFrontmatterSchema = "https://agent-manager.invalid/schemas/agent-skills/skill-frontmatter.schema.json"
)

// schemaFiles is written out by hand so a file that stops declaring its `$id`
// fails the build.
var schemaFiles = map[string]string{
	PluginSchema100:        "schemas/1.0.0-plugin.schema.json",
	PluginSchema110:        "schemas/1.1.0-plugin.schema.json",
	MCPSchema100:           "schemas/1.0.0-mcp.schema.json",
	MCPSchema110:           "schemas/1.1.0-mcp.schema.json",
	SkillFrontmatterSchema: "schemas/skill-frontmatter.schema.json",
}

var (
	pluginSchemaIDs = []string{PluginSchema100, PluginSchema110}
	mcpSchemaIDs    = []string{MCPSchema100, MCPSchema110}
)

func SchemaIDs() []string {
	out := make([]string, 0, len(schemaFiles))
	for id := range schemaFiles {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// RawSchema returns the embedded bytes for one `$id`, exactly as vendored.
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

// liftNameLookahead rewrites the exact published `name` pattern to its
// RE2-expressible remainder and reports the replacement count (see name.go).
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

func carriesNameLookahead(raw []byte) bool {
	// The pattern appears in JSON with its backslashes doubled.
	escaped := strings.ReplaceAll(lookaheadNamePattern, `\`, `\\`)
	return bytes.Contains(raw, []byte(escaped))
}
