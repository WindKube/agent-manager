package pkgspec

import (
	"bytes"
	"encoding/json"
	"sort"
)

// MCPConfig is `mcp.json`: `{$schema, mcpServers}`, both required, closed.
//
// Measured while vendoring (schemas/PROVENANCE.md): this file is IDENTICAL
// between Agent Plugins 1.0.0 and 1.1.0 — 1.0.0 already required both fields.
// research.md R1 says 1.1.0 changed it; it did not, and that sentence is
// corrected there.
type MCPConfig struct {
	Schema     string               `json:"$schema"`
	MCPServers map[string]MCPServer `json:"mcpServers"`
}

// MCPServer is one server entry. The published schema is a `oneOf` over three
// shapes discriminated by `type`, so the union is flattened here and `Type` says
// which fields are meaningful. The schema has already refused any other
// combination by the time this decodes.
type MCPServer struct {
	Type string `json:"type"`

	// stdio
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Cwd     string            `json:"cwd,omitempty"`

	// streamable-http and sse
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// MCP server types, as the published schema's `const` values.
const (
	MCPTypeStdio          = "stdio"
	MCPTypeStreamableHTTP = "streamable-http"
	MCPTypeSSE            = "sse"
)

// ServerNames returns the configured server keys, sorted. Component derivation
// walks them in this order so a version's component rows are stable.
func (c *MCPConfig) ServerNames() []string {
	out := make([]string, 0, len(c.MCPServers))
	for name := range c.MCPServers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func decodeMCPConfig(raw []byte, schemaID string) (*MCPConfig, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var config MCPConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, manifestError(MCPConfigFile, schemaID, Problem{
			SchemaPath: "/additionalProperties",
			Message:    err.Error(),
		})
	}
	return &config, nil
}
