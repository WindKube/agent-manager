package pkgspec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Plugin is `plugin.json`: the TEN fields Agent Plugins 1.0.0 and 1.1.0 permit,
// under `additionalProperties: false`. Only `$schema` and `name` are required.
//
// This struct is the whole field set. It is not a subset chosen for convenience
// and it is not a superset admitting the design's mockup fields
// (`agentPluginsVersion`, `publisher`, `components`, `signature`): research.md R1
// is that those do not exist, and the schema rejects them. Adding one here would
// be a registry that accepts manifests no other client can read.
type Plugin struct {
	Schema      string          `json:"$schema"`
	Name        string          `json:"name"`
	Version     string          `json:"version,omitempty"`
	Description string          `json:"description,omitempty"`
	Author      *PluginAuthor   `json:"author,omitempty"`
	Homepage    string          `json:"homepage,omitempty"`
	Repository  string          `json:"repository,omitempty"`
	License     string          `json:"license,omitempty"`
	Keywords    []string        `json:"keywords,omitempty"`
	Extensions  ExtensionSet    `json:"extensions,omitempty"`
	raw         json.RawMessage `json:"-"`
}

// PluginAuthor is the published `author` object: three optional string fields,
// closed.
type PluginAuthor struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

// ExtensionSet is `extensions`: client-specific data keyed by reverse-domain
// namespace. The spec "assigns no semantics to namespace object contents", so the
// values stay raw here and only this project's own namespace is decoded.
type ExtensionSet map[string]json.RawMessage

// Raw is the manifest bytes exactly as they were read. version.manifest stores
// the conformant manifest verbatim (data-model.md), so a re-encoded copy would
// lose key order and any field this build has no struct member for.
func (p *Plugin) Raw() json.RawMessage { return p.raw }

// Namespaces returns the extension namespaces present, sorted.
func (p *Plugin) Namespaces() []string {
	out := make([]string, 0, len(p.Extensions))
	for ns := range p.Extensions {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// AgentManagerExtension is this project's namespace object,
// `extensions["dev.agent-manager"]` — the only conformant home for anything the
// design drew as a top-level manifest field (FR-018a).
type AgentManagerExtension struct {
	// ExpectedCapabilities is what the publisher or a reviewer says this package
	// should be able to reach. It is an EXPECTATION and never an enforced
	// permission (FR-018a): nothing in this hub grants or denies on it. A finding
	// is raised where the scanner's inferred set exceeds it (FR-027).
	ExpectedCapabilities []ExpectedCapability `json:"expectedCapabilities,omitempty"`

	// Components lists tree paths the publisher asserts are present. It exists to
	// make the spec's edge case expressible with a CONFORMANT manifest: no
	// published field enumerates components, so this is the only place a manifest
	// can name one that is missing from disk — which is a manifest validation
	// failure, not a scan finding.
	Components []string `json:"components,omitempty"`
}

// ExpectedCapability is one row of the expected set. It mirrors the `capability`
// table's shape (name, detail, level) so the comparison in FR-027 is between two
// sets of the same thing.
type ExpectedCapability struct {
	Name   string   `json:"name"`
	Level  string   `json:"level,omitempty"`
	Detail []string `json:"detail,omitempty"`
}

// The capability names this project recognises. Closed, because an unrecognised
// name in the expected set would silently never match anything the scanner
// infers, which is a control that looks present and does nothing.
const (
	CapabilityNetwork         = "network"
	CapabilityFilesystemRead  = "filesystem.read"
	CapabilityFilesystemWrite = "filesystem.write"
	CapabilityShell           = "shell"
)

var capabilityNames = []string{
	CapabilityNetwork, CapabilityFilesystemRead, CapabilityFilesystemWrite, CapabilityShell,
}

// The levels, matching the `capability_level` enum in data-model.md.
const (
	LevelScoped      = "scoped"
	LevelAllowlisted = "allowlisted"
	LevelReview      = "review"
)

var capabilityLevels = []string{LevelScoped, LevelAllowlisted, LevelReview}

// AgentManager decodes this project's extension namespace.
//
// The second result is false when the namespace is absent, which is not an error:
// FR-018a says a publisher MAY record an expected set, and "no expectation
// recorded" is the case where every inferred capability is surfaced for review.
func (p *Plugin) AgentManager() (*AgentManagerExtension, bool, error) {
	rawExt, ok := p.Extensions[ExtensionNamespace]
	if !ok || len(rawExt) == 0 {
		return nil, false, nil
	}

	// DisallowUnknownFields inside our OWN namespace, where the published schema
	// deliberately assigns no semantics and therefore checks nothing. Without it a
	// misspelled `expectedCapabilties` is an expected set that silently does not
	// exist, and the finding it would have suppressed never appears.
	decoder := json.NewDecoder(bytes.NewReader(rawExt))
	decoder.DisallowUnknownFields()

	var ext AgentManagerExtension
	if err := decoder.Decode(&ext); err != nil {
		return nil, false, manifestError(PluginManifest, p.Schema, Problem{
			SchemaPath:   "/properties/extensions/additionalProperties",
			InstancePath: "/extensions/" + escapePointer(ExtensionNamespace),
			Message:      err.Error(),
		})
	}

	for i := range ext.ExpectedCapabilities {
		capability := &ext.ExpectedCapabilities[i]
		pointer := fmt.Sprintf("/extensions/%s/expectedCapabilities/%d", escapePointer(ExtensionNamespace), i)

		if !containsString(capabilityNames, capability.Name) {
			return nil, false, manifestError(PluginManifest, p.Schema, Problem{
				SchemaPath:   "/properties/extensions/additionalProperties",
				InstancePath: pointer + "/name",
				Message: fmt.Sprintf("capability %q is not one of %s",
					capability.Name, strings.Join(capabilityNames, ", ")),
			})
		}
		if capability.Level == "" {
			capability.Level = LevelReview
		}
		if !containsString(capabilityLevels, capability.Level) {
			return nil, false, manifestError(PluginManifest, p.Schema, Problem{
				SchemaPath:   "/properties/extensions/additionalProperties",
				InstancePath: pointer + "/level",
				Message: fmt.Sprintf("level %q is not one of %s",
					capability.Level, strings.Join(capabilityLevels, ", ")),
			})
		}
		// FR-018: a shell capability is never below review. Raised rather than
		// refused, because the publisher's understatement must not become a
		// reviewer's blind spot.
		if capability.Name == CapabilityShell {
			capability.Level = LevelReview
		}
	}
	return &ext, true, nil
}

// decodePlugin decodes an already schema-validated manifest.
//
// DisallowUnknownFields is the second half of `additionalProperties: false`, held
// in Go as well as in the schema. It is not redundant: it is what makes a future
// relaxation of the embedded schema fail here instead of passing an unknown field
// into the catalog.
func decodePlugin(raw []byte, schemaID string) (*Plugin, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var plugin Plugin
	if err := decoder.Decode(&plugin); err != nil {
		return nil, manifestError(PluginManifest, schemaID, Problem{
			SchemaPath: "/additionalProperties",
			Message:    err.Error(),
		})
	}
	plugin.raw = append(json.RawMessage(nil), raw...)
	return &plugin, nil
}

// escapePointer escapes a JSON Pointer token (RFC 6901). The namespace key holds
// dots, not slashes or tildes, but a pointer built without escaping is a pointer
// that breaks the first time a key does.
func escapePointer(token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	return strings.ReplaceAll(token, "/", "~1")
}
