package pkgspec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Plugin is `plugin.json`, the full field set Agent Plugins 1.0.0 and 1.1.0
// permit under `additionalProperties: false`. Don't add fields the schema
// rejects, or the registry accepts manifests no other client can read.
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

// PluginAuthor is the published `author` object.
type PluginAuthor struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

// ExtensionSet is `extensions`, keyed by reverse-domain namespace. Values stay
// raw; only this project's namespace is decoded.
type ExtensionSet map[string]json.RawMessage

// Raw is the manifest bytes exactly as read, preserving key order and
// unknown fields.
func (p *Plugin) Raw() json.RawMessage { return p.raw }

func (p *Plugin) Namespaces() []string {
	out := make([]string, 0, len(p.Extensions))
	for ns := range p.Extensions {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// AgentManagerExtension is `extensions["dev.agent-manager"]`, the only
// conformant home for this project's manifest fields.
type AgentManagerExtension struct {
	// ExpectedCapabilities is an expectation, never an enforced permission; a
	// finding is raised where the inferred set exceeds it.
	ExpectedCapabilities []ExpectedCapability `json:"expectedCapabilities,omitempty"`

	// Components lists tree paths the publisher asserts are present; a missing
	// one is a validation failure, not a scan finding.
	Components []string `json:"components,omitempty"`
}

// ExpectedCapability mirrors the `capability` table's shape so the two sets
// compare like for like.
type ExpectedCapability struct {
	Name   string   `json:"name"`
	Level  string   `json:"level,omitempty"`
	Detail []string `json:"detail,omitempty"`
}

// Capability names are a closed set: an unrecognised name would silently
// never match anything the scanner infers.
const (
	CapabilityNetwork         = "network"
	CapabilityFilesystemRead  = "filesystem.read"
	CapabilityFilesystemWrite = "filesystem.write"
	CapabilityShell           = "shell"
)

var capabilityNames = []string{
	CapabilityNetwork, CapabilityFilesystemRead, CapabilityFilesystemWrite, CapabilityShell,
}

// Levels match the `capability_level` enum.
const (
	LevelScoped      = "scoped"
	LevelAllowlisted = "allowlisted"
	LevelReview      = "review"
)

var capabilityLevels = []string{LevelScoped, LevelAllowlisted, LevelReview}

// AgentManager decodes this project's extension namespace. The second result
// is false, without error, when the namespace is absent.
func (p *Plugin) AgentManager() (*AgentManagerExtension, bool, error) {
	rawExt, ok := p.Extensions[ExtensionNamespace]
	if !ok || len(rawExt) == 0 {
		return nil, false, nil
	}

	// The published schema checks nothing here, so a typo would otherwise
	// silently drop the expected set.
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
		// Shell is raised to review rather than refused, so an understated
		// level can't hide it from reviewers.
		if capability.Name == CapabilityShell {
			capability.Level = LevelReview
		}
	}
	return &ext, true, nil
}

// decodePlugin mirrors `additionalProperties: false` so a future schema
// relaxation can't pass an unknown field into the catalog.
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

// escapePointer escapes a JSON Pointer token (RFC 6901).
func escapePointer(token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	return strings.ReplaceAll(token, "/", "~1")
}
