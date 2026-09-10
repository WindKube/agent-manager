package pkgspec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Plugin is `plugin.json`: the ten fields Agent Plugins 1.0.0 and 1.1.0
// permit, under `additionalProperties: false`. Only `$schema` and `name` are
// required. This struct is the whole field set — adding a field the schema
// rejects would be a registry that accepts manifests no other client can read.
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

// PluginAuthor is the published `author` object: three optional string
// fields, closed.
type PluginAuthor struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

// ExtensionSet is `extensions`: client-specific data keyed by reverse-domain
// namespace. The spec assigns no semantics to namespace object contents, so
// values stay raw here and only this project's own namespace is decoded.
type ExtensionSet map[string]json.RawMessage

// Raw is the manifest bytes exactly as read: a re-encoded copy would lose
// key order and any field this build has no struct member for.
func (p *Plugin) Raw() json.RawMessage { return p.raw }

func (p *Plugin) Namespaces() []string {
	out := make([]string, 0, len(p.Extensions))
	for ns := range p.Extensions {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// AgentManagerExtension is this project's namespace object,
// `extensions["dev.agent-manager"]` — the only conformant home for anything
// the design drew as a top-level manifest field.
type AgentManagerExtension struct {
	// ExpectedCapabilities is what the publisher or a reviewer says this
	// package should be able to reach. It is an expectation and never an
	// enforced permission: nothing in this hub grants or denies on it. A
	// finding is raised where the scanner's inferred set exceeds it.
	ExpectedCapabilities []ExpectedCapability `json:"expectedCapabilities,omitempty"`

	// Components lists tree paths the publisher asserts are present: the only
	// way a manifest can name one missing from disk, which is a validation
	// failure and not a scan finding.
	Components []string `json:"components,omitempty"`
}

// ExpectedCapability mirrors the `capability` table's shape so the two sets
// compare like for like.
type ExpectedCapability struct {
	Name   string   `json:"name"`
	Level  string   `json:"level,omitempty"`
	Detail []string `json:"detail,omitempty"`
}

// The capability names this project recognises. Closed, because an
// unrecognised name would silently never match anything the scanner infers —
// a control that looks present and does nothing.
const (
	CapabilityNetwork         = "network"
	CapabilityFilesystemRead  = "filesystem.read"
	CapabilityFilesystemWrite = "filesystem.write"
	CapabilityShell           = "shell"
)

var capabilityNames = []string{
	CapabilityNetwork, CapabilityFilesystemRead, CapabilityFilesystemWrite, CapabilityShell,
}

// The levels, matching the `capability_level` enum.
const (
	LevelScoped      = "scoped"
	LevelAllowlisted = "allowlisted"
	LevelReview      = "review"
)

var capabilityLevels = []string{LevelScoped, LevelAllowlisted, LevelReview}

// AgentManager decodes this project's extension namespace. The second result
// is false when the namespace is absent, which is not an error: a publisher
// may record no expected set, and that is the case where every inferred
// capability is surfaced for review.
func (p *Plugin) AgentManager() (*AgentManagerExtension, bool, error) {
	rawExt, ok := p.Extensions[ExtensionNamespace]
	if !ok || len(rawExt) == 0 {
		return nil, false, nil
	}

	// DisallowUnknownFields inside our own namespace, where the published
	// schema checks nothing: without it a misspelled `expectedCapabilties` is
	// an expected set that silently does not exist.
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
		// A shell capability is never below review, raised rather than
		// refused: the publisher's understatement must not become a
		// reviewer's blind spot.
		if capability.Name == CapabilityShell {
			capability.Level = LevelReview
		}
	}
	return &ext, true, nil
}

// decodePlugin's DisallowUnknownFields mirrors `additionalProperties: false`
// in Go too, so a future schema relaxation fails here instead of passing an
// unknown field into the catalog.
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

// escapePointer escapes a JSON Pointer token (RFC 6901): a pointer built
// without escaping breaks the first time a key holds a slash or tilde.
func escapePointer(token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	return strings.ReplaceAll(token, "/", "~1")
}
