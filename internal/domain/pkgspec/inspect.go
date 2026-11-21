package pkgspec

import (
	"encoding/json"
	"errors"
	"fmt"

	"agent-manager/internal/bundle"
)

// Package is everything ingestion learns from a fetched tree. The api preview
// and the fetcher share it so the preview can't disagree with the real fetch.
type Package struct {
	Kind Kind
	Name string

	// Semver is the manifest's normalised, optional `version`; registration
	// supplies the authoritative one.
	Semver string

	Keywords       []string
	ManifestObject string
	ManifestBytes  []byte

	// ManifestJSON is what `version.manifest` holds; for a skill, the
	// frontmatter rendered as json.
	ManifestJSON json.RawMessage

	Plugin *Plugin
	Skill  *Skill
	MCP    *MCPConfig

	// Expected is nil when the publisher recorded none, which surfaces every
	// inferred capability for review.
	Expected *AgentManagerExtension

	Components []Component
	Layout     LayoutReport
	Files      *bundle.Bundle
}

// Inspect filters a fetched tree to the spec layout, validates its manifests
// and derives its components. The Package is non-nil whenever the layout could
// be computed, even alongside an error, so the preview can still render it.
// Publishers must check err.
func Inspect(tree *bundle.Bundle, root string) (*Package, error) {
	validator, err := Default()
	if err != nil {
		return nil, err
	}
	return InspectWith(validator, tree, root)
}

func InspectWith(validator *Validator, tree *bundle.Bundle, root string) (*Package, error) {
	filtered, err := filterLayout(tree, root)
	if err != nil {
		return nil, err
	}

	out := &Package{
		Kind:           filtered.kind,
		ManifestObject: filtered.kind.ManifestObject(),
		Files:          filtered.files,
		Layout: LayoutReport{
			Kept:    filtered.kept,
			Dropped: filtered.dropped,
			Links:   filtered.links,
		},
	}

	manifestNote, manifestErr := out.readManifests(validator, filtered)
	out.Layout.Entries = describeLayout(filtered, manifestNote)
	if manifestErr != nil {
		return out, manifestErr
	}

	components, err := filtered.deriveComponents(validator)
	if err != nil {
		return out, err
	}
	out.Components = components

	if err := filtered.checkDeclaredComponents(schemaIDOf(out), out.Expected, out.MCP); err != nil {
		return out, err
	}
	return out, nil
}

// readManifests validates the root manifest and mcp.json and returns the
// panel note for the manifest line.
func (p *Package) readManifests(validator *Validator, filtered *layout) (string, error) {
	manifest, ok := filtered.files.Lookup(p.ManifestObject)
	if !ok {
		return "missing", fmt.Errorf("%w: %s was filtered away", ErrNoManifest, p.ManifestObject)
	}
	p.ManifestBytes = manifest.Data

	switch p.Kind {
	case KindPlugin:
		plugin, err := validator.ValidatePluginManifest(manifest.Data)
		if err != nil {
			return manifestFailureNote(err), err
		}
		p.Plugin = plugin
		p.Name = plugin.Name
		p.Keywords = plugin.Keywords
		p.ManifestJSON = plugin.Raw()

		if plugin.Version != "" {
			normalised, semverErr := NormaliseSemver(plugin.Version)
			if semverErr != nil {
				return manifestFailureNote(semverErr), semverErr
			}
			p.Semver = normalised
		}

		expected, present, err := plugin.AgentManager()
		if err != nil {
			return manifestFailureNote(err), err
		}
		if present {
			p.Expected = expected
		}

	case KindSkill:
		skill, err := validator.ValidateSkillFrontmatter(manifest.Data)
		if err != nil {
			return manifestFailureNote(err), err
		}
		p.Skill = skill
		p.Name = skill.Name

		encoded, err := skill.ManifestJSON()
		if err != nil {
			return "invalid", err
		}
		p.ManifestJSON = encoded

	default:
		return "invalid", fmt.Errorf("unknown package kind %q", p.Kind)
	}

	if filtered.hasMCP {
		file, _ := filtered.files.Lookup(MCPConfigFile)
		config, err := validator.ValidateMCPConfig(file.Data)
		if err != nil {
			return "schema valid", err
		}
		p.MCP = config
	}
	return "schema valid", nil
}

func (p *Package) ExpectedCapabilities() []ExpectedCapability {
	if p.Expected == nil {
		return nil
	}
	return p.Expected.ExpectedCapabilities
}

func (p *Package) ComponentCount(kind ComponentKind) int {
	n := 0
	for i := range p.Components {
		if p.Components[i].Kind == kind {
			n++
		}
	}
	return n
}

func schemaIDOf(p *Package) string {
	if p.Plugin != nil {
		return p.Plugin.Schema
	}
	return SkillFrontmatterSchema
}

func manifestFailureNote(err error) string {
	var manifestErr *ManifestError
	if errors.As(err, &manifestErr) && len(manifestErr.Problems) > 0 {
		return "schema invalid: " + manifestErr.Problems[0].SchemaPath
	}
	return "schema invalid"
}

func describeLayout(filtered *layout, manifestNote string) []LayoutEntry {
	entries := make([]LayoutEntry, 0, 4+len(filtered.extDirs))

	entries = append(entries, LayoutEntry{
		Path: filtered.kind.ManifestObject(),
		Note: manifestNote,
		Kept: true,
	})

	if n := len(filtered.skillDirs); n > 0 {
		entries = append(entries, LayoutEntry{
			Path: SkillsDir + "/",
			Note: plural(n, "skill"),
			Kept: true,
		})
	}
	if filtered.hasMCP {
		entries = append(entries, LayoutEntry{
			Path: MCPConfigFile,
			Note: mcpNote(filtered),
			Kept: true,
		})
	}
	for _, ext := range filtered.extDirs {
		entries = append(entries, LayoutEntry{
			Path: ext.name + "/" + ext.firstChild,
			Note: "client extension",
			Kept: true,
		})
	}
	if kept := supportEntry(filtered); kept != nil {
		entries = append(entries, *kept)
	}

	if groups := (LayoutReport{Dropped: filtered.dropped}).DroppedGroups(); len(groups) > 0 {
		entries = append(entries, LayoutEntry{
			Path: joinGroups(groups),
			Note: "outside spec, dropped",
			Kept: false,
		})
	}
	if groups := (LayoutReport{Dropped: filtered.links}).DroppedGroups(); len(groups) > 0 {
		entries = append(entries, LayoutEntry{
			Path: joinGroups(groups),
			Note: "link, not stored",
			Kept: false,
		})
	}
	return entries
}

// mcpNote counts servers without re-validating: the panel must render even
// when mcp.json failed its schema.
func mcpNote(filtered *layout) string {
	file, ok := filtered.files.Lookup(MCPConfigFile)
	if !ok {
		return "1 server"
	}
	var probe struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(file.Data, &probe); err != nil {
		return "unreadable"
	}
	return plural(len(probe.MCPServers), "server")
}

func supportEntry(filtered *layout) *LayoutEntry {
	if filtered.kind != KindSkill {
		return nil
	}
	present := make([]string, 0, len(skillSupportDirs))
	for _, support := range skillSupportDirs {
		for _, path := range filtered.kept {
			if topSegment(path) == support {
				present = append(present, support+"/")
				break
			}
		}
	}
	if len(present) == 0 {
		return nil
	}
	return &LayoutEntry{Path: joinGroups(present), Note: "skill resources", Kept: true}
}

func joinGroups(groups []string) string {
	out := ""
	for i, group := range groups {
		if i > 0 {
			out += ", "
		}
		out += group
	}
	return out
}
