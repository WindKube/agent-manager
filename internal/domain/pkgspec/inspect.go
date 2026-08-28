package pkgspec

import (
	"encoding/json"
	"errors"
	"fmt"

	"agent-manager/internal/bundle"
)

// Package is everything the ingestion path learns from a fetched tree.
//
// One function produces it and two callers consume it: the API's pre-submit
// preview and the fetcher's authoritative pass. That is deliberate — a preview
// that said "schema valid" and a fetch that then rejected the manifest would be a
// worse lie than no preview at all.
type Package struct {
	// Kind is decided by which manifest is at the package root, never by a
	// manifest field.
	Kind Kind

	// Name is the manifest `name`, which is the catalog's package name.
	Name string

	// Semver is the manifest `version`, normalised. Empty when the manifest
	// carried none: `version` is optional in Agent Plugins, so the registration
	// supplies one (from the ref, or the form) and this is only the manifest's
	// opinion.
	Semver string

	// Keywords is the manifest `keywords`, which become the version's tags. Tags
	// belong to the version and not the package (data-model.md, R1).
	Keywords []string

	// ManifestObject is `plugin.json` or `SKILL.md` — the object name the manifest
	// is stored under beside the bundle (FR-006).
	ManifestObject string

	// ManifestBytes is the manifest verbatim, as stored beside the bundle.
	ManifestBytes []byte

	// ManifestJSON is what `version.manifest` holds. For a plugin it is
	// ManifestBytes; for a skill it is the frontmatter rendered as json, because
	// the column is jsonb and a Markdown file is not json.
	ManifestJSON json.RawMessage

	Plugin *Plugin
	Skill  *Skill
	MCP    *MCPConfig

	// Expected is `extensions["dev.agent-manager"]` when the publisher recorded
	// one. Nil means no expectation, which is the case where every inferred
	// capability is surfaced for review rather than passing silently (FR-018a).
	Expected *AgentManagerExtension

	// Components are derived from the file tree (T038).
	Components []Component

	// Layout is the drop report FR-005 requires be shown before registration.
	Layout LayoutReport

	// Files is the filtered tree: exactly what gets packed and stored.
	Files *bundle.Bundle
}

// Inspect filters a fetched tree to the spec layout, validates its manifests and
// derives its components.
//
// The first result is non-nil whenever the layout could be computed, EVEN WHEN
// err is non-nil. That is what lets the pre-submit preview render the
// archive-contents panel with the manifest line marked as failing, instead of
// showing the user an error and no entry list. A caller that intends to publish
// must check err; a caller that intends to display should use both.
func Inspect(tree *bundle.Bundle, root string) (*Package, error) {
	validator, err := Default()
	if err != nil {
		return nil, err
	}
	return InspectWith(validator, tree, root)
}

// InspectWith is Inspect against a caller-supplied validator.
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
		},
	}

	manifestNote, manifestErr := out.readManifests(validator, filtered)
	out.Layout.Entries = describeLayout(filtered, manifestNote)
	if manifestErr != nil {
		return out, manifestErr
	}

	components, err := filtered.deriveComponents(validator, out.MCP)
	if err != nil {
		return out, err
	}
	out.Components = components

	// The manifest-versus-tree check runs after derivation so its message can name
	// what is actually on disk.
	if err := filtered.checkDeclaredComponents(schemaIDOf(out), out.Expected, out.MCP); err != nil {
		return out, err
	}
	return out, nil
}

// readManifests validates the root manifest and mcp.json, filling the Package.
// The returned string is the note the archive-contents panel shows against the
// manifest line.
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

// ExpectedCapabilities is the recorded expectation, or nil. It exists so a caller
// need not reason about whether the extension namespace was present.
func (p *Package) ExpectedCapabilities() []ExpectedCapability {
	if p.Expected == nil {
		return nil
	}
	return p.Expected.ExpectedCapabilities
}

// ComponentCount is how many components of a kind were derived.
func (p *Package) ComponentCount(kind ComponentKind) int {
	n := 0
	for _, component := range p.Components {
		if component.Kind == kind {
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

// describeLayout renders the archive-contents panel: one line per spec group in
// the design's order, then one line for everything dropped.
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
			Path: ext.name + "/" + ext.firstChild + "/",
			Note: "client extension",
			Kept: true,
		})
	}
	if kept := supportEntry(filtered); kept != nil {
		entries = append(entries, *kept)
	}

	// FR-005's second half. One line, matching the design's `.github/, README.md`.
	if groups := (LayoutReport{Dropped: filtered.dropped}).DroppedGroups(); len(groups) > 0 {
		entries = append(entries, LayoutEntry{
			Path: joinGroups(groups),
			Note: "outside spec, dropped",
			Kept: false,
		})
	}
	return entries
}

// mcpNote counts the configured servers without re-validating: the panel has to
// render even when mcp.json failed its schema, and a count of top-level keys is
// the honest thing to show then.
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

// supportEntry is the standalone-skill case: SKILL.md plus its resource
// directories, which have no group line of their own above.
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
