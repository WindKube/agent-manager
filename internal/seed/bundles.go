package seed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"agent-manager/internal/blob"
	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/store/models"
)

// Every seeded version is a real tree built from the domain types and run
// through pkgspec.Inspect like the fetcher does, so a nonconforming manifest
// fails the seed instead of reaching a screen. bundle.Pack is deterministic, so
// digests are stable across runs.

// builtVersion is one version, ready for both halves of the write.
type builtVersion struct {
	pkg  *packageSpec
	spec versionSpec
	ref  blob.VersionRef

	inspected *pkgspec.Package
	packed    []byte
	digest    [32]byte
	size      int64
}

func (b *builtVersion) id() string { return b.pkg.id() }

// build turns the dataset into bytes without touching anything external.
func build() ([]*builtVersion, error) {
	out := make([]*builtVersion, 0, 16)
	for i := range designPackages {
		spec := &designPackages[i]
		for _, version := range spec.versions {
			built, err := buildVersion(spec, version)
			if err != nil {
				return nil, err
			}
			out = append(out, built)
		}
	}
	return out, nil
}

func buildVersion(spec *packageSpec, version versionSpec) (*builtVersion, error) {
	ref := blob.VersionRef{
		Namespace: namespaceOf(spec.publisher),
		Name:      spec.name,
		Semver:    version.semver,
	}
	if err := ref.Validate(); err != nil {
		return nil, err
	}

	tree, err := buildTree(spec, version.semver)
	if err != nil {
		return nil, fmt.Errorf("build the tree of %s: %w", ref, err)
	}

	inspected, err := pkgspec.Inspect(tree, "")
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", ref, err)
	}
	if inspected.Name != spec.name {
		return nil, fmt.Errorf("%s: the manifest names %q", ref, inspected.Name)
	}
	// Skill frontmatter has no version field, so only plugins can disagree.
	if spec.kind == models.PackageKindPlugin && inspected.Semver != version.semver {
		return nil, fmt.Errorf("%s: the manifest names version %q", ref, inspected.Semver)
	}
	if string(inspected.Kind) != string(spec.kind) {
		return nil, fmt.Errorf("%s: the tree is a %s", ref, inspected.Kind)
	}

	// Pack the filtered tree, matching what the fetcher would store.
	packed, digest, size, err := bundle.Pack(inspected.Files)
	if err != nil {
		return nil, fmt.Errorf("pack %s: %w", ref, err)
	}
	body, err := io.ReadAll(packed)
	if err != nil {
		return nil, fmt.Errorf("pack %s: %w", ref, err)
	}

	return &builtVersion{
		pkg: spec, spec: version, ref: ref,
		inspected: inspected, packed: body, digest: digest, size: size,
	}, nil
}

func buildTree(spec *packageSpec, semver string) (*bundle.Bundle, error) {
	files := make([]fileSpec, 0, 8)

	switch spec.kind {
	case models.PackageKindPlugin:
		manifest, err := pluginManifest(spec, semver)
		if err != nil {
			return nil, err
		}
		files = append(files, fileSpec{path: pkgspec.PluginManifest, body: string(manifest)})

		for _, skill := range spec.skills {
			dir := pkgspec.SkillsDir + "/" + skill.name
			frontmatter, err := skillManifest(skill.name, skill.description, skill.tools, nil)
			if err != nil {
				return nil, err
			}
			files = append(files, fileSpec{path: dir + "/" + pkgspec.SkillManifest, body: frontmatter})
			for _, file := range skill.files {
				files = append(files, fileSpec{path: dir + "/" + file.path, body: file.body, exec: file.exec})
			}
		}

		if len(spec.servers) > 0 {
			config, err := mcpConfig(spec.servers)
			if err != nil {
				return nil, err
			}
			files = append(files, fileSpec{path: pkgspec.MCPConfigFile, body: string(config)})
		}

		for _, ext := range spec.extensions {
			for _, file := range ext.files {
				files = append(files, fileSpec{path: ext.dir + "/" + file.path, body: file.body, exec: file.exec})
			}
		}

	default:
		frontmatter, err := skillManifest(spec.name, spec.description, spec.tools, spec.expected)
		if err != nil {
			return nil, err
		}
		files = append(files, fileSpec{path: pkgspec.SkillManifest, body: frontmatter})
	}

	files = append(files, spec.files...)

	if spec.flaw.carriedBy(semver) {
		var found bool
		for i := range files {
			if files[i].path != spec.flaw.path {
				continue
			}
			files[i].body = strings.TrimRight(files[i].body, "\n") + "\n" + spec.flaw.line + "\n"
			found = true
		}
		if !found {
			return nil, fmt.Errorf("%s@%s: the flaw names %s, which the tree does not contain",
				spec.id(), semver, spec.flaw.path)
		}
	}

	tree := bundle.New()
	for _, file := range files {
		mode := bundle.FileMode
		if file.exec {
			mode = bundle.ExecMode
		}
		if err := tree.Add(file.path, mode, []byte(file.body)); err != nil {
			return nil, err
		}
	}
	return tree, nil
}

// pluginManifest marshals the domain Plugin type, so it cannot emit keys the
// schema would refuse.
func pluginManifest(spec *packageSpec, semver string) ([]byte, error) {
	manifest := pkgspec.Plugin{
		Schema:      pkgspec.PluginSchema100,
		Name:        spec.name,
		Version:     semver,
		Description: spec.description,
		License:     licence,
		Keywords:    spec.keywords,
	}
	if extension := agentManagerExtension(spec.expected, spec.declared); extension != nil {
		encoded, err := json.Marshal(extension)
		if err != nil {
			return nil, err
		}
		manifest.Extensions = pkgspec.ExtensionSet{pkgspec.ExtensionNamespace: encoded}
	}
	return json.MarshalIndent(manifest, "", "  ")
}

// skillManifest renders SKILL.md. Expected capabilities go under `metadata`
// because the Agent Skills schema refuses an `extensions` key.
func skillManifest(name, description string, tools []string, expected []capabilitySpec) (string, error) {
	front := pkgspec.Skill{
		Name:         name,
		Description:  description,
		License:      licence,
		AllowedTools: tools,
	}
	if extension := agentManagerExtension(expected, nil); extension != nil {
		generic, err := asMap(extension)
		if err != nil {
			return "", err
		}
		front.Metadata = map[string]any{pkgspec.ExtensionNamespace: generic}
	}

	encoded, err := yaml.Marshal(front)
	if err != nil {
		return "", err
	}

	body := fmt.Sprintf("# %s\n\n%s\n", name, description)
	return "---\n" + string(encoded) + "---\n\n" + body, nil
}

func agentManagerExtension(expected []capabilitySpec, declared []string) *pkgspec.AgentManagerExtension {
	if len(expected) == 0 && len(declared) == 0 {
		return nil
	}
	out := &pkgspec.AgentManagerExtension{Components: declared}
	for _, entry := range expected {
		out.ExpectedCapabilities = append(out.ExpectedCapabilities, pkgspec.ExpectedCapability{
			Name:   entry.name,
			Level:  entry.level,
			Detail: entry.detail,
		})
	}
	return out
}

func mcpConfig(servers []serverSpec) ([]byte, error) {
	config := pkgspec.MCPConfig{
		Schema:     pkgspec.MCPSchema100,
		MCPServers: make(map[string]pkgspec.MCPServer, len(servers)),
	}
	for _, server := range servers {
		config.MCPServers[server.name] = pkgspec.MCPServer{
			Type:    server.transport,
			URL:     server.url,
			Command: server.command,
			Args:    server.args,
		}
	}
	return json.MarshalIndent(config, "", "  ")
}

// asMap re-encodes a typed value as a generic map for yaml.Marshal, avoiding a
// second literal that could drift from the typed one.
func asMap(value any) (map[string]any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// commitBytes writes every seeded version's objects through blob.Committer,
// which writes index.json last and skips versions the index already names.
func commitBytes(ctx context.Context, deps Deps, built []*builtVersion) (int, error) {
	committer := blob.NewCommitter(deps.BlobRead, deps.BlobWrite)

	written := 0
	for _, version := range built {
		commit, err := committer.Commit(ctx, version.ref, blob.VersionParts{
			Bundle:             bytes.NewReader(version.packed),
			ManifestObjectName: version.inspected.ManifestObject,
			Manifest:           version.inspected.ManifestBytes,
			Latest:             version.spec.distTag == models.DistTagLatest,
		})
		if err != nil {
			return written, err
		}
		if commit.AlreadyCommitted {
			continue
		}
		if commit.Bundle.Digest != version.digest || commit.Bundle.Size != version.size {
			return written, fmt.Errorf("%s: the bucket recorded a different bundle than was packed", version.ref)
		}
		written++
	}
	return written, nil
}
