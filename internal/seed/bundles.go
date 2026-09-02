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

// The bytes half of the seed.
//
// Every seeded version is a real tree: a manifest built by MARSHALLING the domain
// types (so a field the published schemas do not define cannot be written at
// all), the files a scanner would read, then pkgspec.Inspect over the whole thing
// — the same validation, the same layout filter and the same component derivation
// the fetcher runs. A manifest that stopped conforming would fail the seed rather
// than reach a screen, which is the point: 001's research R1 found that the
// design's own manifests are rejected by the published schemas, and a fixture
// nobody validates is how that gets discovered by a user instead.
//
// bundle.Pack is deterministic — path order, epoch mtimes, two modes — so the
// same dataset produces the same digest on every run, and the digest a seeded row
// carries is the digest of the bytes actually in the bucket.

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

// build turns the dataset into bytes. It touches nothing outside this process.
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
	// Only a plugin manifest carries a version. Agent Skills frontmatter has no
	// such field, so a skill's semver comes from the registration and there is
	// nothing here to disagree with.
	if spec.kind == models.PackageKindPlugin && inspected.Semver != version.semver {
		return nil, fmt.Errorf("%s: the manifest names version %q", ref, inspected.Semver)
	}
	if string(inspected.Kind) != string(spec.kind) {
		return nil, fmt.Errorf("%s: the tree is a %s", ref, inspected.Kind)
	}

	// The FILTERED tree is what gets packed: a seeded bundle must be what the
	// fetcher would have stored, not what the dataset happened to describe.
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

// pluginManifest marshals the domain's own Plugin type, which is why the result
// cannot carry `agentPluginsVersion`, `components`, `network`, `filesystem` or
// `signature`: the type has no field for any of them, and the schema this is then
// validated against refuses unknown keys outright.
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

// skillManifest renders SKILL.md: the frontmatter fence, then the prose an agent
// reads. The expected capability set goes under `metadata` rather than
// `extensions`, because Agent Skills frontmatter has no `extensions` key and its
// schema refuses one (FR-018a).
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

// asMap re-encodes a typed value as the generic form yaml.Marshal can emit. The
// alternative is a second literal of the same structure, which is how a manifest
// and the panel beside it start disagreeing.
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

// commitBytes writes every seeded version's objects.
//
// blob.Committer is used rather than a bare writer because it is the only thing
// that writes index.json last, and a seeded package whose index does not name its
// versions is invisible to blob.Catalog — the same half-published state FR-008
// exists to prevent. It also carries the idempotence for this half: a version the
// index already names short-circuits, so a re-run writes no object at all.
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
