package fakeapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"agent-manager/internal/apiclient"
)

const day = 24 * time.Hour

type seedVersion struct {
	version  string
	distTag  apiclient.PackageVersionDistTag
	verdict  apiclient.PackageVersionVerdict
	age      time.Duration
	pinnedBy int64
}

type seedPackage struct {
	id, publisher, category, version string
	age                              time.Duration
	kind                             apiclient.CatalogPackageKind
	verdict                          apiclient.CatalogPackageVerdict
	uses                             int64
	tags                             []string

	description string
	// tools is the skill frontmatter's allowed-tools; nil falls back to Read, Grep.
	tools      []string
	parent     string
	components []apiclient.PackageComponent
	versions   []seedVersion
	caps       apiclient.PackageCapabilities
	dependents []apiclient.PackageDependent

	// repo and subdir make a git-sourced package whose versions come from
	// tags v<semver>; archive is an archive-url one. Neither is an upload.
	repo, subdir, archive string
}

func capability(name apiclient.PackageCapabilityName, level apiclient.PackageCapabilityLevel, detail ...string) apiclient.PackageCapability {
	if detail == nil {
		detail = []string{}
	}
	return apiclient.PackageCapability{Name: name, Level: level, Detail: detail}
}

func component(kind apiclient.PackageComponentKind, name, path, note string) apiclient.PackageComponent {
	return apiclient.PackageComponent{Kind: kind, Name: name, Path: path, Note: &note}
}

func dependent(slug, name string, mode apiclient.PackageDependentMode, pin string) apiclient.PackageDependent {
	out := apiclient.PackageDependent{Slug: slug, Name: name, Mode: mode}
	switch mode {
	case apiclient.PackageDependentModePinned:
		out.Version = &pin
	case apiclient.PackageDependentModeRange:
		out.Range = &pin
	}
	return out
}

func scanned(inferred []apiclient.PackageCapability, expected ...apiclient.PackageCapability) apiclient.PackageCapabilities {
	if expected == nil {
		expected = []apiclient.PackageCapability{}
	}
	return apiclient.PackageCapabilities{Scanned: true, Inferred: inferred, Expected: expected}
}

const (
	allowlisted = apiclient.PackageCapabilityLevelAllowlisted
	scoped      = apiclient.PackageCapabilityLevelScoped
	review      = apiclient.PackageCapabilityLevelReview
	skillKind   = apiclient.PackageComponentKindSkill
	mcpKind     = apiclient.PackageComponentKindMcp
)

func seedPackages() []seedPackage {
	plugin, skill := apiclient.CatalogPackageKindPlugin, apiclient.CatalogPackageKindSkill
	clean, scanning, flagged := apiclient.CatalogPackageVerdictClean, apiclient.CatalogPackageVerdictScanning, apiclient.CatalogPackageVerdictFlagged
	latest, pinned, ranged := apiclient.PackageDependentModeLatest, apiclient.PackageDependentModePinned, apiclient.PackageDependentModeRange

	return []seedPackage{
		{
			id: "example/platform-toolkit", publisher: "example/platform", category: "Infrastructure",
			version: "1.3.0", age: 2 * day, kind: plugin, verdict: clean, uses: 42,
			repo:        "https://github.com/example/platform-toolkit",
			tags:        []string{"terraform", "aws", "guardrails", "scaffolding"},
			description: "Platform guardrails, ADR authoring and service scaffolding in one portable package.",
			components: []apiclient.PackageComponent{
				component(skillKind, "terraform-module-review", "skills/terraform-module-review", "SKILL.md + scripts/"),
				component(skillKind, "adr-writer", "skills/adr-writer", "SKILL.md + references/"),
				component(skillKind, "service-scaffold", "skills/service-scaffold", "SKILL.md + scripts/"),
				component(skillKind, "cost-explainer", "skills/cost-explainer", "SKILL.md"),
				component(mcpKind, "terraform-registry", "mcp.json", "streamable http · registry.terraform.io"),
				component(apiclient.PackageComponentKindExt, "com.anthropic.claude-code", "com.anthropic.claude-code", "client extension: hooks/"),
			},
			caps: scanned([]apiclient.PackageCapability{
				capability(apiclient.Network, allowlisted, "registry.terraform.io"),
				capability(apiclient.FilesystemRead, scoped, "references/", "scripts/"),
				capability(apiclient.Shell, review, "terraform", "jq"),
			}, capability(apiclient.Network, allowlisted, "registry.terraform.io")),
			dependents: []apiclient.PackageDependent{dependent("platform-engineer", "Platform Engineer", latest, "")},
		},
		{
			id: "example/security-review-kit", publisher: "example/security", category: "Security & compliance",
			version: "2.0.1", age: 4 * day, kind: plugin, verdict: clean, uses: 31,
			tags:        []string{"pii", "security", "review"},
			description: "PII redaction, dependency review and scanner triage helpers for reviewers.",
			components: []apiclient.PackageComponent{
				component(skillKind, "pii-redactor", "skills/pii-redactor", "SKILL.md + scripts/"),
				component(skillKind, "dependency-review", "skills/dependency-review", "SKILL.md"),
				component(skillKind, "scanner-triage", "skills/scanner-triage", "SKILL.md + references/"),
				component(mcpKind, "vuln-db", "mcp.json", "stdio · runs locally"),
			},
			caps: scanned([]apiclient.PackageCapability{
				capability(apiclient.FilesystemRead, scoped, "references/"),
				capability(apiclient.Shell, review, "rg"),
			}),
			dependents: []apiclient.PackageDependent{dependent("security-review", "Security Review", latest, "")},
		},
		{
			id: "community/release-toolkit", publisher: "community/octoflow", category: "Developer workflow",
			version: "1.2.7", age: 6 * time.Hour, kind: plugin, verdict: scanning, uses: 6,
			archive:     "https://releases.octoflow.dev/release-toolkit-1.2.7.tar.gz",
			tags:        []string{"github", "changelog", "releases"},
			description: "Drafts release notes and changelogs from merged pull requests.",
			components: []apiclient.PackageComponent{
				component(skillKind, "release-notes", "skills/release-notes", "SKILL.md"),
				component(mcpKind, "github", "mcp.json", "streamable http · api.github.com"),
			},
			caps: apiclient.PackageCapabilities{Inferred: []apiclient.PackageCapability{}, Expected: []apiclient.PackageCapability{}},
		},
		{
			id: "community/slack-digest", publisher: "community/hexley", category: "Developer workflow",
			version: "0.5.1", age: 2 * day, kind: plugin, verdict: flagged, uses: 3,
			tags:        []string{"slack", "summaries"},
			description: "Summarises channel activity into a daily digest.",
			components: []apiclient.PackageComponent{
				component(skillKind, "digest", "skills/digest", "SKILL.md + scripts/digest.sh"),
				component(mcpKind, "slack", "mcp.json", "streamable http · slack.com"),
			},
			caps: scanned([]apiclient.PackageCapability{
				capability(apiclient.Network, review, "collect.hexley-metrics.io", "slack.com"),
				capability(apiclient.Shell, review, "curl", "jq"),
			}, capability(apiclient.Network, allowlisted, "slack.com")),
		},
		{
			id: "example/terraform-module-review", publisher: "example/platform", category: "Infrastructure",
			version: "2.4.1", age: 2 * day, kind: skill, verdict: clean, uses: 38,
			tags: []string{"terraform", "review", "aws", "guardrails"},
			description: "Reviews Terraform plans and module changes against the platform guardrails: " +
				"tagging, remote state layout, IAM boundaries and drift on protected resources.",
			tools:  []string{"Read", "Grep", "Bash(terraform plan)"},
			parent: "example/platform-toolkit",
			versions: []seedVersion{
				{version: "2.4.1", distTag: apiclient.PackageVersionDistTagLatest, verdict: apiclient.PackageVersionVerdictClean, age: 2 * day},
				{version: "2.4.0", distTag: apiclient.PackageVersionDistTagNone, verdict: apiclient.PackageVersionVerdictClean, age: 21 * day, pinnedBy: 2},
				{version: "2.3.5", distTag: apiclient.PackageVersionDistTagArchived, verdict: apiclient.PackageVersionVerdictClean, age: 60 * day},
			},
			caps: scanned([]apiclient.PackageCapability{
				capability(apiclient.FilesystemRead, scoped, "references/guardrails.md"),
				capability(apiclient.Shell, review, "terraform"),
			}),
			dependents: []apiclient.PackageDependent{
				dependent("platform-engineer", "Platform Engineer", latest, ""),
				dependent("sre-oncall", "SRE On-call", pinned, "2.4.0"),
				dependent("security-review", "Security Review", latest, ""),
			},
		},
		{
			id: "example/k8s-incident-triage", publisher: "example/sre", category: "Infrastructure",
			version: "1.9.0", age: 5 * day, kind: skill, verdict: clean, uses: 22,
			tags:        []string{"kubernetes", "incident", "runbook"},
			description: "Walks an alert back to the failing workload and drafts the incident timeline.",
			tools:       []string{"Read", "Bash(kubectl get)"},
			caps:        scanned([]apiclient.PackageCapability{capability(apiclient.Shell, review, "kubectl")}),
			dependents:  []apiclient.PackageDependent{dependent("sre-oncall", "SRE On-call", latest, "")},
		},
		{
			id: "community/postgres-migration-guard", publisher: "community/dbtools", category: "Data",
			version: "0.8.3", age: day, kind: skill, verdict: flagged, uses: 9,
			tags:        []string{"postgres", "migrations"},
			description: "Checks migrations for locking, backfill and rollback hazards before they ship.",
			tools:       []string{"Read", "Bash(psql)"},
			caps: scanned([]apiclient.PackageCapability{
				capability(apiclient.FilesystemRead, review, "~/.aws/credentials", "~/.pgpass"),
				capability(apiclient.Shell, review, "psql"),
			}),
		},
		{
			id: "example/adr-writer", publisher: "example/architecture", category: "Documentation",
			version: "3.1.0", age: 21 * day, kind: skill, verdict: clean, uses: 47,
			repo: "https://github.com/example/architecture-skills", subdir: "adr-writer",
			tags:        []string{"adr", "docs", "review"},
			description: "Writes and supersedes architecture decision records in the house format.",
			tools:       []string{"Read", "Write", "Grep"},
			parent:      "example/platform-toolkit",
			caps: scanned([]apiclient.PackageCapability{
				capability(apiclient.FilesystemRead, scoped, "references/"),
				capability(apiclient.FilesystemWrite, scoped, "docs/adr/"),
			}, capability(apiclient.FilesystemWrite, scoped, "docs/adr/")),
			dependents: []apiclient.PackageDependent{dependent("platform-engineer", "Platform Engineer", ranged, "^3.1")},
		},
		{
			id: "community/aws-cost-explainer", publisher: "community/finops", category: "Infrastructure",
			version: "2.0.0", age: 7 * day, kind: skill, verdict: clean, uses: 15,
			tags:        []string{"aws", "cost", "finops"},
			description: "Explains a cost spike by service, account and tag, then proposes cuts.",
			tools:       []string{"Read", "WebFetch"},
			caps: scanned([]apiclient.PackageCapability{
				capability(apiclient.Network, allowlisted, "ce.us-east-1.amazonaws.com"),
				capability(apiclient.FilesystemWrite, review, "**"),
				capability(apiclient.Shell, review, "aws"),
			}, capability(apiclient.FilesystemWrite, scoped, "reports/")),
		},
		{
			id: "example/pii-redactor", publisher: "example/security", category: "Security & compliance",
			version: "1.4.2", age: 4 * day, kind: skill, verdict: clean, uses: 34,
			tags:        []string{"pii", "security"},
			description: "Finds and masks personal data in logs, fixtures and support transcripts.",
			tools:       []string{"Read", "Write"},
			parent:      "example/security-review-kit",
			caps: scanned([]apiclient.PackageCapability{
				capability(apiclient.FilesystemRead, scoped, "fixtures/"),
				capability(apiclient.FilesystemWrite, scoped, "out/"),
			}, capability(apiclient.Shell, review)),
			dependents: []apiclient.PackageDependent{dependent("security-review", "Security Review", pinned, "1.4.2")},
		},
	}
}

func seedCatalog(d *Data, now time.Time) {
	d.Details = map[string]apiclient.PackageDetail{}
	packages := seedPackages()
	for i := range packages {
		p := &packages[i]
		_, name, _ := strings.Cut(p.id, "/")
		category := p.category
		d.Packages = append(d.Packages, apiclient.CatalogPackage{
			Id: p.id, Name: name, Publisher: p.publisher, Category: &category,
			Version: p.version, UpdatedAt: now.Add(-p.age), Kind: p.kind,
			Verdict: p.verdict, Visibility: apiclient.CatalogPackageVisibilityOrganisation,
			Uses: p.uses, Tags: p.tags,
		})
		d.Details[p.id] = packageDetail(*p, name, now)
	}
	seedFiles(d)
}

func packageDetail(p seedPackage, name string, now time.Time) apiclient.PackageDetail {
	namespace, _, _ := strings.Cut(p.id, "/")
	category, description := p.category, p.description
	detail := apiclient.PackageDetail{
		Id:           p.id,
		Name:         name,
		Kind:         apiclient.PackageDetailKind(p.kind),
		Publisher:    apiclient.PackagePublisher{Slug: p.publisher, Verified: strings.HasPrefix(p.publisher, "example")},
		Category:     &category,
		Description:  &description,
		Version:      p.version,
		Verdict:      apiclient.PackageDetailVerdict(p.verdict),
		Visibility:   apiclient.PackageDetailVisibilityOrganisation,
		Tags:         p.tags,
		Components:   p.components,
		Capabilities: p.caps,
		Dependents:   p.dependents,
	}
	if detail.Components == nil {
		detail.Components = []apiclient.PackageComponent{}
	}
	if detail.Dependents == nil {
		detail.Dependents = []apiclient.PackageDependent{}
	}

	if p.kind == apiclient.CatalogPackageKindPlugin {
		detail.Origin.SpecVersion = ptr("1.0.0")
		detail.ManifestObject = apiclient.PluginJson
		detail.Manifest = pluginManifest(name, p)
	} else {
		detail.ManifestObject = apiclient.SKILLMd
		detail.Manifest = skillManifest(name, p)
		if p.parent != "" {
			_, parentName, _ := strings.Cut(p.parent, "/")
			detail.Origin.ParentId = ptr(p.parent)
			detail.Origin.ParentName = &parentName
		}
	}

	versions := p.versions
	if len(versions) == 0 {
		versions = []seedVersion{{
			version: p.version, distTag: apiclient.PackageVersionDistTagLatest,
			verdict: apiclient.PackageVersionVerdict(p.verdict), age: p.age,
		}}
	}
	switch {
	case p.repo != "":
		detail.Source = &apiclient.PackageSource{
			Kind: apiclient.PackageSourceKindGit, Url: ptr(p.repo), Ref: ptr("v" + p.version),
		}
		if p.subdir != "" {
			detail.Source.Subdirectory = ptr(p.subdir)
		}
	case p.archive != "":
		detail.Source = &apiclient.PackageSource{Kind: apiclient.PackageSourceKindArchiveUrl, Url: ptr(p.archive)}
	default:
		detail.Source = &apiclient.PackageSource{Kind: apiclient.PackageSourceKindUpload}
	}

	for _, v := range versions {
		key := "skills/" + namespace + "/" + name + "/" + v.version + "/bundle.tar.zst"
		sum := sha256.Sum256([]byte(key))
		version := apiclient.PackageVersion{
			Version: v.version, DistTag: v.distTag, Verdict: v.verdict,
			CreatedAt: now.Add(-v.age), ObjectKey: key, PinnedBy: v.pinnedBy,
			Digest:    ptr("sha256:" + hex.EncodeToString(sum[:])),
			SizeBytes: ptr(int64(18842)),
		}
		switch {
		case p.repo != "":
			commit := sha256.Sum256([]byte("commit " + key))
			version.SourceUrl, version.SourceRef = ptr(p.repo), ptr("v"+v.version)
			version.SourceCommit = ptr(hex.EncodeToString(commit[:20]))
		case p.archive != "":
			version.SourceUrl = ptr(p.archive)
		}
		detail.Versions = append(detail.Versions, version)
	}
	return detail
}

func pluginManifest(name string, p seedPackage) string {
	manifest := map[string]any{
		"$schema":     "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
		"name":        name,
		"version":     p.version,
		"description": p.description,
		"keywords":    p.tags,
		"license":     "Apache-2.0",
	}
	if expected := expectedFrom(p.caps); expected != nil {
		manifest["extensions"] = map[string]any{"dev.agent-manager": expected}
	}
	return encode(manifest)
}

func skillManifest(name string, p seedPackage) string {
	tools := p.tools
	if tools == nil {
		tools = []string{"Read", "Grep"}
	}
	manifest := map[string]any{
		"name":          name,
		"description":   p.description,
		"license":       "Apache-2.0",
		"allowed-tools": tools,
	}
	// A skill's frontmatter has no extensions key, so the declaration lives in metadata.
	if expected := expectedFrom(p.caps); expected != nil {
		manifest["metadata"] = map[string]any{"dev.agent-manager": expected}
	}
	return encode(manifest)
}

func expectedFrom(caps apiclient.PackageCapabilities) map[string]any {
	if len(caps.Expected) == 0 {
		return nil
	}
	declared := make([]map[string]any, 0, len(caps.Expected))
	for _, c := range caps.Expected {
		entry := map[string]any{"name": string(c.Name), "level": string(c.Level)}
		if len(c.Detail) > 0 {
			entry["detail"] = c.Detail
		}
		declared = append(declared, entry)
	}
	return map[string]any{"expectedCapabilities": declared}
}

func encode(manifest map[string]any) string {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

type seedFile struct {
	path    string
	kind    apiclient.PackageFileKind
	size    int64
	content string
}

func seedFiles(d *Data) {
	files := map[string][]seedFile{
		"example/adr-writer": {
			{path: "SKILL.md", kind: apiclient.PackageFileKindMarkdown, size: 612, content: "# ADR writer\n\n" +
				"Writes and supersedes architecture decision records in the house format.\n\n" +
				"## Usage\n\n1. Run `/adr new <title>`.\n2. Fill in the context and decision sections.\n" +
				"3. Link the superseded record, if any.\n"},
			{path: "references/template.md", kind: apiclient.PackageFileKindMarkdown, size: 84,
				content: "# Template\n\nContext, decision, consequences.\n"},
		},
		"example/platform-toolkit": {
			{path: "plugin.json", kind: apiclient.PackageFileKindText, size: 218, content: `{"name":"platform-toolkit","version":"1.3.0"}`},
			{path: "skills/adr-writer/SKILL.md", kind: apiclient.PackageFileKindMarkdown, size: 612,
				content: "# ADR writer\n\nBundled here; see example/adr-writer for the standalone skill.\n"},
		},
	}

	d.Files = map[string]apiclient.PackageFileList{}
	d.FileContents = map[string]map[string]apiclient.PackageFileContent{}
	for key, list := range files {
		out := apiclient.PackageFileList{Files: make([]apiclient.PackageFile, 0, len(list))}
		contents := map[string]apiclient.PackageFileContent{}
		for _, f := range list {
			out.Files = append(out.Files, apiclient.PackageFile{Path: f.path, Kind: f.kind, SizeBytes: f.size})
			contents[f.path] = apiclient.PackageFileContent{
				Path: f.path, Kind: apiclient.PackageFileContentKind(f.kind), Content: f.content,
			}
			// A root SKILL.md wins over plugin.json, as listPackageFiles picks it.
			if f.path == "SKILL.md" || (f.path == "plugin.json" && out.Default == nil) {
				out.Default = ptr(f.path)
			}
		}
		d.Files[key] = out
		d.FileContents[key] = contents
	}
}
