package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"agent-manager/internal/web/view"
)

// The detail-screen half of the fixture (US3), transcribed from
// docs/design/agent-manager.dc.html: items() at lines 867-920 for the packages
// and their components, and the version list and `usedIn` at lines 1053-1063.
//
// THE MANIFESTS ARE NOT THE DESIGN'S. research.md R1: the design draws
// `agentPluginsVersion`, `publisher`, `components`, `signature`, `network` and
// `filesystem`, and none of those fields exist — Agent Plugins 1.0.0 permits ten
// fields with additionalProperties:false, and Agent Skills six. Reproducing them
// here would make every screen test assert against a manifest this hub refuses
// at registration. They are rewritten as conformant documents, with the expected
// capability set in the one conformant home it has (FR-018a).

// Package implements web.PackageSource over the same ten rows the catalog
// serves, so a link the catalog renders leads to a page this fixture can answer.
//
// An id that is not one of them is view.ErrNotFound, which is the same answer
// the api gives for a package the caller may not read — one answer for both, on
// purpose.
func (c *Catalog) Package(_ context.Context, namespace, name string) (view.Package, error) {
	id := namespace + "/" + name
	for i := range c.rows {
		if c.rows[i].ID == id {
			return detailOf(&c.rows[i]), nil
		}
	}
	return view.Package{}, view.ErrNotFound
}

// IDs is every package the fixture can serve, so a test can walk all of them
// rather than naming a few and calling it coverage (T062).
func (c *Catalog) IDs() []string {
	out := make([]string, 0, len(c.rows))
	for i := range c.rows {
		out = append(out, c.rows[i].ID)
	}
	return out
}

// extras is everything the detail screen needs that the catalog row does not
// carry.
type extras struct {
	description string
	// tools is the skill frontmatter's `allowed-tools`. It is EXPERIMENTAL and is
	// not an enforcement mechanism — the Agent Skills spec says it pre-approves
	// the listed tools without blocking others — so it is recorded and displayed
	// and nothing reads it as a boundary.
	tools      []string
	parent     string
	components []view.Component
	versions   []view.PackageVersion
	caps       view.Capabilities
	dependents []view.Dependent
}

func detailOf(row *view.Row) view.Package {
	namespace, name, _ := strings.Cut(row.ID, "/")
	e := designExtras[row.ID]

	detail := view.Package{
		ID:           row.ID,
		Name:         row.Name,
		Kind:         row.Kind,
		Publisher:    row.Publisher,
		Verified:     strings.HasPrefix(row.Publisher, "example"),
		Category:     row.Category,
		Description:  e.description,
		Version:      row.Version,
		Scan:         row.Scan,
		Tags:         row.Tags,
		Components:   e.components,
		Capabilities: e.caps,
		Dependents:   e.dependents,
	}

	if row.Kind == view.KindPlugin {
		detail.SpecVersion = "1.0.0"
		detail.ManifestObject = "plugin.json"
		detail.Manifest = pluginManifest(name, row, e)
	} else {
		detail.ManifestObject = "SKILL.md"
		detail.Manifest = skillManifest(name, e)
		if e.parent != "" {
			detail.ParentID = e.parent
			_, parentName, _ := strings.Cut(e.parent, "/")
			detail.ParentName = parentName
		}
	}

	detail.Versions = e.versions
	if len(detail.Versions) == 0 {
		detail.Versions = []view.PackageVersion{{
			Version: row.Version, DistTag: "latest", Scan: row.Scan, Date: row.Updated,
		}}
	}
	for i := range detail.Versions {
		version := &detail.Versions[i]
		version.ObjectKey = "skills/" + namespace + "/" + name + "/" + version.Version + "/bundle.tar.zst"
		version.Digest = "sha256:" + digestOf(version.ObjectKey)
		version.Size = "18.4 KB"
	}
	return detail
}

// digestOf is a stable stand-in for a real content digest. It is a hash of the
// KEY and not of any bytes, because the fixture ships no bytes — which is
// exactly why it must be obviously derived rather than a plausible-looking
// literal somebody might later mistake for a recorded one.
func digestOf(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func pluginManifest(name string, row *view.Row, e extras) string {
	manifest := map[string]any{
		"$schema":     "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
		"name":        name,
		"version":     row.Version,
		"description": e.description,
		"keywords":    row.Tags,
		"license":     "Apache-2.0",
	}
	if expected := expectedFrom(e.caps); expected != nil {
		manifest["extensions"] = map[string]any{"dev.agent-manager": expected}
	}
	return encode(manifest)
}

// skillManifest is the frontmatter as `version.manifest` holds it: the column is
// jsonb for both kinds and a Markdown file is not json, so a skill's manifest
// column carries its frontmatter rather than its SKILL.md.
func skillManifest(name string, e extras) string {
	tools := e.tools
	if tools == nil {
		tools = []string{"Read", "Grep"}
	}
	manifest := map[string]any{
		"name":          name,
		"description":   e.description,
		"license":       "Apache-2.0",
		"allowed-tools": tools,
	}
	if expected := expectedFrom(e.caps); expected != nil {
		// A skill's frontmatter has no `extensions` key — the schema refuses one —
		// so the same reverse-domain name lives inside `metadata`.
		manifest["metadata"] = map[string]any{"dev.agent-manager": expected}
	}
	return encode(manifest)
}

// expectedFrom renders the expected side of the capability panel back into the
// manifest shape it was read from, so the fixture cannot show a declaration on
// the panel that its own manifest does not contain.
func expectedFrom(caps view.Capabilities) map[string]any {
	declared := make([]map[string]any, 0, len(caps.Rows))
	for i := range caps.Rows {
		row := &caps.Rows[i]
		if !row.Expected.Present {
			continue
		}
		entry := map[string]any{"name": row.Name, "level": row.Expected.Level}
		if len(row.Expected.Detail) > 0 {
			entry["detail"] = row.Expected.Detail
		}
		declared = append(declared, entry)
	}
	if len(declared) == 0 {
		return nil
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

func inferred(level string, detail ...string) view.CapabilityFacet {
	return view.CapabilityFacet{Present: true, Level: level, Detail: detail}
}

// designExtras is the per-package detail data. Absent keys are deliberate: a
// package with no entry renders a scanned version with no capabilities and no
// readable dependants, which is a state the screen has to handle correctly and
// is the majority state in a young hub.
var designExtras = map[string]extras{
	"example/platform-toolkit": {
		description: "Platform guardrails, ADR authoring and service scaffolding in one portable package.",
		components: []view.Component{
			{Kind: "skill", Name: "terraform-module-review", Path: "skills/terraform-module-review", Note: "SKILL.md + scripts/"},
			{Kind: "skill", Name: "adr-writer", Path: "skills/adr-writer", Note: "SKILL.md + references/"},
			{Kind: "skill", Name: "service-scaffold", Path: "skills/service-scaffold", Note: "SKILL.md + scripts/"},
			{Kind: "skill", Name: "cost-explainer", Path: "skills/cost-explainer", Note: "SKILL.md"},
			{Kind: "mcp", Name: "terraform-registry", Path: "mcp.json", Note: "streamable http · registry.terraform.io"},
			{Kind: "ext", Name: "com.anthropic.claude-code", Path: "com.anthropic.claude-code", Note: "client extension: hooks/"},
		},
		caps: view.Capabilities{Scanned: true, Rows: []view.CapabilityRow{
			{Name: "network",
				Inferred: inferred("allowlisted", "registry.terraform.io"),
				Expected: inferred("allowlisted", "registry.terraform.io")},
			{Name: "filesystem.read", Inferred: inferred("scoped", "references/", "scripts/")},
			{Name: "shell", Inferred: inferred("review", "terraform", "jq")},
		}},
		dependents: []view.Dependent{
			{Slug: "platform-engineer", Name: "Platform Engineer", Mode: "latest"},
		},
	},
	"example/security-review-kit": {
		description: "PII redaction, dependency review and scanner triage helpers for reviewers.",
		components: []view.Component{
			{Kind: "skill", Name: "pii-redactor", Path: "skills/pii-redactor", Note: "SKILL.md + scripts/"},
			{Kind: "skill", Name: "dependency-review", Path: "skills/dependency-review", Note: "SKILL.md"},
			{Kind: "skill", Name: "scanner-triage", Path: "skills/scanner-triage", Note: "SKILL.md + references/"},
			{Kind: "mcp", Name: "vuln-db", Path: "mcp.json", Note: "stdio · runs locally"},
		},
		caps: view.Capabilities{Scanned: true, Rows: []view.CapabilityRow{
			{Name: "filesystem.read", Inferred: inferred("scoped", "references/")},
			{Name: "shell", Inferred: inferred("review", "rg")},
		}},
		dependents: []view.Dependent{
			{Slug: "security-review", Name: "Security Review", Mode: "latest"},
		},
	},
	"community/release-toolkit": {
		description: "Drafts release notes and changelogs from merged pull requests.",
		components: []view.Component{
			{Kind: "skill", Name: "release-notes", Path: "skills/release-notes", Note: "SKILL.md"},
			{Kind: "mcp", Name: "github", Path: "mcp.json", Note: "streamable http · api.github.com"},
		},
		// Deliberately unscanned. Its verdict is `scanning` in the design, and a
		// version that has not been scanned has capability rows of NEITHER source —
		// which the panel must say, rather than render an empty comparison.
		caps: view.Capabilities{Scanned: false},
	},
	"community/slack-digest": {
		description: "Summarises channel activity into a daily digest.",
		components: []view.Component{
			{Kind: "skill", Name: "digest", Path: "skills/digest", Note: "SKILL.md + scripts/digest.sh"},
			{Kind: "mcp", Name: "slack", Path: "mcp.json", Note: "streamable http · slack.com"},
		},
		// The design's f1 finding, re-expressed against the expected set: the
		// manifest field it quoted (`"network": {"allow": ["slack.com"]}`) cannot
		// exist, and the shell side — a curl to collect.hexley-metrics.io — is the
		// real control.
		caps: view.Capabilities{Scanned: true, Rows: []view.CapabilityRow{
			{Name: "network",
				Inferred: inferred("review", "collect.hexley-metrics.io", "slack.com"),
				Expected: inferred("allowlisted", "slack.com")},
			{Name: "shell", Inferred: inferred("review", "curl", "jq")},
		}},
	},
	"example/terraform-module-review": {
		description: "Reviews Terraform plans and module changes against the platform guardrails: " +
			"tagging, remote state layout, IAM boundaries and drift on protected resources.",
		tools:  []string{"Read", "Grep", "Bash(terraform plan)"},
		parent: "example/platform-toolkit",
		versions: []view.PackageVersion{
			{Version: "2.4.1", DistTag: "latest", Scan: view.ScanClean, Date: "2 days ago"},
			// The design's `pinned by 2` row. It is DERIVED from profile pins and is
			// not a distribution tag, which is why this version carries `none` and a
			// pin count rather than a third dist_tag value.
			{Version: "2.4.0", DistTag: "none", Scan: view.ScanClean, Date: "3 weeks ago", PinnedBy: 2},
			{Version: "2.3.5", DistTag: "archived", Scan: view.ScanClean, Date: "2 months ago"},
		},
		caps: view.Capabilities{Scanned: true, Rows: []view.CapabilityRow{
			{Name: "filesystem.read", Inferred: inferred("scoped", "references/guardrails.md")},
			{Name: "shell", Inferred: inferred("review", "terraform")},
		}},
		// The design's usedIn at lines 1059-1063. The organisation's fourth
		// profile, `example/data-migration`, is Private and is absent from this
		// panel for every viewer who is not a member — see the api's scoping.
		dependents: []view.Dependent{
			{Slug: "platform-engineer", Name: "Platform Engineer", Mode: "latest"},
			{Slug: "sre-oncall", Name: "SRE On-call", Mode: "pinned", Pin: "2.4.0"},
			{Slug: "security-review", Name: "Security Review", Mode: "latest"},
		},
	},
	"example/k8s-incident-triage": {
		description: "Walks an alert back to the failing workload and drafts the incident timeline.",
		tools:       []string{"Read", "Bash(kubectl get)"},
		caps: view.Capabilities{Scanned: true, Rows: []view.CapabilityRow{
			{Name: "shell", Inferred: inferred("review", "kubectl")},
		}},
		dependents: []view.Dependent{{Slug: "sre-oncall", Name: "SRE On-call", Mode: "latest"}},
	},
	"community/postgres-migration-guard": {
		description: "Checks migrations for locking, backfill and rollback hazards before they ship.",
		tools:       []string{"Read", "Bash(psql)"},
		// The design's f2 finding: a SKILL.md instructing the agent to read local
		// credential files. No expected set was recorded, so every inferred
		// capability is surfaced for review rather than silently accepted (FR-027).
		caps: view.Capabilities{Scanned: true, Rows: []view.CapabilityRow{
			{Name: "filesystem.read", Inferred: inferred("review", "~/.aws/credentials", "~/.pgpass")},
			{Name: "shell", Inferred: inferred("review", "psql")},
		}},
	},
	"example/adr-writer": {
		description: "Writes and supersedes architecture decision records in the house format.",
		tools:       []string{"Read", "Write", "Grep"},
		parent:      "example/platform-toolkit",
		caps: view.Capabilities{Scanned: true, Rows: []view.CapabilityRow{
			{Name: "filesystem.read", Inferred: inferred("scoped", "references/")},
			{Name: "filesystem.write",
				Inferred: inferred("scoped", "docs/adr/"),
				Expected: inferred("scoped", "docs/adr/")},
		}},
		dependents: []view.Dependent{
			{Slug: "platform-engineer", Name: "Platform Engineer", Mode: "range", Pin: "^3.1"},
		},
	},
	"community/aws-cost-explainer": {
		description: "Explains a cost spike by service, account and tag, then proposes cuts.",
		tools:       []string{"Read", "WebFetch"},
		// The design's f4 finding, re-expressed: an over-broad write scope inferred
		// from the scripts and compared against what the publisher declared.
		caps: view.Capabilities{Scanned: true, Rows: []view.CapabilityRow{
			{Name: "network", Inferred: inferred("allowlisted", "ce.us-east-1.amazonaws.com")},
			{Name: "filesystem.write",
				Inferred: inferred("review", "**"),
				Expected: inferred("scoped", "reports/")},
			{Name: "shell", Inferred: inferred("review", "aws")},
		}},
	},
	"example/pii-redactor": {
		description: "Finds and masks personal data in logs, fixtures and support transcripts.",
		tools:       []string{"Read", "Write"},
		parent:      "example/security-review-kit",
		caps: view.Capabilities{Scanned: true, Rows: []view.CapabilityRow{
			{Name: "filesystem.read", Inferred: inferred("scoped", "fixtures/")},
			{Name: "filesystem.write", Inferred: inferred("scoped", "out/")},
			// Declared but never observed: the publisher expected a shell capability
			// the scan did not find. The panel must say so rather than hide the row.
			{Name: "shell", Expected: inferred("review")},
		}},
		dependents: []view.Dependent{
			{Slug: "security-review", Name: "Security Review", Mode: "pinned", Pin: "1.4.2"},
		},
	},
}
