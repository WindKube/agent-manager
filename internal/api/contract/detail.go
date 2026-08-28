package contract

import "time"

// The package detail surface (US3, FR-016..FR-019). Like the catalog it is
// web-facing: the frozen contract inventories `GET /v1/packages/{id}` but
// specifies no schema for it, so these shapes are emitted rather than frozen.
//
// Nothing here is a rendered sentence. The design's origin line reads
// "Portable package · Agent Plugins 1.0.0 · 4 skills, 1 MCP server(s)"; what is
// returned is the spec version and the components, because which words express
// that is a rendering decision and an API that made it would have made it for
// every client. The same reasoning keeps timestamps as instants and the manifest
// as the bytes that were stored.

// PackageDetail is one package's whole detail page (FR-016).
type PackageDetail struct {
	ID        string           `json:"id" doc:"namespace/name — the first segment of the publisher slug, not the whole slug." example:"example/platform-toolkit"`
	Name      string           `json:"name" doc:"The manifest name. No manifest field and no column carries a human title." example:"platform-toolkit"`
	Kind      string           `json:"kind" enum:"plugin,skill" doc:"Decided by which manifest is at the tree root, never by a manifest field." example:"plugin"`
	Publisher PackagePublisher `json:"publisher"`
	Category  string           `json:"category,omitempty" doc:"The admin-curated category (FR-049). Empty when none was chosen." example:"Infrastructure"`

	// Description is read from the LATEST VERSION'S MANIFEST, because `package`
	// has no description column and deliberately does not: a description belongs
	// to a release, changes between them, and the manifest is where a publisher
	// writes it.
	Description string `json:"description,omitempty" example:"Platform guardrails, ADR authoring and service scaffolding."`

	Origin  PackageOrigin `json:"origin"`
	Version string        `json:"version" doc:"The latest visible version's semver — the one the panels below describe." example:"1.3.0"`
	Verdict string        `json:"verdict" enum:"scanning,clean,flagged,rejected" example:"clean"`
	Tags    []string      `json:"tags" doc:"The latest version's manifest keywords. Tags belong to the version, not the package."`

	// ManifestObject names which file Manifest came from, so the panel can be
	// headed with it rather than guessing from Kind.
	ManifestObject string `json:"manifestObject" enum:"plugin.json,SKILL.md" example:"plugin.json"`
	// Manifest is the stored manifest document, verbatim and unformatted. It is a
	// string and not an object: the panel shows the document a publisher wrote,
	// and re-encoding it through a Go map would silently reorder and reformat it.
	// For a standalone skill it is the SKILL.md frontmatter as json, which is what
	// the jsonb column holds — a Markdown file is not json.
	Manifest string `json:"manifest"`

	Components   []PackageComponent  `json:"components" doc:"Derived from the FILE TREE. No manifest field enumerates components (FR-017, R1)."`
	Capabilities PackageCapabilities `json:"capabilities"`
	Versions     []PackageVersion    `json:"versions" doc:"Every visible version, newest first."`
	Dependents   []PackageDependent  `json:"dependents" doc:"Profiles using this package that the CALLER MAY READ, and no others (FR-044)."`
}

// PackagePublisher is the owning team. It is the whole two-segment slug, which is
// a different string from the id's namespace: example/security publishes
// example/pii-redactor.
type PackagePublisher struct {
	Slug        string `json:"slug" example:"example/platform"`
	DisplayName string `json:"displayName" example:"Platform Engineering"`
	Verified    bool   `json:"verified" doc:"Set by a catalog admin and never inferred from the namespace."`
}

// PackageOrigin is what the origin line is built from (US3 scenarios 1 and 2).
type PackageOrigin struct {
	// SpecVersion is the version of the specification the manifest names in its
	// `$schema`, e.g. "1.0.0". Empty for a standalone skill: agentskills.io
	// publishes no schema and no version, so there is nothing to state.
	SpecVersion string `json:"specVersion,omitempty" example:"1.0.0"`

	// ParentID and ParentName are the plugin a skill is distributed inside, or
	// empty for a standalone one.
	//
	// There is no parent VERSION here and the design's "distributed inside
	// Platform Toolkit 1.3.0" is therefore not reproducible. `parent_package_id`
	// points at a package; no column links a skill's version to the plugin version
	// that contains it. Rendering the parent's current latest instead would make
	// the sentence rewrite itself whenever the parent publishes, and become false
	// exactly when a later parent version drops the component — so the version is
	// omitted rather than approximated.
	ParentID   string `json:"parentId,omitempty" example:"example/platform-toolkit"`
	ParentName string `json:"parentName,omitempty" example:"platform-toolkit"`
}

// PackageComponent is one component the file tree revealed (FR-017).
type PackageComponent struct {
	Kind string `json:"kind" enum:"skill,mcp,ext" example:"skill"`
	Name string `json:"name" example:"terraform-module-review"`
	Path string `json:"path" example:"skills/terraform-module-review"`
	Note string `json:"note,omitempty" example:"SKILL.md + scripts/"`
}

// PackageCapabilities is the inferred-versus-expected comparison (FR-018,
// FR-018a) and the state that precedes it.
type PackageCapabilities struct {
	// Scanned is whether a scan of this version has FINISHED. It is not derivable
	// from the two lists below: a scan that ran and found nothing produces the same
	// empty lists as a version registered a second ago and never scanned, and those
	// are opposite facts. The scanner writes both sources in the transaction that
	// records the scan, so until then a version has rows of neither.
	Scanned bool `json:"scanned"`
	// Inferred is what static analysis found in the bytes (FR-018).
	Inferred []PackageCapability `json:"inferred"`
	// Expected is what the publisher recorded under
	// extensions["dev.agent-manager"] (FR-018a). It is an expectation and never an
	// enforced permission — nothing in this hub grants or denies on it.
	Expected []PackageCapability `json:"expected"`
}

// PackageCapability is one capability row.
type PackageCapability struct {
	Name   string   `json:"name" enum:"network,filesystem.read,filesystem.write,shell" example:"network"`
	Level  string   `json:"level" enum:"scoped,allowlisted,review" doc:"How much trust it demands. A shell capability is never below review (FR-018)." example:"allowlisted"`
	Detail []string `json:"detail" doc:"The scoping: hosts for network, paths for filesystem, command names for shell."`
	// Indefinite says the analysis found targets it could not name — a host behind
	// a shell variable, or a list too long to carry. Detail is then a sample and
	// not the whole set, and must not be read as one.
	Indefinite bool `json:"indefinite,omitempty"`
}

// PackageVersion is one row of the versions panel (FR-019).
type PackageVersion struct {
	Version string `json:"version" example:"1.3.0"`
	// DistTag is the stored distribution channel. `pinned by N` is NOT one of its
	// values — see PinnedBy.
	DistTag   string    `json:"distTag" enum:"latest,archived,none" example:"latest"`
	Verdict   string    `json:"verdict" enum:"scanning,clean,flagged,rejected" example:"clean"`
	CreatedAt time.Time `json:"createdAt"`
	// ObjectKey is the FULL key, not a suffix: FR-019 asks for the whole thing so
	// an operator can find the bytes in the bucket without reconstructing it.
	ObjectKey string `json:"objectKey" example:"skills/example/platform-toolkit/1.3.0/bundle.tar.zst"`
	Digest    string `json:"digest,omitempty" pattern:"^sha256:[0-9a-f]{64}$" doc:"Empty while a registration is still being fetched: the digest is computed on write."`
	SizeBytes int64  `json:"sizeBytes,omitempty"`
	// PinnedBy is how many profiles THE CALLER MAY READ pin this exact version. It
	// is derived at query time and never stored (data-model.md), and it is scoped
	// for the same reason Dependents is: an unscoped count beside a scoped list
	// leaks the existence of private profiles by arithmetic.
	PinnedBy int `json:"pinnedBy"`
}

// PackageDependent is one profile that uses this package and how it resolves it
// (US3 scenario 5).
//
// The list is scoped by the FR-044 readability predicate, exactly as
// /v1/profiles is: unreadable profiles are not enumerated at all, so a caller
// cannot learn the names of private profiles — or the versions they pin — from a
// page they are allowed to read.
type PackageDependent struct {
	Slug string `json:"slug" example:"platform-baseline"`
	Name string `json:"name" example:"Platform baseline"`
	Mode string `json:"mode" enum:"latest,pinned,range" doc:"How this profile resolves the package." example:"pinned"`
	// Version is the pinned semver, present only when mode is pinned.
	Version string `json:"version,omitempty" example:"1.3.0"`
	// Range is the range expression, present only when mode is range.
	Range string `json:"range,omitempty" example:"^1.2"`
}
