package contract

import "time"

type PackageDetail struct {
	ID        string           `json:"id" doc:"namespace/name — the first segment of the publisher slug, not the whole slug." example:"example/platform-toolkit"`
	Name      string           `json:"name" doc:"The manifest name. No manifest field and no column carries a human title." example:"platform-toolkit"`
	Kind      string           `json:"kind" enum:"plugin,skill" doc:"Decided by which manifest is at the tree root, never by a manifest field." example:"plugin"`
	Publisher PackagePublisher `json:"publisher"`
	Category  string           `json:"category,omitempty" doc:"The admin-curated category (FR-049). Empty when none was chosen." example:"Infrastructure"`

	Description string `json:"description,omitempty" example:"Platform guardrails, ADR authoring and service scaffolding."`

	Origin  PackageOrigin `json:"origin"`
	Version string        `json:"version" doc:"The latest visible version's semver — the one the panels below describe." example:"1.3.0"`
	Verdict string        `json:"verdict" enum:"scanning,clean,flagged,rejected" example:"clean"`
	Tags    []string      `json:"tags" doc:"The latest version's manifest keywords. Tags belong to the version, not the package."`

	ManifestObject string `json:"manifestObject" enum:"plugin.json,SKILL.md" example:"plugin.json"`
	// Manifest is verbatim and unformatted: a Go map would reorder it.
	Manifest string `json:"manifest"`

	Components   []PackageComponent  `json:"components" doc:"Derived from the FILE TREE. No manifest field enumerates components (FR-017, R1)."`
	Capabilities PackageCapabilities `json:"capabilities"`
	Versions     []PackageVersion    `json:"versions" doc:"Every visible version, newest first."`
	Dependents   []PackageDependent  `json:"dependents" doc:"Profiles using this package that the CALLER MAY READ, and no others (FR-044)."`
}

type PackagePublisher struct {
	Slug        string `json:"slug" example:"example/platform"`
	DisplayName string `json:"displayName" example:"Platform Engineering"`
	Verified    bool   `json:"verified" doc:"Set by a catalog admin and never inferred from the namespace."`
}

type PackageOrigin struct {
	SpecVersion string `json:"specVersion,omitempty" example:"1.0.0"`

	// ParentID/ParentName carry no parent VERSION: rendering the parent's
	// current latest would go stale silently.
	ParentID   string `json:"parentId,omitempty" example:"example/platform-toolkit"`
	ParentName string `json:"parentName,omitempty" example:"platform-toolkit"`
}

type PackageComponent struct {
	Kind string `json:"kind" enum:"skill,mcp,ext" example:"skill"`
	Name string `json:"name" example:"terraform-module-review"`
	Path string `json:"path" example:"skills/terraform-module-review"`
	Note string `json:"note,omitempty" example:"SKILL.md + scripts/"`
}

type PackageCapabilities struct {
	// Scanned is not derivable from the two lists below: a scan that found
	// nothing looks the same as a version never scanned.
	Scanned  bool                `json:"scanned"`
	Inferred []PackageCapability `json:"inferred"`
	// Expected is what the publisher recorded — an expectation, never an
	// enforced permission.
	Expected []PackageCapability `json:"expected"`
}

type PackageCapability struct {
	Name   string   `json:"name" enum:"network,filesystem.read,filesystem.write,shell" example:"network"`
	Level  string   `json:"level" enum:"scoped,allowlisted,review" doc:"How much trust it demands. A shell capability is never below review (FR-018)." example:"allowlisted"`
	Detail []string `json:"detail" doc:"The scoping: hosts for network, paths for filesystem, command names for shell."`
	// Indefinite means the analysis found targets it could not name; Detail
	// is then a sample, not the whole set.
	Indefinite bool `json:"indefinite,omitempty"`
}

type PackageVersion struct {
	Version   string    `json:"version" example:"1.3.0"`
	DistTag   string    `json:"distTag" enum:"latest,archived,none" example:"latest"`
	Verdict   string    `json:"verdict" enum:"scanning,clean,flagged,rejected" example:"clean"`
	CreatedAt time.Time `json:"createdAt"`
	ObjectKey string    `json:"objectKey" example:"skills/example/platform-toolkit/1.3.0/bundle.tar.zst"`
	Digest    string    `json:"digest,omitempty" pattern:"^sha256:[0-9a-f]{64}$" doc:"Empty while a registration is still being fetched: the digest is computed on write."`
	SizeBytes int64     `json:"sizeBytes,omitempty"`
	// PinnedBy is scoped to profiles the caller may read: an unscoped count
	// beside a scoped list would leak private profiles' existence.
	PinnedBy int `json:"pinnedBy"`
}

// PackageDependent is scoped the same way /v1/profiles is: a caller can't
// learn the names of private profiles from this list.
type PackageDependent struct {
	Slug    string `json:"slug" example:"platform-baseline"`
	Name    string `json:"name" example:"Platform baseline"`
	Mode    string `json:"mode" enum:"latest,pinned,range" doc:"How this profile resolves the package." example:"pinned"`
	Version string `json:"version,omitempty" example:"1.3.0"`
	Range   string `json:"range,omitempty" example:"^1.2"`
}
