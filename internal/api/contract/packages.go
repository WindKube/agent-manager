package contract

// Mark values are names rather than glyphs, since which glyph renders a
// kept file is a view decision.
const (
	MarkKept    = "kept"
	MarkDropped = "dropped"
	MarkInvalid = "invalid"
)

// PackagePreview runs the same internal/domain/pkgspec.Inspect the fetcher
// does, so nothing is written to produce it.
type PackagePreview struct {
	Valid bool   `json:"valid" doc:"Whether this tree would be accepted for registration."`
	Kind  string `json:"kind,omitempty" enum:"plugin,skill" doc:"Decided by which manifest is at the tree root, never by a manifest field." example:"plugin"`
	Name  string `json:"name,omitempty" doc:"The manifest's name, which becomes the catalog's package name." example:"platform-toolkit"`
	// Version is the manifest's own `version`, normalised; empty means the
	// registration must supply one.
	Version string `json:"version,omitempty" example:"1.3.0"`

	Entries    []PreviewEntry      `json:"entries" doc:"One row per top-level entry, in the order the pre-submit panel shows them."`
	Components []PreviewComponent  `json:"components" doc:"Derived from the file tree. No manifest field enumerates components."`
	Expected   []PreviewCapability `json:"expectedCapabilities" doc:"The publisher's declared expectations, read from extensions[\"dev.agent-manager\"] and from nowhere else."`
	Tags       []string            `json:"tags" doc:"The manifest's keywords, which become the version's tags."`
	Dropped    []string            `json:"dropped" doc:"Every discarded path in full. The entries above group them for display."`
	Problems   []PreviewProblem    `json:"problems" doc:"Why the tree was refused. Empty when valid."`
}

type PreviewEntry struct {
	Path string `json:"path" doc:"A file, a directory, or a comma-joined group of dropped paths." example:"skills/"`
	Note string `json:"note" doc:"What was found there." example:"4 skills"`
	Kept bool   `json:"kept" doc:"False for a path outside the spec layout, which is not stored."`
	Mark string `json:"mark" enum:"kept,dropped,invalid" example:"kept"`
}

type PreviewComponent struct {
	Kind string `json:"kind" enum:"skill,mcp,ext" example:"skill"`
	Name string `json:"name" example:"terraform-review"`
	Path string `json:"path" example:"skills/terraform-review/SKILL.md"`
	Note string `json:"note,omitempty" example:"SKILL.md + scripts/"`
}

// PreviewCapability is a declared expectation, not evidence: a finding is
// raised where the scanner's inferred set exceeds this.
type PreviewCapability struct {
	Name   string   `json:"name" example:"network"`
	Level  string   `json:"level,omitempty" enum:"scoped,allowlisted,review" example:"allowlisted"`
	Detail []string `json:"detail,omitempty" doc:"The publisher's scoping, e.g. hosts for network."`
}

type PreviewProblem struct {
	Manifest     string `json:"manifest,omitempty" doc:"Which manifest failed." example:"plugin.json"`
	SchemaID     string `json:"schemaId,omitempty" doc:"The $id of the schema it was checked against." example:"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"`
	SchemaPath   string `json:"schemaPath,omitempty" doc:"The keyword location that refused it." example:"/additionalProperties"`
	InstancePath string `json:"instancePath,omitempty" doc:"Where in the manifest the offending value sits." example:"/repository"`
	Message      string `json:"message" example:"additionalProperties 'repository' not allowed"`
}

// PackageRegistered is an acknowledgement, not a published version: bytes
// are fetched by `worker fetcher`, so the version has no digest yet.
type PackageRegistered struct {
	PackageID string `json:"packageId" format:"uuid"`
	VersionID string `json:"versionId" format:"uuid"`

	Publisher string `json:"publisher" example:"example/platform"`
	Name      string `json:"name" example:"platform-toolkit"`
	Version   string `json:"version" example:"1.3.0"`
	Kind      string `json:"kind" enum:"plugin,skill" example:"plugin"`

	// ObjectKey is fixed at registration because it's derived from the
	// identity, not the bytes.
	ObjectKey string `json:"objectKey" example:"skills/example/platform-toolkit/1.3.0/bundle.tar.zst"`

	Verdict string `json:"verdict" enum:"scanning,clean,flagged,rejected" doc:"Always scanning here: the scan has not run." example:"scanning"`
	Visible bool   `json:"visible" doc:"Always false here. Commit-last (FR-008): the fetcher flips it."`

	Preview *PackagePreview `json:"preview,omitempty" doc:"Present for an upload, where the archive was inspected in-process before the version row was written."`
}
