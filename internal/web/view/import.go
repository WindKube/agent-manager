package view

// The registration modal's view model (US1, FR-005).
//
// It is deliberately a plain value with no behaviour: the web role holds no
// datastore credential and no outbound client, so everything here arrives from
// whatever implements web.CatalogSource. The pre-submit report the api's
// `POST /v1/packages/preview` produces lands in ImportPreview unchanged.

// ImportTab is which half of the modal is showing. FR-001 gives three source
// shapes and the modal offers two doors to them: an upload, and a URL that is
// routed to the git or the archive source by its shape.
type ImportTab string

const (
	ImportUpload ImportTab = "upload"
	ImportURL    ImportTab = "url"
)

// ImportTabs is the design's tab row.
var ImportTabs = []struct {
	ID    ImportTab
	Label string
}{
	{ImportUpload, "Upload archive"},
	{ImportURL, "Fetch from URL"},
}

// ImportVisibilities is the package_visibility vocabulary as the modal shows it.
var ImportVisibilities = []struct {
	Value string
	Label string
}{
	{"organisation", "Organisation"},
	{"team", "Private to my team"},
	{"private", "Private"},
}

// Import is everything the modal renders.
type Import struct {
	// Categories is the admin-curated vocabulary (FR-049). The modal only ever
	// selects from it: a registration cannot add to it.
	Categories []string

	// Preview is the pre-submit report for an attached archive, when one has been
	// validated. Nil is the modal's resting state, and the panel is absent rather
	// than empty — FR-005 is a report about a specific tree, so a blank one would
	// be a claim about no tree at all.
	Preview *ImportPreview
}

// ImportPreview is the api's PackagePreview as the panel needs it.
type ImportPreview struct {
	Valid   bool
	Kind    Kind
	Name    string
	Version string

	// Entries is one row per top-level entry, in the order the panel shows them.
	Entries []ImportEntry

	// Problems is why the tree was refused, each reported against the schema path
	// that refused it (US1 scenario 3).
	Problems []ImportProblem
}

// ImportEntry is one row of the archive-contents panel.
type ImportEntry struct {
	Path string
	Note string
	Kept bool
	Mark string
}

// Glyph is the design's mark column: a tick for a kept entry, an en dash for a
// dropped one, a cross for the manifest that failed.
func (e ImportEntry) Glyph() string {
	switch {
	case e.Mark == "invalid":
		return "✕"
	case e.Kept:
		return "✓"
	default:
		return "–"
	}
}

// Tone maps the mark onto the palette's semantic tokens.
func (e ImportEntry) Tone() string {
	switch {
	case e.Mark == "invalid":
		return "dan"
	case e.Kept:
		return "ok"
	default:
		return "fg3"
	}
}

// ImportProblem is one refusal, with the schema path that produced it.
type ImportProblem struct {
	Manifest   string
	SchemaPath string
	Message    string
}

// Where renders the location of a problem for the panel. It is built from the
// manifest name and the keyword location rather than from a free-form string, so
// a publisher can look the refusal up in the published schema.
func (p ImportProblem) Where() string {
	switch {
	case p.Manifest != "" && p.SchemaPath != "":
		return p.Manifest + " " + p.SchemaPath
	case p.Manifest != "":
		return p.Manifest
	default:
		return p.SchemaPath
	}
}
