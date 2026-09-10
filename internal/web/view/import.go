package view

import "io"

// The registration modal's view model: a plain value with no behaviour.
// Everything here arrives from whatever implements web.CatalogSource.

// ImportTab is which half of the modal is showing: an upload, or a URL
// routed to the git or archive source by its shape.
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

// ImportVisibilities is the part of the package_visibility vocabulary the
// modal may offer: currently one value of three. `team` and `private` are
// omitted because `package` has no owner column to compare a reader to, so
// the catalog fails closed and shows neither. Offering them anyway would be
// worse: a person picks "Private" and their package becomes invisible to
// everyone including themselves.
var ImportVisibilities = []struct {
	Value string
	Label string
}{
	{"organisation", "Organisation"},
}

// Import is everything the modal renders.
type Import struct {
	// Categories is the admin-curated vocabulary. The modal only ever
	// selects from it: a registration cannot add to it.
	Categories []string

	// Preview is the pre-submit report for an attached archive, when one has
	// been validated. Nil is the modal's resting state, and the panel is
	// absent rather than empty: a blank one would claim there was no tree at all.
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

	// Problems is why the tree was refused, each reported against the
	// schema path that refused it.
	Problems []ImportProblem
}

// ImportEntry is one row of the archive-contents panel.
type ImportEntry struct {
	Path string
	Note string
	Kept bool
	Mark string
}

// Glyph is the mark column: a tick for kept, an en dash for dropped, a
// cross for the manifest that failed.
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

// Where renders the location of a problem for the panel, built from the
// manifest name and keyword location so a publisher can look the refusal up
// in the published schema.
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

// ---- what the modal submits --------------------------------------------------

// Registration is the modal's form, on its way to POST /v1/packages. It
// carries the archive as a reader rather than bytes: the cap is 25 MB, and
// buffering the whole upload here would double the memory the api spends on it.
type Registration struct {
	Tab ImportTab

	URL          string
	Ref          string
	Subdirectory string

	Publisher string
	Name      string
	Version   string

	Category   string
	Visibility string

	Archive *Archive
}

// Archive is one uploaded file.
type Archive struct {
	Filename string
	Size     int64
	Content  io.Reader
}

// ImportResult is what came back. A refusal is a result, not an error: the
// problem detail is shown to the person who submitted; an error is only for the log.
type ImportResult struct {
	Registered bool
	// ID and Version identify what was accepted, for the confirmation line.
	ID      string
	Version string
	// Message is the api's problem detail when the registration was refused.
	Message string
	// Preview is the pre-submit report, when the api produced one.
	Preview *ImportPreview
}
