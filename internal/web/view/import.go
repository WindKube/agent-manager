package view

import "io"

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

// ImportVisibilities is the part of the package_visibility vocabulary the modal
// may offer, which is currently one value of three.
//
// `team` and `private` are omitted because nothing can honour them. `profile` has
// an `owner_team` column and `package` has no owner column at all — that
// asymmetry is the whole reason one can be scoped and the other cannot, and it is
// a MISSING COLUMN rather than a missing predicate. Until `package` grows an
// owner there is nobody to compare a reader to, so the catalog fails closed and
// shows neither (see queries.CatalogFilter.baseFilters).
//
// Offering them anyway would be worse than omitting them: a person picks
// "Private", the registration succeeds, and their package is invisible to
// everyone including themselves with nothing on screen to explain it. A control
// whose only effect is to lose your own work is not a feature.
//
// These two lists move together. A test binds this vocabulary to what the live
// catalog actually returns, so adding an option here without a predicate behind
// it — or widening the predicate without an option — fails.
var ImportVisibilities = []struct {
	Value string
	Label string
}{
	{"organisation", "Organisation"},
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

// ---- what the modal submits --------------------------------------------------

// Registration is the modal's form, on its way to POST /v1/packages.
//
// It carries the archive as a reader rather than as bytes: the cap is 25 MB and
// the web role is a hop, so buffering the whole upload here would double the
// memory the api already spends on it for no gain.
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

// ImportResult is what came back. A refusal is a result and not an error: the
// api's problem detail is something the modal shows the person who submitted,
// while an error is something only the log should see.
type ImportResult struct {
	Registered bool
	// ID and Version identify what was accepted, for the confirmation line.
	ID      string
	Version string
	// Message is the api's problem detail when the registration was refused.
	Message string
	// Preview is the pre-submit report, when the api produced one. FR-005: a
	// refusal names the entries and the schema path that refused them.
	Preview *ImportPreview
}
