package view

import "io"

// ImportTab is which half of the modal is showing: an upload, or a URL routed to the git or archive source.
type ImportTab string

const (
	ImportUpload ImportTab = "upload"
	ImportURL    ImportTab = "url"
)

var ImportTabs = []struct {
	ID    ImportTab
	Label string
}{
	{ImportUpload, "Upload archive"},
	{ImportURL, "Fetch from URL"},
}

// MaxTagsFieldLength is commands.MaxTagCount tags of commands.MaxTagLength characters plus separators;
// the api's per-tag checks still decide.
const MaxTagsFieldLength = 20 * (40 + 1)

// ImportVisibilityOptions is the visibility vocabulary the modal offers. Team is disabled for a viewer with
// no identity-provider groups: team matches the owner's groups against a reader's, so it would silently
// behave like private.
func ImportVisibilityOptions(viewerGroups []string) []ImportOption {
	options := []ImportOption{
		{Value: "organisation", Label: "Organisation"},
		{Value: "team", Label: "Team"},
		{Value: "private", Label: "Private"},
	}
	if len(viewerGroups) == 0 {
		options[1].Disabled = true
		options[1].Reason = "Team visibility is matched against your identity provider groups, " +
			"and your identity carries none."
	}
	return options
}

// ImportOption is one entry of a select. A disabled option is still shown, with its Reason.
type ImportOption struct {
	Value    string
	Label    string
	Disabled bool
	Reason   string
}

// Import is everything the modal renders.
type Import struct {
	// Categories is the admin-curated vocabulary; a registration cannot add to it.
	Categories []string

	// Preview is nil until an archive is validated, and the panel is then absent rather than empty.
	Preview *ImportPreview
}

// ImportPreview is the api's PackagePreview as the panel needs it.
type ImportPreview struct {
	Valid   bool
	Kind    Kind
	Name    string
	Version string

	// Entries is one row per top-level entry.
	Entries []ImportEntry

	Problems []ImportProblem
}

// ImportEntry is one row of the archive-contents panel.
type ImportEntry struct {
	Path string
	Note string
	Kept bool
	Mark string
}

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

type ImportProblem struct {
	Manifest   string
	SchemaPath string
	Message    string
}

// Where locates a problem by manifest and schema path, so a publisher can look it up in the schema.
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

// Registration is the modal's form for POST /v1/packages. The archive is a reader so the upload is not
// buffered twice.
type Registration struct {
	Tab ImportTab

	URL          string
	Ref          string
	Subdirectory string

	Publisher string
	Name      string
	Version   string

	// Kind is provisional: the fetcher decides it from the root manifest, and "" asks it to detect.
	Kind       string
	Category   string
	Visibility string

	// Tags is forwarded verbatim; the api splits, dedupes and validates it.
	Tags string

	Archive *Archive
}

// Archive is one uploaded file.
type Archive struct {
	Filename string
	Size     int64
	Content  io.Reader
}

// ImportResult is what came back. A refusal is a result shown to the submitter, not an error.
type ImportResult struct {
	Registered bool
	ID         string
	Version    string
	// Message is the api's problem detail when the registration was refused.
	Message string
	Preview *ImportPreview
}
