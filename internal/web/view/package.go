package view

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// ErrNotFound is a PackageSource reporting that there is no such package, or
// that this identity may not read it. One error for both, mirroring the
// api's single 404: distinguishing them would confirm the existence of
// packages a caller is not allowed to see.
var ErrNotFound = errors.New("no such package")

// The package detail screen's view models. Everything the API returns as
// data becomes a sentence here and nowhere else.

// Package is one detail page.
type Package struct {
	ID          string
	Name        string
	Kind        Kind
	Publisher   string
	Verified    bool
	Category    string
	Description string
	Version     string
	Scan        Scan
	Tags        []string

	// SpecVersion is the version the manifest's $schema names, empty for a skill.
	SpecVersion string
	// ParentID and ParentName name the plugin a skill is distributed inside.
	// There is no parent VERSION and there cannot be one.
	ParentID   string
	ParentName string

	ManifestObject string
	Manifest       string

	Components   []Component
	Capabilities Capabilities
	Versions     []PackageVersion
	Dependents   []Dependent

	// SignedOut is the same third outcome the catalog has: a screen renders
	// because the screen is not the secret, only the contents are.
	SignedOut bool
	// Missing is a package that does not exist, or that this identity may
	// not read — one state for both, exactly as the api's 404 is.
	Missing bool
}

// Component is one component the file tree revealed.
type Component struct {
	Kind string
	Name string
	Path string
	Note string
}

// PackageVersion is one row of the versions panel.
type PackageVersion struct {
	Version   string
	DistTag   string
	Scan      Scan
	Date      string
	ObjectKey string
	Digest    string
	Size      string
	// PinnedBy is how many profiles the viewer can see pin this exact
	// version. Derived at query time, never stored.
	PinnedBy int
}

// Dependent is one profile using the package, and how it resolves it.
type Dependent struct {
	Slug string
	Name string
	Mode string
	Pin  string
}

// Capabilities is the inferred-versus-expected panel.
type Capabilities struct {
	// Scanned is whether a scan of this version has finished. It is NOT
	// len(Rows) > 0: a scan that found nothing and one never scanned
	// produce the same empty list and are opposite facts.
	Scanned bool
	Rows    []CapabilityRow
}

// CapabilityRow is one capability name with both sides of the comparison, so
// the panel is a comparison rather than two lists to align by eye.
type CapabilityRow struct {
	Name     string
	Inferred CapabilityFacet
	Expected CapabilityFacet
}

// CapabilityFacet is one side of one row.
type CapabilityFacet struct {
	Present bool
	Level   string
	Detail  []string
	// Indefinite says the analysis found targets it could not name, so
	// Detail is a sample, not the whole set.
	Indefinite bool
}

// The capability comparison verdicts describe a RELATIONSHIP between two
// records, never a decision this hub took: nothing here grants or denies.
const (
	CapabilityUndeclared = "not declared"
	CapabilityUnobserved = "declared, not observed"
	CapabilityExceeds    = "exceeds the expectation"
	CapabilityWithin     = "within the expectation"
)

// Status compares the two sides: where the inferred set exceeds the
// expected one, a human is meant to look, and where no expectation was
// recorded at all, everything is surfaced rather than silently accepted.
func (r CapabilityRow) Status() string {
	switch {
	case r.Inferred.Present && !r.Expected.Present:
		return CapabilityUndeclared
	case !r.Inferred.Present && r.Expected.Present:
		return CapabilityUnobserved
	case levelRank(r.Inferred.Level) > levelRank(r.Expected.Level):
		return CapabilityExceeds
	default:
		return CapabilityWithin
	}
}

// Tone colours the verdict. `within` is not coloured as a pass: a pass would
// imply the hub checked something it enforces.
func (r CapabilityRow) Tone() string {
	switch r.Status() {
	case CapabilityExceeds:
		return "dan"
	case CapabilityUndeclared, CapabilityUnobserved:
		return "warn"
	default:
		return "fg2"
	}
}

func levelRank(level string) int {
	switch level {
	case "scoped":
		return 0
	case "allowlisted":
		return 1
	case "review":
		return 2
	default:
		return -1
	}
}

// LevelLabel is the design's badge text.
func LevelLabel(level string) string {
	switch level {
	case "scoped":
		return "Scoped"
	case "allowlisted":
		return "Allowlisted"
	case "review":
		return "Review"
	default:
		return "—"
	}
}

// LevelTone maps a level onto the palette: Scoped is settled, Review needs a person.
func LevelTone(level string) string {
	switch level {
	case "scoped":
		return "ok"
	case "allowlisted":
		return "warn"
	case "review":
		return "dan"
	default:
		return "fg3"
	}
}

// Targets renders one side's scoping for the panel's note column.
func (f CapabilityFacet) Targets() string {
	if !f.Present {
		return ""
	}
	switch {
	case len(f.Detail) == 0 && f.Indefinite:
		return "targets not determined"
	case len(f.Detail) == 0:
		return ""
	case f.Indefinite:
		return strings.Join(f.Detail, ", ") + ", and targets not determined"
	default:
		return strings.Join(f.Detail, ", ")
	}
}

// Origin is the origin line. The skill branch names the parent PACKAGE, not
// a parent version: `parent_package_id` points at a package and nothing
// links a skill's version to the plugin version containing it, so naming a
// version would be a claim that rewrites itself when the parent republishes.
func (p Package) Origin() string {
	if p.Kind == KindSkill {
		if p.ParentName != "" {
			return "Agent Skills spec · distributed inside " + Title(p.ParentName)
		}
		return "Agent Skills spec · standalone skill"
	}

	spec := "Agent Plugins"
	if p.SpecVersion != "" {
		spec += " " + p.SpecVersion
	}
	return "Portable package · " + spec + " · " +
		plural(p.CountOf("skill"), "skill") + ", " + plural(p.CountOf("mcp"), "MCP server")
}

// CountOf is how many components of a kind the tree revealed.
func (p Package) CountOf(kind string) int {
	n := 0
	for _, component := range p.Components {
		if component.Kind == kind {
			n++
		}
	}
	return n
}

// HasContents is the plugin/skill structural split: the package-contents
// section is ABSENT for a standalone skill, not empty.
func (p Package) HasContents() bool { return p.Kind == KindPlugin }

// Tree renders the package-contents tree, derived from the COMPONENT ROWS
// and the manifest object rather than a byte-level file listing: the bundle
// stores no file list, so the only other way would be fetching and
// decompressing up to 25 MB of zstd on every page view.
func (p Package) Tree() string {
	if !p.HasContents() {
		return ""
	}

	type node struct {
		label    string
		children []string
	}

	nodes := []node{{label: p.ManifestObject}}
	if skills := p.namesOf("skill"); len(skills) > 0 {
		for i := range skills {
			skills[i] += "/"
		}
		nodes = append(nodes, node{label: "skills/", children: skills})
	}
	if p.CountOf("mcp") > 0 {
		nodes = append(nodes, node{label: "mcp.json"})
	}
	for _, ext := range p.namesOf("ext") {
		nodes = append(nodes, node{label: ext + "/"})
	}

	var out strings.Builder
	out.WriteString(p.Name + "/\n")
	for i, entry := range nodes {
		last := i == len(nodes)-1
		out.WriteString(branch(last) + entry.label + "\n")
		for j, child := range entry.children {
			out.WriteString(continuation(last) + branch(j == len(entry.children)-1) + child + "\n")
		}
	}
	return strings.TrimRight(out.String(), "\n")
}

func branch(last bool) string {
	if last {
		return "└── "
	}
	return "├── "
}

func continuation(last bool) string {
	if last {
		return "    "
	}
	return "│   "
}

func (p Package) namesOf(kind string) []string {
	out := make([]string, 0, len(p.Components))
	for _, component := range p.Components {
		if component.Kind == kind {
			out = append(out, component.Name)
		}
	}
	return out
}

// ManifestText is the manifest as the panel shows it, indented here rather
// than stored indented: re-encoding through a Go map on the way in would
// silently reorder the keys of a document a reviewer is reading precisely
// because they do not trust it. A document this cannot indent is shown
// verbatim rather than replaced by an error.
func (p Package) ManifestText() string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(p.Manifest), "", "  "); err != nil {
		return p.Manifest
	}
	return buf.String()
}

// ManifestPanelTitle says which of two things the jsonb column holds: a
// standalone skill shows its SKILL.md FRONTMATTER, since a Markdown file is not json.
func (p Package) ManifestPanelTitle() string {
	if p.Kind == KindSkill {
		return "SKILL.md frontmatter"
	}
	return p.ManifestObject
}

// Tag is a version row's distribution tag as the design shows it.
func (v PackageVersion) Tag() string {
	if v.DistTag == "none" {
		return ""
	}
	return v.DistTag
}

// PinLabel is `pinned by N`, DERIVED from profile pins and never stored. It
// sits beside the dist tag rather than replacing it: `latest` is a channel
// this version occupies, `pinned by 2` is what profiles chose, and a
// version is routinely both.
func (v PackageVersion) PinLabel() string {
	if v.PinnedBy == 0 {
		return ""
	}
	return "pinned by " + strconv.Itoa(v.PinnedBy)
}

// Resolution is how one profile resolves the package.
func (d Dependent) Resolution() string {
	switch d.Mode {
	case "pinned":
		if d.Pin == "" {
			return "pinned"
		}
		return d.Pin
	case "range":
		return d.Pin
	default:
		return "latest"
	}
}

// DependentsLine summarises the panel: what the list shows and nothing
// else. No "N people" here — a membership row can name a GROUP, and this
// system does not know how many people are in one. The profile count is
// scoped to the viewer for the same reason the list is: an unscoped total
// would state the number of private profiles by subtraction.
func (p Package) DependentsLine() string {
	switch {
	case len(p.Dependents) == 0:
		return "No profile you can see uses this package"
	case len(p.Dependents) == 1:
		return "Used by 1 profile you can see"
	default:
		return "Used by " + strconv.Itoa(len(p.Dependents)) + " profiles you can see"
	}
}

// PackageHref is the link to one package's detail screen. The id is
// VALIDATED rather than escaped: escaping the two `namespace/name` halves
// separately still leaves `..` intact, since `.` is a legal path character
// url.PathEscape does not touch, and `../../etc/passwd` would traverse out
// of /packages/. Each half must match the object-key segment pattern, or it
// is not linked at all.
func PackageHref(id string) string {
	namespace, name, ok := strings.Cut(id, "/")
	if !ok || !validIDSegment(namespace) || !validIDSegment(name) {
		return "/catalog"
	}
	// Escaped as well as validated, so widening the pattern later cannot
	// silently become a URL injection.
	return "/packages/" + url.PathEscape(namespace) + "/" + url.PathEscape(name)
}

// ProfileHref links to one profile, validating its slug for the same reason
// PackageHref validates a package id: `..` inside one would climb out of
// /profiles/. A slug may be several segments, so each is checked.
func ProfileHref(slug string) string {
	if slug == "" {
		return "/profiles"
	}
	segments := strings.Split(slug, "/")
	escaped := make([]string, 0, len(segments))
	for _, segment := range segments {
		if !validIDSegment(segment) {
			return "/profiles"
		}
		escaped = append(escaped, url.PathEscape(segment))
	}
	return "/profiles/" + strings.Join(escaped, "/")
}

// validIDSegment mirrors blob.segmentPattern: a segment must start
// alphanumerically, which alone rules out "", ".", ".." and a leading slash.
func validIDSegment(segment string) bool {
	if segment == "" || strings.Contains(segment, "..") {
		return false
	}
	for i, r := range segment {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '.' || r == '_' || r == '+' || r == '-'):
		default:
			return false
		}
	}
	return true
}
