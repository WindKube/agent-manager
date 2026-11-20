package view

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// ErrNotFound is the api reporting that there is no such package, or
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

	// Visibility and Owner are read straight off the api's PackageDetail:
	// Visibility is always one of organisation/team/private (an owner-less
	// pre-migration row is still "organisation" — see the migration note on
	// the store side), and Owner is empty for one, never a placeholder like
	// "unknown".
	Visibility string
	Owner      string
	// CanChangeVisibility mirrors the api's own gate (owner or catalog
	// admin) so the control can be shown disabled rather than omitted
	// (FR-126) instead of the screen guessing from the role alone.
	CanChangeVisibility bool

	// SpecVersion is the version the manifest's $schema names, empty for a skill.
	SpecVersion string
	// ParentID and ParentName name the plugin a skill is distributed inside.
	// There is no parent VERSION and there cannot be one.
	ParentID   string
	ParentName string

	ManifestObject string
	Manifest       string

	// Source is nil for a package registered before sources were recorded.
	Source *Provenance
	// Tracking is nil unless the package comes from git.
	Tracking *Tracking
	Signer   Signer

	Components   []Component
	Capabilities Capabilities
	Versions     []PackageVersion
	Dependents   []Dependent
	// Affected is nil when the viewer cannot filter the inventory by this package.
	Affected *AffectedMachines

	// ScanDetail is the security section: the latest version's scan result,
	// its findings and any reviewer decision, read independently of
	// everything above (loadScan) so a deployment can answer the rest of the
	// page while this read is unavailable.
	ScanDetail PackageScan

	// ProfileOptions is every profile this identity may read, for the
	// add-to-profile control (US5). One this identity may not curate, or
	// one that already holds this package, is still listed — never hidden
	// — and marked accordingly.
	ProfileOptions []ProfileOption
	// ProfilesUnavailable is true when the viewer's profiles could not be
	// read, so the control says the read failed rather than claiming there
	// are none.
	ProfilesUnavailable bool

	// SignedOut is the same third outcome the catalog has: a screen renders
	// because the screen is not the secret, only the contents are.
	SignedOut bool
	// Missing is a package that does not exist, or that this identity may
	// not read — one state for both, exactly as the api's 404 is.
	Missing bool

	// Files is the bundle's own file tree (US3/US5: read a skill's files
	// before using it), read independently of everything above — a
	// deployment can answer the package detail while its bundle reader is
	// unavailable, and the two must fail on their own terms.
	Files []FileRow
	// FilesDefault is the file listPackageFiles would recommend reading
	// first. The panel no longer opens on it by itself — see
	// SelectedFilePath — so today this is read only by the api's own
	// response; it stays on the view in case a future control wants to
	// point at it explicitly.
	FilesDefault string
	// FilesUnavailable is the list read failing outright. FilesRejected is
	// the version answering plainly that it was never distributable, which
	// is not a failure of this read.
	FilesUnavailable bool
	FilesRejected    bool

	// SelectedFilePath is the path this screen is showing, set only when
	// the query names one explicitly. Empty means the panel is closed —
	// the panel never falls back to FilesDefault, which is what used to
	// force it open on every page load. It is never used to build a
	// filesystem path — only ever compared against Files.
	SelectedFilePath string
	SelectedFile     *FileDetail
	// The three reasons a chosen path can come back with nothing to show,
	// each a different true statement: a stale or tampered link, a refusal
	// to render something this large, and a kind this hub never renders.
	FileMissing       bool
	FileTooLarge      bool
	FileNotRenderable bool

	// DeleteAccess is whether this identity may delete a package or a
	// version from the catalog, computed the same way OrgAccessFor is: from
	// the viewer the api resolved, never from a role string this screen
	// guessed at. Every delete button on this screen reads the same value.
	DeleteAccess OrgAccess
	// Notice is a write's own outcome — a delete's, or a visibility change's
	// — read back off the redirect exactly as scanner.go's decisionNotice
	// is: a token looked up here, never rendered prose the redirect itself
	// carried.
	Notice *Notice
}

// PackageNotice is a delete's outcome, carried by the post-redirect-get
// query string as a token rather than as rendered prose.
type PackageNotice string

const (
	PackageNoticeVersionDeleted PackageNotice = "version-deleted"
	PackageNoticeRefused        PackageNotice = "refused"
	PackageNoticeFailed         PackageNotice = "failed"
)

// PackageNoticeFrom maps a delete's outcome onto the notice banner. detail is
// the api's own explanation for a conflict (already withdrawn, say);
// subject is the version string for a version delete, escaped by templ on
// render like everything else here.
func PackageNoticeFrom(raw, detail, subject string) *Notice {
	switch PackageNotice(raw) {
	case PackageNoticeVersionDeleted:
		text := "Version withdrawn from the catalog. An existing profile pin or a published " +
			"revision still resolves it; this hub only stops offering it for a new install."
		if subject != "" {
			text = "Version " + subject + " withdrawn from the catalog. An existing profile pin " +
				"or a published revision still resolves it; this hub only stops offering it for " +
				"a new install."
		}
		return &Notice{Tone: "ok", Text: text}
	case PackageNoticeRefused:
		return &Notice{Tone: "dan", Text: "Your role may not delete anything from the catalog, so " +
			"nothing changed."}
	case PackageNoticeFailed:
		text := "That delete was refused."
		if detail != "" {
			text = detail
		}
		return &Notice{Tone: "warn", Text: text}
	default:
		return nil
	}
}

// VersionDeleted is a version delete's acknowledgement.
type VersionDeleted struct {
	PinnedByProfiles int
}

// PackageDeleted is a package delete's acknowledgement.
type PackageDeleted struct {
	VersionsArchived int
}

// VisibilityLabel is the badge beside the package's identity.
func (p Package) VisibilityLabel() string { return visibilityLabels[p.Visibility] }

// VisibilityChangeDisabledReason is why the change-visibility control is
// disabled for a viewer who is neither the owner nor a catalog admin
// (FR-126): stated once, up front, rather than discovered by submitting.
const VisibilityChangeDisabledReason = "Only this package's owner or a catalog admin may change its visibility."

// VisibilityOptions is the change-visibility control's vocabulary. Team and
// private are both enforced by matching a reader against the OWNER
// (queries.PackageReadable), so an owner-less package narrowed to either
// would match nobody, ever — the same guard commands.SetPackageVisibility
// itself applies, restated here so the control never offers a choice the
// api would refuse.
func (p Package) VisibilityOptions() []ImportOption {
	options := []ImportOption{
		{Value: "organisation", Label: "Organisation"},
		{Value: "team", Label: "Team"},
		{Value: "private", Label: "Private"},
	}
	if p.Owner == "" {
		reason := "This package has no recorded owner, so only organisation visibility is safe for it."
		options[1].Disabled, options[1].Reason = true, reason
		options[2].Disabled, options[2].Reason = true, reason
	}
	return options
}

// FileRow is one file the bundle holds, as the files panel lists it.
type FileRow struct {
	Path      string
	Kind      string // "markdown" | "text" | "binary"
	SizeLabel string
	OverLimit bool
}

// FileList is one read of the panel's list.
type FileList struct {
	Files   []FileRow
	Default string
}

// FileDetail is one file's rendered content. Markdown is populated only
// when Kind is "markdown"; Text carries the file's content for both kinds,
// since a markdown file's own source is what MarkdownBody's own Text nodes
// escape from — Text is not rendered a second time for a markdown file.
type FileDetail struct {
	Path     string
	Kind     string // "markdown" | "text"
	Text     string
	Markdown MarkdownDoc
}

// FileHref selects one file without disturbing anything else the page
// shows — the same query-parameter idiom the audit screen's detail panel
// uses.
func (p Package) FileHref(path string) string {
	values := url.Values{}
	values.Set("file", path)
	return PackageHref(p.ID) + "?" + values.Encode()
}

// ProfileOption is one of the viewer's profiles as the add-to-profile
// control offers it.
type ProfileOption struct {
	Slug       string
	Name       string
	Visibility string
	CanCurate  bool
	// Held is whether this profile already holds the package this screen
	// is showing.
	Held bool
}

func (o ProfileOption) VisibilityLabel() string { return visibilityLabels[o.Visibility] }

func (o ProfileOption) Href() string { return ProfileHref(o.Slug) }

// ProfileOptionsFor is one visibility group of ProfileOptions, in the order
// the add-to-profile control renders them.
func (p Package) ProfileOptionsFor(visibility string) []ProfileOption {
	var out []ProfileOption
	for _, option := range p.ProfileOptions {
		if option.Visibility == visibility {
			out = append(out, option)
		}
	}
	return out
}

// ProfileOptionsHeld marks each option already present among dependents.
// Dependents already answers "does this profile hold this package", scoped
// identically to the profile list itself, so this is what makes the
// add-to-profile control honest without a second read per profile.
func ProfileOptionsHeld(options []ProfileOption, dependents []Dependent) []ProfileOption {
	held := make(map[string]bool, len(dependents))
	for _, dependent := range dependents {
		held[dependent.Slug] = true
	}
	out := make([]ProfileOption, len(options))
	for i, option := range options {
		option.Held = held[option.Slug]
		out[i] = option
	}
	return out
}

// Component is one component the file tree revealed.
type Component struct {
	Kind string
	Name string
	Path string
	Note string

	Event     string
	Matcher   string
	Transport string
	Target    string
}

// Detail is the row's right-hand text: what a hook or MCP server runs or
// reaches, and the note for anything else.
func (c Component) Detail() string {
	switch c.Kind {
	case "hook":
		matcher := c.Matcher
		if matcher == "" {
			matcher = "every tool"
		}
		parts := []string{c.Event, "matcher " + matcher}
		if c.Target != "" {
			parts = append(parts, c.Target)
		}
		return strings.Join(parts, " · ")
	case "mcp":
		if c.Transport != "" && c.Target != "" {
			return c.Transport + " · " + c.Target
		}
	}
	return c.Note
}

// ComponentGroup is one kind's rows in the contents section.
type ComponentGroup struct {
	Label      string
	Components []Component
}

var componentGroups = []struct{ kind, label string }{
	{"skill", "Skills"}, {"agent", "Agents"}, {"command", "Commands"},
	{"hook", "Hooks"}, {"mcp", "MCP servers"}, {"ext", "Client extensions"},
}

// ComponentGroups groups the rows by kind, omitting empty kinds.
func (p Package) ComponentGroups() []ComponentGroup {
	out := make([]ComponentGroup, 0, len(componentGroups))
	for _, group := range componentGroups {
		var rows []Component
		for i := range p.Components {
			if p.Components[i].Kind == group.kind {
				rows = append(rows, p.Components[i])
			}
		}
		if len(rows) > 0 {
			out = append(out, ComponentGroup{Label: group.label, Components: rows})
		}
	}
	return out
}

// ContentsNote counts the components by kind, naming the plugin-surface
// kinds only where present.
func (p Package) ContentsNote() string {
	parts := []string{
		strconv.Itoa(p.CountOf("skill")) + " skills",
		strconv.Itoa(p.CountOf("mcp")) + " MCP",
	}
	for _, kind := range []string{"agent", "command", "hook"} {
		if n := p.CountOf(kind); n > 0 {
			parts = append(parts, plural(n, kind))
		}
	}
	parts = append(parts, strconv.Itoa(p.CountOf("ext"))+" extensions")
	return strings.Join(parts, " · ")
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

	SourceURL    string
	SourceRef    string
	SourceCommit string

	Signature VersionSignature
}

// ShortCommit is the commit as a reader scans it.
func (v PackageVersion) ShortCommit() string { return shortCommit(v.SourceCommit) }

// CommitHref links the commit on its forge, empty where the forge's commit
// URL shape is not known.
func (v PackageVersion) CommitHref() string { return commitHref(v.SourceURL, v.SourceCommit) }

// SignerChangeDisabledReason is why the expected-signer control is disabled.
const SignerChangeDisabledReason = "Only this package's owner or a catalog admin may change its expected signer."

// Signer is the package's expected Sigstore signer: an exact OIDC issuer and
// an identity pattern. Both are empty when none is configured.
type Signer struct {
	Issuer    string
	Identity  string
	CanChange bool
}

func (s Signer) Configured() bool { return s.Issuer != "" }

// Summary is the line under the control.
func (s Signer) Summary() string {
	if !s.Configured() {
		return "No expected signer: no version of this package counts as signed."
	}
	return "Expected signer: " + s.Identity + " via " + s.Issuer
}

// SignatureStatus mirrors the api's five values. Only SignatureMatching is a
// trustworthy signature; the two other verified states prove the bytes were
// signed by somebody, not by whoever should have signed them.
type SignatureStatus string

const (
	SignatureUnsigned         SignatureStatus = "unsigned"
	SignatureInvalid          SignatureStatus = "invalid"
	SignatureNoExpectedSigner SignatureStatus = "verified-no-expected-signer"
	SignatureUnexpectedSigner SignatureStatus = "verified-unexpected-signer"
	SignatureMatching         SignatureStatus = "verified-matching"
)

type VersionSignature struct {
	Status   SignatureStatus
	Issuer   string
	Identity string
	Reason   string
	Ref      string
}

func (s VersionSignature) Label() string {
	switch s.Status {
	case SignatureMatching:
		return "Signed by expected signer"
	case SignatureUnexpectedSigner:
		return "Signed, unexpected signer"
	case SignatureNoExpectedSigner:
		return "Signed, no expected signer"
	case SignatureInvalid:
		return "Signature invalid"
	default:
		return "Unsigned"
	}
}

func (s VersionSignature) Tone() string {
	switch s.Status {
	case SignatureMatching:
		return "ok"
	case SignatureUnexpectedSigner, SignatureInvalid:
		return "dan"
	default:
		return "warn"
	}
}

// Detail says who signed, or why the signature failed, empty for an unsigned
// version.
func (s VersionSignature) Detail() string {
	switch s.Status {
	case SignatureMatching, SignatureUnexpectedSigner, SignatureNoExpectedSigner:
		return "signed by " + s.Identity + " via " + s.Issuer
	case SignatureInvalid:
		if s.Reason == "" {
			return "the signature did not verify"
		}
		return "did not verify: " + s.Reason
	default:
		return ""
	}
}

// TrackingChangeDisabledReason is why the track-upstream control is disabled.
const TrackingChangeDisabledReason = "Only this package's owner or a catalog admin may change its upstream tracking."

// Tracking is the upstream check's control and its last outcome.
type Tracking struct {
	On          bool
	Pattern     string
	LastChecked string
	LastError   string
	CanChange   bool
}

// Status is the line under the control: when the check last ran, and why
// it failed if it did.
func (t Tracking) Status() string {
	status := "not checked yet"
	if t.LastChecked != "" {
		status = "last checked " + t.LastChecked
	}
	if t.LastError != "" {
		status += " · error: " + t.LastError
	}
	return status
}

// Provenance is where a package comes from, plus the commit the version on
// screen was downloaded at.
type Provenance struct {
	Kind         string
	URL          string
	Ref          string
	Subdirectory string
	Commit       string
	CommitURL    string
}

// Lead is the provenance line up to the commit:
// "from github.com/acme/skills @ v1.2.0".
func (s Provenance) Lead() string {
	switch {
	case s.Kind == "upload":
		return "from an uploaded archive"
	case s.URL == "":
		return ""
	}
	lead := "from " + strings.TrimPrefix(s.URL, "https://")
	if s.Ref != "" {
		lead += " @ " + s.Ref
	}
	return lead
}

func (s Provenance) ShortCommit() string { return shortCommit(s.Commit) }

func (s Provenance) CommitHref() string { return commitHref(s.CommitURL, s.Commit) }

// Tail is what follows the commit: ", subdirectory pdf/".
func (s Provenance) Tail() string {
	if s.Subdirectory == "" {
		return ""
	}
	return ", subdirectory " + strings.TrimSuffix(s.Subdirectory, "/") + "/"
}

func shortCommit(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func commitHref(repo, sha string) string {
	if sha == "" || !strings.HasPrefix(repo, "https://github.com/") {
		return ""
	}
	return repo + "/commit/" + sha
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
	for i := range p.Components {
		component := &p.Components[i]
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
	if p.hasRootMCP() {
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

// hasRootMCP: an MCP server may also come from the Claude Code extension,
// which the tree shows as its directory rather than as mcp.json.
func (p Package) hasRootMCP() bool {
	for i := range p.Components {
		component := &p.Components[i]
		if component.Kind == "mcp" && (component.Path == "mcp.json" || strings.HasPrefix(component.Path, "mcp.json#")) {
			return true
		}
	}
	return false
}

func (p Package) namesOf(kind string) []string {
	out := make([]string, 0, len(p.Components))
	for i := range p.Components {
		component := &p.Components[i]
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
	namespace, name, ok := SplitPackageID(id)
	if !ok {
		return "/catalog"
	}
	// Escaped as well as validated, so widening the pattern later cannot
	// silently become a URL injection.
	return "/packages/" + url.PathEscape(namespace) + "/" + url.PathEscape(name)
}

// SplitPackageID is a package id's two halves, validated the same way
// PackageHref validates them — shared so a form posting an id (the
// visibility control) rejects the same malformed values a link would rather
// than re-deriving the rule.
func SplitPackageID(id string) (namespace, name string, ok bool) {
	namespace, name, cut := strings.Cut(id, "/")
	if !cut || !validIDSegment(namespace) || !validIDSegment(name) {
		return "", "", false
	}
	return namespace, name, true
}

// PackageDeleteHref links the package-level delete form, validated the same
// way PackageHref is.
func PackageDeleteHref(id string) string {
	namespace, name, ok := SplitPackageID(id)
	if !ok {
		return "/catalog"
	}
	return "/packages/" + url.PathEscape(namespace) + "/" + url.PathEscape(name) + "/delete"
}

// VersionDeleteHref links one version row's delete form.
func VersionDeleteHref(id, version string) string {
	namespace, name, ok := SplitPackageID(id)
	if !ok {
		return "/catalog"
	}
	return "/packages/" + url.PathEscape(namespace) + "/" + url.PathEscape(name) +
		"/versions/" + url.PathEscape(version) + "/delete"
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
