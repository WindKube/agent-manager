package view

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// ErrNotFound means the package does not exist or this identity may not read it.
// One error for both, so a caller cannot probe for packages it may not see.
var ErrNotFound = errors.New("no such package")

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

	// Owner is empty for an owner-less package, never a placeholder like "unknown".
	Visibility string
	Owner      string
	// CanChangeVisibility mirrors the api's own gate so the control can be shown disabled rather than omitted.
	CanChangeVisibility bool

	// SpecVersion is the version the manifest's $schema names, empty for a skill.
	SpecVersion string
	// ParentID and ParentName name the plugin a skill is distributed inside; there is no parent version.
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

	// ScanDetail is read independently of the rest so the page still renders while the scan read is unavailable.
	ScanDetail PackageScan

	// ProfileOptions lists every readable profile, including ones the viewer cannot curate or that already hold this package.
	ProfileOptions []ProfileOption
	// ProfilesUnavailable makes the control say the read failed rather than claim there are none.
	ProfilesUnavailable bool

	SignedOut bool
	// Missing covers both a nonexistent and an unreadable package, as the api's 404 does.
	Missing bool

	// Files is read independently of the package detail so the two fail on their own terms.
	Files []FileRow
	// FilesDefault is not used to open the panel; it is kept for a control that wants to point at it.
	FilesDefault string
	// FilesRejected means the version was never distributable, which is not a read failure.
	FilesUnavailable bool
	FilesRejected    bool

	// SelectedFilePath is set only when the query names a file; it is only ever compared against Files,
	// never used to build a filesystem path.
	SelectedFilePath  string
	SelectedFile      *FileDetail
	FileMissing       bool
	FileTooLarge      bool
	FileNotRenderable bool

	// DeleteAccess is computed from the viewer the api resolved, never from a guessed role string.
	DeleteAccess OrgAccess
	// Notice is looked up from a redirect token, never prose the redirect carried.
	Notice *Notice
}

// PackageNotice is a delete's outcome, carried through the redirect as a token rather than prose.
type PackageNotice string

const (
	PackageNoticeVersionDeleted PackageNotice = "version-deleted"
	PackageNoticeRefused        PackageNotice = "refused"
	PackageNoticeFailed         PackageNotice = "failed"
)

// PackageNoticeFrom maps a delete's outcome onto the notice banner; detail is the api's explanation for a conflict.
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

// VisibilityChangeDisabledReason is why the change-visibility control is disabled.
const VisibilityChangeDisabledReason = "Only this package's owner or a catalog admin may change its visibility."

// VisibilityOptions is the change-visibility control's vocabulary. Team and private match readers against the
// owner, so an owner-less package narrowed to either would be readable by nobody; the api refuses it too.
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

// FileDetail is one file's rendered content. Markdown is set only for markdown files; Text holds the source for both kinds.
type FileDetail struct {
	Path     string
	Kind     string // "markdown" | "text"
	Text     string
	Markdown MarkdownDoc
}

// FileHref selects one file via the query string.
func (p Package) FileHref(path string) string {
	values := url.Values{}
	values.Set("file", path)
	return PackageHref(p.ID) + "?" + values.Encode()
}

// ProfileOption is one of the viewer's profiles as the add-to-profile control offers it.
type ProfileOption struct {
	Slug       string
	Name       string
	Visibility string
	CanCurate  bool
	Held       bool
}

func (o ProfileOption) VisibilityLabel() string { return visibilityLabels[o.Visibility] }

func (o ProfileOption) Href() string { return ProfileHref(o.Slug) }

// ProfileOptionsFor is one visibility group of ProfileOptions.
func (p Package) ProfileOptionsFor(visibility string) []ProfileOption {
	var out []ProfileOption
	for _, option := range p.ProfileOptions {
		if option.Visibility == visibility {
			out = append(out, option)
		}
	}
	return out
}

// ProfileOptionsHeld marks each option already present among dependents, avoiding a second read per profile.
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

// toolEvents are the hook events whose matcher selects a tool; an empty matcher elsewhere matches nothing tool-shaped.
var toolEvents = map[string]bool{
	"PreToolUse": true, "PostToolUse": true, "PostToolUseFailure": true, "PermissionRequest": true,
}

// Detail is what a hook or MCP server runs or reaches, and the note for anything else.
func (c Component) Detail() string {
	switch c.Kind {
	case "hook":
		parts := []string{c.Event}
		switch {
		case c.Matcher != "":
			parts = append(parts, "matcher "+c.Matcher)
		case toolEvents[c.Event]:
			parts = append(parts, "matcher every tool")
		}
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

// ContentsNote counts the components by kind, naming the plugin-surface kinds only where present.
func (p Package) ContentsNote() string {
	parts := []string{
		plural(p.CountOf("skill"), "skill"),
		strconv.Itoa(p.CountOf("mcp")) + " MCP",
	}
	for _, kind := range []string{"agent", "command", "hook"} {
		if n := p.CountOf(kind); n > 0 {
			parts = append(parts, plural(n, kind))
		}
	}
	parts = append(parts, plural(p.CountOf("ext"), "extension"))
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
	// PinnedBy counts profiles visible to the viewer that pin this version; derived, never stored.
	PinnedBy int

	SourceURL    string
	SourceRef    string
	SourceCommit string

	Signature VersionSignature
}

func (v PackageVersion) ShortCommit() string { return shortCommit(v.SourceCommit) }

// CommitHref links the commit on its forge, empty where the forge's URL shape is unknown.
func (v PackageVersion) CommitHref() string { return commitHref(v.SourceURL, v.SourceCommit) }

// SignerChangeDisabledReason is why the expected-signer control is disabled.
const SignerChangeDisabledReason = "Only this package's owner or a catalog admin may change its expected signer."

// Signer is the package's expected Sigstore signer: an exact OIDC issuer and an identity pattern.
type Signer struct {
	Issuer    string
	Identity  string
	CanChange bool
}

func (s Signer) Configured() bool { return s.Issuer != "" }

func (s Signer) Summary() string {
	if !s.Configured() {
		return "No expected signer: no version of this package counts as signed."
	}
	return "Expected signer: " + s.Identity + " via " + s.Issuer
}

// SignatureStatus mirrors the api's values. Only SignatureMatching is trustworthy; the other verified states
// prove the bytes were signed by somebody, not by whoever should have signed them.
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

// Detail says who signed or why the signature failed, empty for an unsigned version.
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

// Status says when the check last ran, and why it failed if it did.
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

// Provenance is where a package comes from, plus the commit the shown version was downloaded at.
type Provenance struct {
	Kind         string
	URL          string
	Ref          string
	Subdirectory string
	Commit       string
	CommitURL    string
}

// Lead is the provenance line up to the commit, e.g. "from github.com/acme/skills @ v1.2.0".
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

// Tail is what follows the commit, e.g. ", subdirectory pdf/".
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
	// Scanned is not len(Rows) > 0: a clean scan and no scan both produce an empty list.
	Scanned bool
	Rows    []CapabilityRow
}

// CapabilityRow is one capability name with both sides of the comparison.
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
	// Indefinite means the analysis found targets it could not name, so Detail is a sample.
	Indefinite bool
}

// The capability verdicts describe a relationship between two records; nothing here grants or denies.
const (
	CapabilityUndeclared = "not declared"
	CapabilityUnobserved = "declared, not observed"
	CapabilityExceeds    = "exceeds the expectation"
	CapabilityWithin     = "within the expectation"
)

// Status compares the two sides; with no expectation recorded, everything is surfaced rather than accepted.
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

// Tone colours the verdict. "within" is not coloured as a pass, since the hub enforces nothing here.
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

// Origin is the origin line. A skill names its parent package, never a parent version: nothing links a
// skill's version to the plugin version containing it.
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

// HasContents is false for a standalone skill: its contents section is absent, not empty.
func (p Package) HasContents() bool { return p.Kind == KindPlugin }

// Tree renders the contents tree from the component rows, since the alternative is decompressing the
// whole bundle on every page view.
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

// hasRootMCP ignores MCP servers from the Claude Code extension, which the tree shows as its directory.
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

// ManifestText indents the manifest at render time; re-encoding through a Go map would reorder keys a
// reviewer is reading precisely because they do not trust it.
func (p Package) ManifestText() string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(p.Manifest), "", "  "); err != nil {
		return p.Manifest
	}
	return buf.String()
}

// ManifestPanelTitle is the manifest object name, or "SKILL.md frontmatter" for a standalone skill.
func (p Package) ManifestPanelTitle() string {
	if p.Kind == KindSkill {
		return "SKILL.md frontmatter"
	}
	return p.ManifestObject
}

func (v PackageVersion) Tag() string {
	if v.DistTag == "none" {
		return ""
	}
	return v.DistTag
}

// PinLabel sits beside the dist tag rather than replacing it: a version is routinely both "latest" and pinned.
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

// DependentsLine counts only profiles the viewer can see; an unscoped total would leak the number of
// private profiles. It never counts people, since a membership can name a group.
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

// PackageHref links one package's detail screen. The id is validated, not just escaped: url.PathEscape
// leaves ".." intact, which would traverse out of /packages/.
func PackageHref(id string) string {
	namespace, name, ok := SplitPackageID(id)
	if !ok {
		return "/catalog"
	}
	// Escaped as well, so widening the pattern later cannot become a URL injection.
	return "/packages/" + url.PathEscape(namespace) + "/" + url.PathEscape(name)
}

// SplitPackageID splits and validates a package id, shared by links and forms so both reject the same values.
func SplitPackageID(id string) (namespace, name string, ok bool) {
	namespace, name, cut := strings.Cut(id, "/")
	if !cut || !validIDSegment(namespace) || !validIDSegment(name) {
		return "", "", false
	}
	return namespace, name, true
}

// PackageDeleteHref links the package-level delete form, validated like PackageHref.
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

// ProfileHref links to one profile, validating each slug segment so ".." cannot climb out of /profiles/.
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
