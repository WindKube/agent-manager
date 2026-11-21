package view

import "strconv"

// Resolved versions, verdicts and policy notes arrive already decided by internal/domain/resolve; nothing
// here recomputes a gate outcome.

// ProfileRow is one profile as the list names it.
type ProfileRow struct {
	Slug         string
	Name         string
	Visibility   string
	PackageCount int
	HeadRevision int
	CanCurate    bool
}

func (r ProfileRow) Unpublished() bool { return r.HeadRevision == 0 }

func (r ProfileRow) RevisionLabel() string {
	if r.Unpublished() {
		return "unpublished"
	}
	return "r" + strconv.Itoa(r.HeadRevision)
}

func (r ProfileRow) VisibilityLabel() string { return visibilityLabels[r.Visibility] }

func (r ProfileRow) Href() string { return "/profiles/" + r.Slug }

// visibilityLabels covers both profile and package visibility vocabularies.
var visibilityLabels = map[string]string{
	"organisation": "Organisation",
	"shared":       "Shared",
	"team":         "Team",
	"private":      "Private",
}

// ProfileVisibilities is the create form's vocabulary, safest default first.
var ProfileVisibilities = []struct{ Value, Label string }{
	{"private", "Private"},
	{"shared", "Shared"},
	{"organisation", "Organisation"},
}

// ProfileDefaultPolicies is the create form's version-policy vocabulary.
var ProfileDefaultPolicies = []struct{ Value, Label string }{
	{"floating-latest", "Floating latest"},
	{"pinned", "Pinned"},
	{"range", "Range"},
}

// Profiles is the list screen.
type Profiles struct {
	Rows []ProfileRow
	GovernanceState
	Notice    *Notice
	CanCreate bool
	// CreateRefused is the api's refusal, rendered on the same request so a forwarded link cannot inject text.
	CreateRefused string
}

func (p Profiles) Empty() bool { return len(p.Rows) == 0 }

func (p Profiles) Count() string {
	switch {
	case !p.Readable():
		return ""
	case len(p.Rows) == 1:
		return "1 profile"
	default:
		return strconv.Itoa(len(p.Rows)) + " profiles"
	}
}

// ProfileOutcome is the gate's effect on one entry, mirroring internal/domain/resolve.Outcome.
type ProfileOutcome string

const (
	OutcomeResolved   ProfileOutcome = "resolved"
	OutcomeWarned     ProfileOutcome = "warned"
	OutcomeOverridden ProfileOutcome = "overridden"
	OutcomeDowngraded ProfileOutcome = "downgraded"
	OutcomeSkipped    ProfileOutcome = "skipped"
)

func (o ProfileOutcome) Label() string {
	switch o {
	case OutcomeResolved:
		return "Resolved"
	case OutcomeWarned:
		return "Warned"
	case OutcomeOverridden:
		return "Overridden"
	case OutcomeDowngraded:
		return "Downgraded"
	case OutcomeSkipped:
		return "Skipped"
	default:
		return string(o)
	}
}

func (o ProfileOutcome) Tone() string {
	switch o {
	case OutcomeResolved:
		return "ok"
	case OutcomeWarned, OutcomeOverridden, OutcomeDowngraded:
		return "warn"
	case OutcomeSkipped:
		return "dan"
	default:
		return "neutral"
	}
}

// SkipReasonLabel phrases an internal/domain/resolve.Reason.
func SkipReasonLabel(reason string) string {
	switch reason {
	case "flagged-blocked-by-gate":
		return "blocked by the org gate"
	case "flagged-awaiting-approval":
		return "awaiting reviewer approval"
	case "version-rejected":
		return "rejected by the scanner"
	case "no-clean-version-available":
		return "no clean version available"
	case "pin-target-missing":
		return "the pinned version no longer exists"
	case "unsigned-and-signatures-required":
		return "unsigned, and the org requires signatures"
	default:
		return reason
	}
}

// EntryModeLabel is the profile's own setting for one entry, never relabelled by what the gate did.
func EntryModeLabel(mode string) string {
	switch mode {
	case "latest":
		return "Floating latest"
	case "pinned":
		return "Pinned"
	case "range":
		return "Range"
	default:
		return mode
	}
}

// ProfileMemberRoleLabel labels a membership role, distinct from the organisation roles Viewer resolves.
func ProfileMemberRoleLabel(role string) string {
	switch role {
	case "owner":
		return "Owner"
	case "maintainer":
		return "Maintainer"
	case "reviewer":
		return "Reviewer"
	case "consumer":
		return "Consumer"
	default:
		return role
	}
}

var ProfileMemberRoles = []struct{ Value, Label string }{
	{"owner", "Owner"},
	{"maintainer", "Maintainer"},
	{"reviewer", "Reviewer"},
	{"consumer", "Consumer"},
}

var ProfileMemberKinds = []struct{ Value, Label string }{
	{"user", "Person"},
	{"group", "Identity-provider group"},
}

// targetLabels and targetPaths are display-only: what to call a sync target and where a client writes it.
var targetLabels = map[string]string{
	"claude-code": "Claude Code",
	"codex":       "Codex",
	"opencode":    "OpenCode",
}

var targetPaths = map[string]string{
	"claude-code": "~/.claude/skills/",
	"codex":       "~/.agents/skills/",
	"opencode":    "~/.config/opencode/",
}

// ProfileTargetRow is one sync target and whether this profile enables it.
type ProfileTargetRow struct {
	Target  string
	Enabled bool
}

func (t ProfileTargetRow) Label() string {
	if label, ok := targetLabels[t.Target]; ok {
		return label
	}
	return t.Target
}

func (t ProfileTargetRow) Path() string { return targetPaths[t.Target] }

// ProfileSkip is one excluded entry and why.
type ProfileSkip struct {
	Reason              string
	Detail              string
	WouldHaveResolvedTo string
}

func (s ProfileSkip) ReasonLabel() string { return SkipReasonLabel(s.Reason) }

// ProfileOverride is the acceptance a flagged version resolved under.
type ProfileOverride struct {
	Reviewer string
	Note     string
	// Expires is "" when the acceptance does not lapse.
	Expires string
}

// ProfileEntryRow is one package in a profile, as the detail screen draws it.
type ProfileEntryRow struct {
	ID   string
	Name string
	Kind Kind

	Mode          string
	Range         string
	PinnedVersion string

	LatestVersion string
	LatestVerdict Verdict

	// Version and Verdict are empty exactly when Outcome is OutcomeSkipped.
	Version string
	Verdict Verdict
	Digest  string

	Outcome ProfileOutcome
	// Note is the resolver's policy note, rendered verbatim and never recomposed.
	Note     string
	Skip     *ProfileSkip
	Override *ProfileOverride

	// Unpublished means this row would resolve differently from the head revision's lockfile.
	Unpublished bool
}

func (e ProfileEntryRow) ModeLabel() string { return EntryModeLabel(e.Mode) }

// PinTarget is what the row resolves to, or its latest catalog version when the gate excluded it.
func (e ProfileEntryRow) PinTarget() string {
	if e.Version != "" {
		return e.Version
	}
	return e.LatestVersion
}

func (e ProfileEntryRow) CanFloat() bool { return e.Mode != "latest" }

// PinFieldValue is the pinned version, or PinTarget as a starting guess.
func (e ProfileEntryRow) PinFieldValue() string {
	if e.Mode == "pinned" {
		return e.PinnedVersion
	}
	return e.PinTarget()
}

// ProfileMemberRow is one subject a profile is shared with.
type ProfileMemberRow struct {
	Kind        string
	Ref         string
	Role        string
	DisplayName string
}

// Label is the display name when the hub has one, and the raw subject otherwise.
func (m ProfileMemberRow) Label() string {
	if m.DisplayName != "" {
		return m.DisplayName
	}
	return m.Ref
}

func (m ProfileMemberRow) KindLabel() string {
	if m.Kind == "group" {
		return "Group"
	}
	return "Person"
}

func (m ProfileMemberRow) RoleLabel() string { return ProfileMemberRoleLabel(m.Role) }

// ProfileRevisionRow is one published revision, as the history panel lists it.
type ProfileRevisionRow struct {
	Revision    int
	Note        string
	PublishedAt string
	PublishedBy string
}

// ProfilePermissions is what this identity may do here, so the screen can disable rather than hide a control.
type ProfilePermissions struct {
	Curate  bool
	Share   bool
	Publish bool
	// Delete is the role check alone; Profile.CanDelete also requires no published revision.
	Delete bool
}

const CurateDisabledReason = "Your role on this profile may not change its entries."

// ShareDisabledReason explains why sharing is owner-only.
const ShareDisabledReason = "Only this profile's owner may change who it is shared with: a " +
	"maintainer who could re-share it could widen an access decision the owner made."

const PublishDisabledReason = "Your role on this profile may not publish a revision."

const ProfileDeleteRoleReason = "Only this profile's owner may delete it."

// ProfileDeleteHasRevisionsReason: published revisions are never deleted, since a client may have synced
// them, so deleting their profile is refused rather than cascaded.
const ProfileDeleteHasRevisionsReason = "This profile has published revisions that a client " +
	"may already have synced. Deleting it would either orphan that history or remove a " +
	"revision, which this hub never does."

// ProfileAddOption is one catalog package the "Add package" select can offer.
type ProfileAddOption struct {
	ID   string
	Name string
	Kind Kind
}

// Profile is the detail screen.
type Profile struct {
	Slug        string
	Name        string
	Description string
	Visibility  string
	OwnerTeam   string

	DefaultPolicy string
	Gate          string
	HeadRevision  int
	ForkedFrom    string

	// Role is empty for a reader with no membership, e.g. of an organisation-visible profile.
	Role        string
	Permissions ProfilePermissions

	UnpublishedChanges bool

	Entries   []ProfileEntryRow
	Members   []ProfileMemberRow
	Targets   []ProfileTargetRow
	Revisions []ProfileRevisionRow

	// AddOptions is every catalog package this profile does not hold; empty for a non-curator or when the
	// catalog cannot be read.
	AddOptions []ProfileAddOption

	GovernanceState
	// Missing covers both a nonexistent and an unreadable profile, so a private one cannot be probed.
	Missing bool
	Notice  *Notice
	// Refusal is the api's refusal of a curation request, rendered on the same request.
	Refusal string

	// Diff is set exactly when the URL carries a revision query parameter.
	Diff *RevisionDiffPanel
}

func (p Profile) VisibilityLabel() string { return visibilityLabels[p.Visibility] }

func (p Profile) DefaultPolicyLabel() string { return DefaultPolicyLabel(p.DefaultPolicy) }

func DefaultPolicyLabel(policy string) string {
	for _, option := range ProfileDefaultPolicies {
		if option.Value == policy {
			return option.Label
		}
	}
	return policy
}

func (p Profile) GateLabel() string { return GateLabel(p.Gate) }

func GateLabel(gate string) string {
	switch gate {
	case "block":
		return "Block"
	case "approval":
		return "Approval required"
	case "warn-with-override":
		return "Warn, with override"
	default:
		return gate
	}
}

func (p Profile) RoleLabel() string {
	if p.Role == "" {
		return ""
	}
	return ProfileMemberRoleLabel(p.Role)
}

func (p Profile) HeadRevisionLabel() string {
	if p.HeadRevision == 0 {
		return "unpublished"
	}
	return "r" + strconv.Itoa(p.HeadRevision)
}

func (p Profile) SkillEntries() []ProfileEntryRow { return p.entriesOfKind(KindSkill) }

func (p Profile) PluginEntries() []ProfileEntryRow { return p.entriesOfKind(KindPlugin) }

func (p Profile) entriesOfKind(kind Kind) []ProfileEntryRow {
	var out []ProfileEntryRow
	for i := range p.Entries {
		if p.Entries[i].Kind == kind {
			out = append(out, p.Entries[i])
		}
	}
	return out
}

func (p Profile) MembersEmpty() bool { return len(p.Members) == 0 }

func (p Profile) RevisionsEmpty() bool { return len(p.Revisions) == 0 }

// CanDelete combines the role check with ProfileDeleteHasRevisionsReason's rule.
func (p Profile) CanDelete() bool { return p.Permissions.Delete && p.HeadRevision == 0 }

// DeleteDisabledReason is empty exactly when CanDelete is true.
func (p Profile) DeleteDisabledReason() string {
	switch {
	case !p.Permissions.Delete:
		return ProfileDeleteRoleReason
	case p.HeadRevision > 0:
		return ProfileDeleteHasRevisionsReason
	default:
		return ""
	}
}

func (p Profile) SkillAddOptions() []ProfileAddOption { return p.addOptionsOfKind(KindSkill) }

func (p Profile) PluginAddOptions() []ProfileAddOption { return p.addOptionsOfKind(KindPlugin) }

func (p Profile) addOptionsOfKind(kind Kind) []ProfileAddOption {
	var out []ProfileAddOption
	for _, option := range p.AddOptions {
		if option.Kind == kind {
			out = append(out, option)
		}
	}
	return out
}
