package view

import "strconv"

// The Profiles screens' view models.
//
// Every entry's resolved version, verdict and policy note arrive from the hub
// already decided by internal/domain/resolve. Nothing here recomputes a gate
// outcome — it only turns the api's closed vocabulary into a sentence.

// ProfileRow is one profile as the list names it.
type ProfileRow struct {
	Slug         string
	Name         string
	Visibility   string
	PackageCount int
	HeadRevision int
}

// Unpublished is a profile with no revision at all — created but never
// published, which is a real and common state.
func (r ProfileRow) Unpublished() bool { return r.HeadRevision == 0 }

func (r ProfileRow) RevisionLabel() string {
	if r.Unpublished() {
		return "unpublished"
	}
	return "r" + strconv.Itoa(r.HeadRevision)
}

func (r ProfileRow) VisibilityLabel() string { return visibilityLabels[r.Visibility] }

func (r ProfileRow) Href() string { return "/profiles/" + r.Slug }

// visibilityLabels is shared between profile and package visibility: both
// vocabularies spell "organisation" and "private" the same way, and "team"
// (package-only) and "shared" (profile-only) each answer to one of them.
var visibilityLabels = map[string]string{
	"organisation": "Organisation",
	"shared":       "Shared",
	"team":         "Team",
	"private":      "Private",
}

// ProfileVisibilities is the create form's vocabulary, in the order a person
// reads them: the safest default first.
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
	Notice *Notice
	// CanCreate is the list-level form of the same role gate the detail screen
	// applies per action: an identity resolving to no role cannot create a
	// profile either, and the form is absent rather than offered and refused.
	CanCreate bool
	// CreateRefused carries the api's own sentence when the create form was
	// submitted and refused — the slug is taken, the visibility is not a value
	// the api knows. It renders inline, on the same request, so nothing here is
	// text a forwarded link could have put in the hub's mouth.
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

// ---- the detail screen --------------------------------------------------

// ProfileOutcome is the gate's effect on one entry, in the resolver's own
// closed vocabulary (internal/domain/resolve.Outcome).
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

// SkipReasonLabel turns the resolver's exclusion reason into a sentence
// fragment. The values mirror internal/domain/resolve.Reason.
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

// EntryModeLabel is the profile's own setting for one entry, never relabelled
// by what the gate then did to it.
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

// ProfileMemberRoleLabel is a membership role, distinct from the
// organisation roles view.Viewer resolves.
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

// ProfileMemberRoles is the sharing form's role vocabulary.
var ProfileMemberRoles = []struct{ Value, Label string }{
	{"owner", "Owner"},
	{"maintainer", "Maintainer"},
	{"reviewer", "Reviewer"},
	{"consumer", "Consumer"},
}

// ProfileMemberKinds is the sharing form's subject-kind vocabulary.
var ProfileMemberKinds = []struct{ Value, Label string }{
	{"user", "Person"},
	{"group", "Identity-provider group"},
}

// targetLabels and targetPaths are the two things a screen says about an agent
// directory convention that the api's bare enum value does not: what to call it
// and where a client writes it. Neither affects what the server stores, only
// how the choice reads.
var targetLabels = map[string]string{
	"claude-code": "Claude Code",
	"codex":       "Codex",
}

var targetPaths = map[string]string{
	"claude-code": "~/.claude/skills/",
	"codex":       "~/.codex/prompts/",
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
//
// Unlike the scanner's Override, a nil Expires here genuinely means the
// acceptance does not lapse — the hub has already turned the lockfile schema's
// required-but-sometimes-absent zero instant back into that absence at the
// door (see hub.EntryOverride).
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

	// Version and Verdict are what this entry actually resolves to, empty
	// exactly when Outcome is OutcomeSkipped.
	Version string
	Verdict Verdict
	Digest  string

	Outcome ProfileOutcome
	// Note is the gate's policy note, rendered verbatim from the api. It is
	// never recomposed here — the resolver decided what happened and this is
	// its sentence about it.
	Note     string
	Skip     *ProfileSkip
	Override *ProfileOverride

	// Unpublished means this row would resolve differently from the head
	// revision's lockfile: nothing has reached a machine yet.
	Unpublished bool
}

func (e ProfileEntryRow) ModeLabel() string { return EntryModeLabel(e.Mode) }

// PinTarget is the version a "Pin" control on this row would freeze: what it
// currently resolves to, or its latest catalog version when the gate excluded
// it and there is nothing else to pin to.
func (e ProfileEntryRow) PinTarget() string {
	if e.Version != "" {
		return e.Version
	}
	return e.LatestVersion
}

func (e ProfileEntryRow) CanFloat() bool { return e.Mode != "latest" }

// PinFieldValue prefills the row's editable pin input: the version already
// pinned, or PinTarget as a starting guess when the row is not pinned yet.
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

// Label is the display name when the hub has one, and the raw subject
// otherwise — an email, a subject, or a group name the identity provider
// spells however it spells it.
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

// ProfilePermissions is what this identity may do here, so the screen can
// disable a control rather than offer one the api will refuse.
type ProfilePermissions struct {
	Curate  bool
	Share   bool
	Publish bool
	// Delete is the role check alone (owner only). Whether the profile is
	// ALSO clean enough to delete (no published revision) is a fact of the
	// profile, not the role, and Profile.CanDelete combines the two.
	Delete bool
}

// CurateDisabledReason is why the float and pin controls are disabled for a
// viewer whose role on this profile does not include curating it.
const CurateDisabledReason = "Your role on this profile may not change its entries."

// ShareDisabledReason is why the sharing form is disabled for anyone but the
// owner. MembershipRole.MayShare is owner-only by design — a maintainer who
// could re-share could widen an access decision the owner made — and this is
// the screen saying so rather than hiding the form.
const ShareDisabledReason = "Only this profile's owner may change who it is shared with: a " +
	"maintainer who could re-share it could widen an access decision the owner made."

// PublishDisabledReason is why the publish-revision control is disabled for a
// viewer whose role on this profile does not include publishing it.
const PublishDisabledReason = "Your role on this profile may not publish a revision."

// ProfileDeleteRoleReason is why the delete-profile control is disabled for
// a viewer who is not this profile's owner.
const ProfileDeleteRoleReason = "Only this profile's owner may delete it."

// ProfileDeleteHasRevisionsReason is why the delete-profile control is
// disabled even for an owner: a published revision is what a client may
// already have synced, and FR-034 forbids deleting one, so deleting the
// profile that holds it is refused rather than cascaded.
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

	// Role is legitimately empty: a profile with organisation visibility is
	// readable by everyone and most readers hold no membership.
	Role        string
	Permissions ProfilePermissions

	UnpublishedChanges bool

	Entries   []ProfileEntryRow
	Members   []ProfileMemberRow
	Targets   []ProfileTargetRow
	Revisions []ProfileRevisionRow

	// AddOptions is every catalog package this profile does not already hold,
	// for the "Add package" control. Empty for a viewer who may not curate, and
	// whenever the catalog cannot be read.
	AddOptions []ProfileAddOption

	GovernanceState
	// Missing is a slug in the URL that names nothing this identity may read —
	// an unreadable profile answers exactly as a missing one, so a caller cannot
	// tell a private profile from one that does not exist.
	Missing bool
	Notice  *Notice
	// Refusal carries the api's own sentence for a curation request it
	// understood but refused (a name already shared twice, a range on an entry
	// that holds no versions in it). It renders inline on the same request.
	Refusal string

	// Diff is "Show diff": present exactly when the URL carries a revision
	// query parameter, the same plain-round-trip idiom the audit screen uses
	// for its own detail panel.
	Diff *RevisionDiffPanel
}

func (p Profile) VisibilityLabel() string { return visibilityLabels[p.Visibility] }

func (p Profile) DefaultPolicyLabel() string { return DefaultPolicyLabel(p.DefaultPolicy) }

// DefaultPolicyLabel is the free function Profile.DefaultPolicyLabel wraps,
// so the revision diff panel can label a from/to pair without a Profile to
// hang it off of.
func DefaultPolicyLabel(policy string) string {
	for _, option := range ProfileDefaultPolicies {
		if option.Value == policy {
			return option.Label
		}
	}
	return policy
}

func (p Profile) GateLabel() string { return GateLabel(p.Gate) }

// GateLabel is the free function Profile.GateLabel wraps, for the same
// reason DefaultPolicyLabel is.
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

// SkillEntries and PluginEntries split Entries by kind, so the screen can
// name and empty-state skills and plugins separately instead of one
// undifferentiated "Packages" list.
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

// CanDelete combines the role check the api reported with the one business
// fact that also has to hold: a profile with a published revision refuses
// to delete regardless of role (see ProfileDeleteHasRevisionsReason).
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

// SkillAddOptions and PluginAddOptions split AddOptions by kind, so the Add
// skill and Add plugin controls each offer only their own kind rather than
// one list a person has to read the kind column of.
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
