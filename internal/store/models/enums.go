package models

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

type Enum interface {
	Valid() bool
}

// Postgres enum type names. These are the names the `type:` option of each bun
// struct tag must carry, so Atlas diffs the column against the enum type rather
// than against text.
const (
	PGPackageKind       = "package_kind"
	PGPackageVisibility = "package_visibility"
	PGDistTag           = "dist_tag"
	PGVerdict           = "verdict"
	PGComponentKind     = "component_kind"
	PGCapabilitySource  = "capability_source"
	PGCapabilityLevel   = "capability_level"
	PGSignatureKind     = "signature_kind"
	PGSignatureResult   = "signature_result"
	PGCheckResult       = "check_result"
	PGFindingSeverity   = "finding_severity"
	PGFindingState      = "finding_state"
	PGProfileVisibility = "profile_visibility"
	PGVersionPolicy     = "version_policy"
	PGEntryMode         = "entry_mode"
	PGMembershipRole    = "membership_role"
	PGSubjectKind       = "subject_kind"
	PGSyncTargetKind    = "sync_target_kind"
	PGOrgRole           = "org_role"
	PGDeviceAuthState   = "device_auth_state"
	PGScanGate          = "scan_gate"
	PGActorKind         = "actor_kind"
	PGAuditKind         = "audit_kind"
	PGOutboxState       = "outbox_state"
	PGEvidenceRole      = "evidence_role"
	PGFetchSourceKind   = "fetch_source_kind"
	PGFetchOutcome      = "fetch_outcome"
)

// enumTypes maps each Postgres enum type to its value set in declaration order.
// Valid() and EnumDDL both read this map, so the values Postgres accepts and the
// values Go accepts cannot drift apart.
var enumTypes = map[string][]string{
	PGPackageKind:       {"plugin", "skill"},
	PGPackageVisibility: {"organisation", "team", "private"},
	PGDistTag:           {"latest", "archived", "none"},
	PGVerdict:           {"scanning", "clean", "flagged", "rejected"},
	PGComponentKind:     {"skill", "mcp", "ext"},
	PGCapabilitySource:  {"inferred", "expected"},
	PGCapabilityLevel:   {"scoped", "allowlisted", "review"},
	PGSignatureKind:     {"none", "cosign-bundle"},
	PGSignatureResult:   {"verified", "invalid", "error"},
	PGCheckResult:       {"pass", "fail", "warn"},
	PGFindingSeverity:   {"low", "medium", "high"},
	PGFindingState:      {"open", "approved", "rejected"},
	PGProfileVisibility: {"organisation", "shared", "private"},
	PGVersionPolicy:     {"floating-latest", "pinned", "range"},
	PGEntryMode:         {"latest", "pinned", "range"},
	PGMembershipRole:    {"owner", "maintainer", "reviewer", "consumer"},
	PGSubjectKind:       {"user", "group"},
	PGSyncTargetKind:    {"claude-code", "codex"},
	PGOrgRole:           {"catalog-admin", "scanner-reviewer", "profile-consumer", "read-only"},
	PGDeviceAuthState:   {"pending", "approved", "consumed", "expired", "denied"},
	PGScanGate:          {"block", "approval", "warn-with-override"},
	PGActorKind:         {"identity", "system"},
	PGAuditKind: {
		"fetch", "scan", "approve", "profile", "share", "sync", "login",
		// The four admin kinds are appended, never interleaved: the migration
		// that added them is `alter type ... add value`, which appends.
		"policy", "role", "category", "secret",
	},
	PGOutboxState:     {"pending", "delivered"},
	PGEvidenceRole:    {"primary", "supporting"},
	PGFetchSourceKind: {"upload", "git", "archive-url"},
	// fetch_outcome is one value per failure fetch/repourl/bundle can actually
	// tell apart; it deliberately excludes HTTP status codes and transport
	// causes, which belong in `detail`.
	PGFetchOutcome: {
		"ok", "invalid-ref", "blocked", "unreachable",
		"malformed", "too-large", "rejected-member", "extract-timeout",
	},
}

func inEnum(pgType, value string) bool {
	return slices.Contains(enumTypes[pgType], value)
}

// EnumTypes returns the Postgres enum types the models reference, mapped to their
// declared value sets.
func EnumTypes() map[string][]string {
	out := make(map[string][]string, len(enumTypes))
	for name, values := range enumTypes {
		out[name] = slices.Clone(values)
	}
	return out
}

// EnumDDL returns one `create type` statement per enum type, sorted by name.
// Bun emits no DDL for enum types, so the migration layer prepends these before
// the loader's `create table` output.
func EnumDDL() []string {
	names := make([]string, 0, len(enumTypes))
	for name := range enumTypes {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]string, 0, len(names))
	for _, name := range names {
		quoted := make([]string, 0, len(enumTypes[name]))
		for _, v := range enumTypes[name] {
			quoted = append(quoted, "'"+v+"'")
		}
		out = append(out, fmt.Sprintf("create type %s as enum (%s);", name, strings.Join(quoted, ", ")))
	}
	return out
}

// PackageKind distinguishes a plugin from a standalone skill.
type PackageKind string

const (
	PackageKindPlugin PackageKind = "plugin"
	PackageKindSkill  PackageKind = "skill"
)

func (v PackageKind) Valid() bool { return inEnum(PGPackageKind, string(v)) }

// PackageVisibility is who may see a package in the catalog.
type PackageVisibility string

const (
	PackageVisibilityOrganisation PackageVisibility = "organisation"
	PackageVisibilityTeam         PackageVisibility = "team"
	PackageVisibilityPrivate      PackageVisibility = "private"
)

func (v PackageVisibility) Valid() bool { return inEnum(PGPackageVisibility, string(v)) }

// DistTag is the distribution channel a version occupies.
type DistTag string

const (
	DistTagLatest   DistTag = "latest"
	DistTagArchived DistTag = "archived"
	DistTagNone     DistTag = "none"
)

func (v DistTag) Valid() bool { return inEnum(PGDistTag, string(v)) }

// Verdict is the scan outcome carried by both version and scan.
type Verdict string

const (
	VerdictScanning Verdict = "scanning"
	VerdictClean    Verdict = "clean"
	VerdictFlagged  Verdict = "flagged"
	VerdictRejected Verdict = "rejected"
)

func (v Verdict) Valid() bool { return inEnum(PGVerdict, string(v)) }

// ComponentKind is derived from the bundle's file tree, not from the manifest.
type ComponentKind string

const (
	ComponentKindSkill ComponentKind = "skill"
	ComponentKindMCP   ComponentKind = "mcp"
	ComponentKindExt   ComponentKind = "ext"
)

func (v ComponentKind) Valid() bool { return inEnum(PGComponentKind, string(v)) }

// CapabilitySource: `inferred` is what the scanner found in the bytes,
// `expected` is what the publisher declared.
type CapabilitySource string

const (
	CapabilitySourceInferred CapabilitySource = "inferred"
	CapabilitySourceExpected CapabilitySource = "expected"
)

func (v CapabilitySource) Valid() bool { return inEnum(PGCapabilitySource, string(v)) }

// CapabilityLevel is how much trust a capability demands.
type CapabilityLevel string

const (
	CapabilityLevelScoped      CapabilityLevel = "scoped"
	CapabilityLevelAllowlisted CapabilityLevel = "allowlisted"
	CapabilityLevelReview      CapabilityLevel = "review"
)

func (v CapabilityLevel) Valid() bool { return inEnum(PGCapabilityLevel, string(v)) }

// SignatureKind is the signature format. `cosign-bundle` is reserved for when
// sigstore-go lands.
type SignatureKind string

const (
	SignatureKindNone         SignatureKind = "none"
	SignatureKindCosignBundle SignatureKind = "cosign-bundle"
)

func (v SignatureKind) Valid() bool { return inEnum(PGSignatureKind, string(v)) }

// SignatureResult is the outcome of a verification attempt. Every value is
// provisional: nothing writes this column until sigstore-go lands, and null
// means "never attempted".
type SignatureResult string

const (
	SignatureResultVerified SignatureResult = "verified"
	SignatureResultInvalid  SignatureResult = "invalid"
	SignatureResultError    SignatureResult = "error"
)

func (v SignatureResult) Valid() bool { return inEnum(PGSignatureResult, string(v)) }

type CheckResult string

const (
	CheckResultPass CheckResult = "pass"
	CheckResultFail CheckResult = "fail"
	CheckResultWarn CheckResult = "warn"
)

func (v CheckResult) Valid() bool { return inEnum(PGCheckResult, string(v)) }

type FindingSeverity string

const (
	FindingSeverityLow    FindingSeverity = "low"
	FindingSeverityMedium FindingSeverity = "medium"
	FindingSeverityHigh   FindingSeverity = "high"
)

func (v FindingSeverity) Valid() bool { return inEnum(PGFindingSeverity, string(v)) }

type FindingState string

const (
	FindingStateOpen     FindingState = "open"
	FindingStateApproved FindingState = "approved"
	FindingStateRejected FindingState = "rejected"
)

func (v FindingState) Valid() bool { return inEnum(PGFindingState, string(v)) }

// ProfileVisibility is who may see a profile. Deliberately a different value set
// from PackageVisibility: a profile is shared, not owned by a team.
type ProfileVisibility string

const (
	ProfileVisibilityOrganisation ProfileVisibility = "organisation"
	ProfileVisibilityShared       ProfileVisibility = "shared"
	ProfileVisibilityPrivate      ProfileVisibility = "private"
)

func (v ProfileVisibility) Valid() bool { return inEnum(PGProfileVisibility, string(v)) }

// VersionPolicy is the organisation-wide or profile-wide default for how entries
// track new versions.
type VersionPolicy string

const (
	VersionPolicyFloatingLatest VersionPolicy = "floating-latest"
	VersionPolicyPinned         VersionPolicy = "pinned"
	VersionPolicyRange          VersionPolicy = "range"
)

func (v VersionPolicy) Valid() bool { return inEnum(PGVersionPolicy, string(v)) }

type EntryMode string

const (
	EntryModeLatest EntryMode = "latest"
	EntryModePinned EntryMode = "pinned"
	EntryModeRange  EntryMode = "range"
)

func (v EntryMode) Valid() bool { return inEnum(PGEntryMode, string(v)) }

type MembershipRole string

const (
	MembershipRoleOwner      MembershipRole = "owner"
	MembershipRoleMaintainer MembershipRole = "maintainer"
	MembershipRoleReviewer   MembershipRole = "reviewer"
	MembershipRoleConsumer   MembershipRole = "consumer"
)

func (v MembershipRole) Valid() bool { return inEnum(PGMembershipRole, string(v)) }

// What each membership role may do to the profile it is held on.
//
// These live beside the enum, not in internal/api, because several packages
// need the same answer and none may import another — a hand-written copy per
// package is how they'd silently drift apart.
//
// The empty role is legitimately common and grants nothing (an
// organisation-visibility profile is readable by almost everyone, and few
// readers hold a membership), so every method below fails closed on it.

// MayCurate reports whether this role may change what the profile holds — its
// entries and its sync targets.
func (v MembershipRole) MayCurate() bool {
	return v == MembershipRoleOwner || v == MembershipRoleMaintainer
}

// MayShare reports whether this role may change who the profile is shared with.
//
// Owner only, and deliberately narrower than MayCurate: curating what a profile
// contains and deciding who can see it are different powers, and a maintainer
// who could re-share would be able to widen an access decision the owner made.
func (v MembershipRole) MayShare() bool { return v == MembershipRoleOwner }

// MayPublish reports whether this role may publish a revision.
//
// A revision is what reaches machines, so this is the sharpest of the three. A
// consumer may not — they consume what somebody else published — and neither may
// a reviewer, whose role is to look at a profile rather than to ship it.
func (v MembershipRole) MayPublish() bool {
	return v == MembershipRoleOwner || v == MembershipRoleMaintainer
}

// SubjectKind is whether a membership names a person or a mapped group.
type SubjectKind string

const (
	SubjectKindUser  SubjectKind = "user"
	SubjectKindGroup SubjectKind = "group"
)

func (v SubjectKind) Valid() bool { return inEnum(PGSubjectKind, string(v)) }

// SyncTargetKind is a client-side directory convention a profile can be written
// to. Adding a value is a migration rather than an API-level allowlist, since a
// dead enum value can still be written directly and then nothing can render it.
type SyncTargetKind string

const (
	SyncTargetKindClaudeCode SyncTargetKind = "claude-code"
	SyncTargetKindCodex      SyncTargetKind = "codex"
)

func (v SyncTargetKind) Valid() bool { return inEnum(PGSyncTargetKind, string(v)) }

type OrgRole string

const (
	OrgRoleCatalogAdmin    OrgRole = "catalog-admin"
	OrgRoleScannerReviewer OrgRole = "scanner-reviewer"
	OrgRoleProfileConsumer OrgRole = "profile-consumer"
	OrgRoleReadOnly        OrgRole = "read-only"
)

func (v OrgRole) Valid() bool { return inEnum(PGOrgRole, string(v)) }

// DeviceAuthState is the device-flow lifecycle. Single use comes from the
// pending -> approved -> consumed transition inside one transaction, which is
// why there is no boolean here.
type DeviceAuthState string

const (
	DeviceAuthStatePending  DeviceAuthState = "pending"
	DeviceAuthStateApproved DeviceAuthState = "approved"
	DeviceAuthStateConsumed DeviceAuthState = "consumed"
	DeviceAuthStateExpired  DeviceAuthState = "expired"
	DeviceAuthStateDenied   DeviceAuthState = "denied"
)

func (v DeviceAuthState) Valid() bool { return inEnum(PGDeviceAuthState, string(v)) }

// ScanGate is what a non-clean verdict does to a publish.
type ScanGate string

const (
	ScanGateBlock            ScanGate = "block"
	ScanGateApproval         ScanGate = "approval"
	ScanGateWarnWithOverride ScanGate = "warn-with-override"
)

func (v ScanGate) Valid() bool { return inEnum(PGScanGate, string(v)) }

// ActorKind separates a person from the system in the audit log.
type ActorKind string

const (
	ActorKindIdentity ActorKind = "identity"
	ActorKindSystem   ActorKind = "system"
)

func (v ActorKind) Valid() bool { return inEnum(PGActorKind, string(v)) }

// AuditKind is the class of audited action.
//
// The last four are the Organization screen's mutations, kept as four values
// rather than one `admin` bucket because the audit screen filters by kind and
// "who changed the scan gate" is not the same question as "who rotated the
// identity-provider secret".
type AuditKind string

const (
	AuditKindFetch   AuditKind = "fetch"
	AuditKindScan    AuditKind = "scan"
	AuditKindApprove AuditKind = "approve"
	AuditKindProfile AuditKind = "profile"
	AuditKindShare   AuditKind = "share"
	AuditKindSync    AuditKind = "sync"
	AuditKindLogin   AuditKind = "login"
	// AuditKindPolicy covers org_policy as a whole: the scan gate, the default
	// version policy, and the four booleans beside them.
	AuditKindPolicy AuditKind = "policy"
	// AuditKindRole is the group->role map, which can grant catalog-admin.
	AuditKindRole AuditKind = "role"
	// AuditKindCategory is the admin-curated category vocabulary.
	AuditKindCategory AuditKind = "category"
	// AuditKindSecret is identity-provider credential rotation. The credential
	// itself never reaches a row here; the fact that it moved does.
	AuditKindSecret AuditKind = "secret"
)

func (v AuditKind) Valid() bool { return inEnum(PGAuditKind, string(v)) }

type OutboxState string

const (
	OutboxStatePending   OutboxState = "pending"
	OutboxStateDelivered OutboxState = "delivered"
)

func (v OutboxState) Valid() bool { return inEnum(PGOutboxState, string(v)) }

// EvidenceRole separates the location that caused a finding from the ones that
// show its consequences, since a single location per finding can't render a
// finding whose cause and effects are on different lines.
type EvidenceRole string

const (
	EvidenceRolePrimary    EvidenceRole = "primary"
	EvidenceRoleSupporting EvidenceRole = "supporting"
)

func (v EvidenceRole) Valid() bool { return inEnum(PGEvidenceRole, string(v)) }

// FetchSourceKind mirrors fetch.SourceKind. It is a copy rather than an import:
// internal/store/models is loaded by the Atlas provider and must stay free of
// the fetch tree, and internal/fetch must not learn about the database.
type FetchSourceKind string

const (
	FetchSourceUpload     FetchSourceKind = "upload"
	FetchSourceGit        FetchSourceKind = "git"
	FetchSourceArchiveURL FetchSourceKind = "archive-url"
)

func (v FetchSourceKind) Valid() bool { return inEnum(PGFetchSourceKind, string(v)) }

// FetchOutcome is how one fetch attempt ended, mapped one-to-one to its cause
// so nothing has to be recovered by parsing `detail`:
//
//	ok               a Tree was produced
//	invalid-ref      repourl.ErrInvalid or fetch.ErrNoSource — nothing was dialled
//	blocked          fetch.ErrBlocked — the outbound policy refused the address
//	unreachable      any other failure out of fetch.Client.Do
//	malformed        bundle.ErrMalformed
//	too-large        bundle.ErrTooLarge
//	rejected-member  bundle.ErrRejectedMember
//	extract-timeout  bundle.ErrTimeout
//
// A fetch-side timeout is `unreachable`, not `extract-timeout`: the http
// client's deadline is indistinguishable from a dead host at this layer.
type FetchOutcome string

const (
	FetchOutcomeOK             FetchOutcome = "ok"
	FetchOutcomeInvalidRef     FetchOutcome = "invalid-ref"
	FetchOutcomeBlocked        FetchOutcome = "blocked"
	FetchOutcomeUnreachable    FetchOutcome = "unreachable"
	FetchOutcomeMalformed      FetchOutcome = "malformed"
	FetchOutcomeTooLarge       FetchOutcome = "too-large"
	FetchOutcomeRejectedMember FetchOutcome = "rejected-member"
	FetchOutcomeExtractTimeout FetchOutcome = "extract-timeout"
)

func (v FetchOutcome) Valid() bool { return inEnum(PGFetchOutcome, string(v)) }
