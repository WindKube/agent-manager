package models

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Enum is implemented by every enumerated column type in this package.
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
	PGSyncTargetKind:    {"claude-code", "agents-md", "codex"},
	PGOrgRole:           {"catalog-admin", "scanner-reviewer", "profile-consumer", "read-only"},
	PGDeviceAuthState:   {"pending", "approved", "consumed", "expired", "denied"},
	PGScanGate:          {"block", "approval", "warn-with-override"},
	PGActorKind:         {"identity", "system"},
	PGAuditKind:         {"fetch", "scan", "approve", "profile", "share", "sync", "login"},
	PGOutboxState:       {"pending", "delivered"},
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

// DistTag is the distribution channel a version occupies. "pinned by N" in the
// design is derived from profile entries, never stored here.
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

// CapabilitySource is the R1 inversion: `inferred` is what the scanner found in
// the bytes, `expected` is what the publisher declared.
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
// sigstore-go lands (R9).
type SignatureKind string

const (
	SignatureKindNone         SignatureKind = "none"
	SignatureKindCosignBundle SignatureKind = "cosign-bundle"
)

func (v SignatureKind) Valid() bool { return inEnum(PGSignatureKind, string(v)) }

// SignatureResult is the outcome of a verification attempt. Every value is
// provisional: nothing writes this column until sigstore-go lands, and null
// means "never attempted" — which is what the UI must say (FR-048a).
type SignatureResult string

const (
	SignatureResultVerified SignatureResult = "verified"
	SignatureResultInvalid  SignatureResult = "invalid"
	SignatureResultError    SignatureResult = "error"
)

func (v SignatureResult) Valid() bool { return inEnum(PGSignatureResult, string(v)) }

// CheckResult is one scanner check's outcome.
type CheckResult string

const (
	CheckResultPass CheckResult = "pass"
	CheckResultFail CheckResult = "fail"
	CheckResultWarn CheckResult = "warn"
)

func (v CheckResult) Valid() bool { return inEnum(PGCheckResult, string(v)) }

// FindingSeverity ranks a finding.
type FindingSeverity string

const (
	FindingSeverityLow    FindingSeverity = "low"
	FindingSeverityMedium FindingSeverity = "medium"
	FindingSeverityHigh   FindingSeverity = "high"
)

func (v FindingSeverity) Valid() bool { return inEnum(PGFindingSeverity, string(v)) }

// FindingState is where a finding sits in review.
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

// EntryMode is one profile entry's tracking mode.
type EntryMode string

const (
	EntryModeLatest EntryMode = "latest"
	EntryModePinned EntryMode = "pinned"
	EntryModeRange  EntryMode = "range"
)

func (v EntryMode) Valid() bool { return inEnum(PGEntryMode, string(v)) }

// MembershipRole is a subject's role on one profile.
type MembershipRole string

const (
	MembershipRoleOwner      MembershipRole = "owner"
	MembershipRoleMaintainer MembershipRole = "maintainer"
	MembershipRoleReviewer   MembershipRole = "reviewer"
	MembershipRoleConsumer   MembershipRole = "consumer"
)

func (v MembershipRole) Valid() bool { return inEnum(PGMembershipRole, string(v)) }

// SubjectKind is whether a membership names a person or a mapped group.
type SubjectKind string

const (
	SubjectKindUser  SubjectKind = "user"
	SubjectKindGroup SubjectKind = "group"
)

func (v SubjectKind) Valid() bool { return inEnum(PGSubjectKind, string(v)) }

// SyncTargetKind is a client-side file format a profile can be written to.
type SyncTargetKind string

const (
	SyncTargetKindClaudeCode SyncTargetKind = "claude-code"
	SyncTargetKindAgentsMD   SyncTargetKind = "agents-md"
	SyncTargetKindCodex      SyncTargetKind = "codex"
)

func (v SyncTargetKind) Valid() bool { return inEnum(PGSyncTargetKind, string(v)) }

// OrgRole is the role an IdP group maps onto.
type OrgRole string

const (
	OrgRoleCatalogAdmin    OrgRole = "catalog-admin"
	OrgRoleScannerReviewer OrgRole = "scanner-reviewer"
	OrgRoleProfileConsumer OrgRole = "profile-consumer"
	OrgRoleReadOnly        OrgRole = "read-only"
)

func (v OrgRole) Valid() bool { return inEnum(PGOrgRole, string(v)) }

// DeviceAuthState is the device-flow lifecycle. Single use comes from the
// pending -> approved -> consumed transition inside one transaction (FR-042),
// which is why there is no boolean here.
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
type AuditKind string

const (
	AuditKindFetch   AuditKind = "fetch"
	AuditKindScan    AuditKind = "scan"
	AuditKindApprove AuditKind = "approve"
	AuditKindProfile AuditKind = "profile"
	AuditKindShare   AuditKind = "share"
	AuditKindSync    AuditKind = "sync"
	AuditKindLogin   AuditKind = "login"
)

func (v AuditKind) Valid() bool { return inEnum(PGAuditKind, string(v)) }

// OutboxState is the hand-off state of one outbox row.
type OutboxState string

const (
	OutboxStatePending   OutboxState = "pending"
	OutboxStateDelivered OutboxState = "delivered"
)

func (v OutboxState) Valid() bool { return inEnum(PGOutboxState, string(v)) }
