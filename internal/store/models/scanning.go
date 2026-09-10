package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Scan is one run of the check registry against one version at one
// rule-pack version. `unique (version_id, pack_version)` is the idempotency
// key.
type Scan struct {
	bun.BaseModel `bun:"table:scan,alias:scn"`

	ID          uuid.UUID  `bun:"id,pk,type:uuid,notnull"`
	VersionID   uuid.UUID  `bun:"version_id,type:uuid,notnull,unique:scan_version_pack_version"`
	PackVersion string     `bun:"pack_version,type:text,notnull,unique:scan_version_pack_version"`
	StartedAt   time.Time  `bun:"started_at,type:timestamptz,notnull,default:now()"`
	FinishedAt  *time.Time `bun:"finished_at,type:timestamptz,nullzero"`
	Verdict     Verdict    `bun:"verdict,type:verdict,notnull"`
	// TimedOut records a scan that exceeded its budget, never silently
	// reported as clean.
	TimedOut  bool      `bun:"timed_out,type:boolean,notnull,default:false"`
	UpdatedAt time.Time `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Version  *Version     `bun:"rel:belongs-to,join:version_id=id"`
	Checks   []*ScanCheck `bun:"rel:has-many,join:id=scan_id"`
	Findings []*Finding   `bun:"rel:has-many,join:id=scan_id"`
}

// ScanCheck is one row per registered check per scan, including passes.
type ScanCheck struct {
	bun.BaseModel `bun:"table:scan_check,alias:schk"`

	ScanID    uuid.UUID   `bun:"scan_id,pk,type:uuid,notnull"`
	CheckID   string      `bun:"check_id,pk,type:text,notnull"`
	Label     string      `bun:"label,type:text,notnull"`
	Result    CheckResult `bun:"result,type:check_result,notnull"`
	WarnCount int32       `bun:"warn_count,type:integer,notnull,default:0"`
	CreatedAt time.Time   `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Scan *Scan `bun:"rel:belongs-to,join:scan_id=id"`
}

// Finding is one problem a check raised. The evidence triple below is the
// PRIMARY location only, denormalised so the findings list renders without a
// join; the full set lives in FindingEvidence.
type Finding struct {
	bun.BaseModel `bun:"table:finding,alias:fnd"`

	ID        uuid.UUID       `bun:"id,pk,type:uuid,notnull"`
	ScanID    uuid.UUID       `bun:"scan_id,type:uuid,notnull"`
	VersionID uuid.UUID       `bun:"version_id,type:uuid,notnull"`
	RuleID    string          `bun:"rule_id,type:text,notnull"`
	Severity  FindingSeverity `bun:"severity,type:finding_severity,notnull"`
	Title     string          `bun:"title,type:text,notnull"`
	Detail    string          `bun:"detail,type:text,nullzero"`
	// EvidenceQuote is attacker-controlled bundle content, quoted verbatim
	// and always rendered escaped.
	EvidencePath  string       `bun:"evidence_path,type:text,nullzero"`
	EvidenceLine  *int32       `bun:"evidence_line,type:integer,nullzero"`
	EvidenceQuote string       `bun:"evidence_quote,type:text,nullzero"`
	State         FindingState `bun:"state,type:finding_state,notnull"`
	CreatedAt     time.Time    `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt     time.Time    `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Scan     *Scan              `bun:"rel:belongs-to,join:scan_id=id"`
	Version  *Version           `bun:"rel:belongs-to,join:version_id=id"`
	Override *Override          `bun:"rel:has-one,join:id=finding_id"`
	Evidence []*FindingEvidence `bun:"rel:has-many,join:id=finding_id"`
}

// FindingEvidence is one location a finding points at; a finding can have
// several.
type FindingEvidence struct {
	bun.BaseModel `bun:"table:finding_evidence,alias:fev"`

	ID        uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	FindingID uuid.UUID `bun:"finding_id,type:uuid,notnull"`
	Path      string    `bun:"path,type:text,notnull"`
	// Line is nullable: a finding can name a file without naming a line.
	Line *int32 `bun:"line,type:integer,nullzero"`
	// Quote is attacker-controlled bundle content, quoted verbatim and
	// always rendered escaped.
	Quote     string       `bun:"quote,type:text,nullzero"`
	Role      EvidenceRole `bun:"role,type:evidence_role,notnull"`
	CreatedAt time.Time    `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Finding *Finding `bun:"rel:belongs-to,join:finding_id=id"`
}

// Override is a reviewer accepting a finding.
type Override struct {
	bun.BaseModel `bun:"table:override,alias:ovr"`

	FindingID          uuid.UUID  `bun:"finding_id,pk,type:uuid,notnull"`
	ReviewerIdentityID uuid.UUID  `bun:"reviewer_identity_id,type:uuid,notnull"`
	Note               string     `bun:"note,type:text,nullzero"`
	ExpiresAt          *time.Time `bun:"expires_at,type:timestamptz,nullzero"`
	CreatedAt          time.Time  `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Finding  *Finding  `bun:"rel:belongs-to,join:finding_id=id"`
	Reviewer *Identity `bun:"rel:belongs-to,join:reviewer_identity_id=id"`
}
