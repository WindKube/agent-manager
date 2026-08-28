package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Scan is one run of the check registry against one version at one rule-pack
// version. `unique (version_id, pack_version)` is the idempotency key from R5: a
// redelivered scan job for the same version at the same pack version is a no-op,
// and "rescan needed" is a comparison rather than a guess.
type Scan struct {
	bun.BaseModel `bun:"table:scan,alias:scn"`

	ID          uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	VersionID   uuid.UUID `bun:"version_id,type:uuid,notnull,unique:scan_version_pack_version"`
	PackVersion string    `bun:"pack_version,type:text,notnull,unique:scan_version_pack_version"`
	// StartedAt is the row's creation instant; FinishedAt null means in flight,
	// which is what the median-duration stat reads.
	StartedAt  time.Time  `bun:"started_at,type:timestamptz,notnull,default:now()"`
	FinishedAt *time.Time `bun:"finished_at,type:timestamptz,nullzero"`
	Verdict    Verdict    `bun:"verdict,type:verdict,notnull"`
	// TimedOut records a scan that exceeded its budget. FR-031: a timeout is
	// recorded, never silently reported as clean.
	TimedOut  bool      `bun:"timed_out,type:boolean,notnull,default:false"`
	UpdatedAt time.Time `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Version  *Version     `bun:"rel:belongs-to,join:version_id=id"`
	Checks   []*ScanCheck `bun:"rel:has-many,join:id=scan_id"`
	Findings []*Finding   `bun:"rel:has-many,join:id=scan_id"`
}

// ScanCheck is one row per registered check per scan, including passes (FR-025).
// The runner writes it by iterating the registry, so a newly registered check
// appears in the checks-run matrix with no renderer change.
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

// Finding is one problem a check raised.
//
// The evidence triple below is the PRIMARY location only, kept denormalised so
// the findings list renders without a join. It is not the whole evidence: a
// finding legitimately has several locations, and those live in
// FindingEvidence — including a `primary` row that mirrors this triple.
type Finding struct {
	bun.BaseModel `bun:"table:finding,alias:fnd"`

	ID     uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	ScanID uuid.UUID `bun:"scan_id,type:uuid,notnull"`
	// VersionID is denormalised so the open-findings query needs no join. The
	// partial index that serves it lives on this column.
	VersionID uuid.UUID       `bun:"version_id,type:uuid,notnull"`
	RuleID    string          `bun:"rule_id,type:text,notnull"`
	Severity  FindingSeverity `bun:"severity,type:finding_severity,notnull"`
	Title     string          `bun:"title,type:text,notnull"`
	Detail    string          `bun:"detail,type:text,nullzero"`
	// EvidenceQuote is rendered escaped, always (FR-055). It is attacker-controlled
	// bundle content quoted verbatim.
	//
	// These three are the primary location, duplicated from the FindingEvidence
	// row whose role is `primary`. The duplication is what keeps the list view a
	// single-table read; `unique (finding_id) where role = 'primary'` is what keeps
	// "the" primary row well defined, so the two can never disagree about which
	// location this triple copies.
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

// FindingEvidence is one location a finding points at. A finding has several:
// SH-FS-007's cause is scripts/explain-costs.sh:9 while the writes it lets escape
// are on lines 28, 34 and 36, and a schema that holds one location per finding
// either drops the rest or formats them into a string.
//
// Formatting them into a string is the option this table exists to refuse. It
// would defeat Line — the number a reader needs to find the code — and it would
// turn FR-055's escaping requirement into a per-substring problem inside one
// text column, which is exactly the shape that gets escaped once and then
// concatenated wrong.
//
// The rows carry no explicit ordering column. Evidence is read as `order by
// role, path, line`, which is stable and is what the pane renders; a position
// column would be a second thing to keep right for no question anyone asks.
type FindingEvidence struct {
	bun.BaseModel `bun:"table:finding_evidence,alias:fev"`

	ID        uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	FindingID uuid.UUID `bun:"finding_id,type:uuid,notnull"`
	Path      string    `bun:"path,type:text,notnull"`
	// Line is nullable because a finding can name a file without naming a line —
	// which is also why the primary key is a uuid rather than
	// (finding_id, path, line): Postgres will not hold a null in one.
	Line *int32 `bun:"line,type:integer,nullzero"`
	// Quote is attacker-controlled bundle content, quoted verbatim, and is rendered
	// escaped always (FR-055).
	Quote     string       `bun:"quote,type:text,nullzero"`
	Role      EvidenceRole `bun:"role,type:evidence_role,notnull"`
	CreatedAt time.Time    `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Finding *Finding `bun:"rel:belongs-to,join:finding_id=id"`
}

// Override is a reviewer accepting a finding (FR-028). ExpiresAt is what the
// "overrides active / expires in N days" stat reads.
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
