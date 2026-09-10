package contract

import "time"

// Nothing in this file is a rendered sentence or duration: ages cross the
// wire as seconds and instants.

type ScannerSummary struct {
	PeriodDays int `json:"periodDays" doc:"The window VersionsScanned and MedianSeconds were computed over." example:"30"`

	// VersionsScanned counts VERSIONS and not scan rows: a version rescanned
	// under a new rule pack has two scans and is one version.
	VersionsScanned int `json:"versionsScanned" doc:"Distinct versions that reached a verdict inside the period." example:"1284"`

	// Quarantined counts LATEST VISIBLE flagged versions, not history.
	Quarantined int `json:"quarantined" doc:"Packages whose latest visible version is flagged, and so awaits a decision." example:"2"`

	OverridesActive int        `json:"overridesActive" doc:"Accepted findings whose override has not expired." example:"1"`
	NearestExpiry   *time.Time `json:"nearestOverrideExpiry,omitempty" doc:"When the first active override lapses. Absent when none is active."`

	// MedianSeconds is absent, not zero, when no scan finished in the period.
	MedianSeconds *float64 `json:"medianScanSeconds,omitempty" doc:"Median seconds from a scan starting to its verdict, over the period." example:"18"`
}

type FindingSummary struct {
	ID       string `json:"id" format:"uuid" doc:"The finding's identifier, as the detail and decision paths take it."`
	RuleID   string `json:"ruleId" doc:"Stable rule identifier (FR-024)." example:"SH-NET-002"`
	Severity string `json:"severity" enum:"low,medium,high" example:"high"`
	State    string `json:"state" enum:"open,approved,rejected" example:"open"`
	Title    string `json:"title" example:"Undeclared network egress"`

	PackageID string `json:"packageId" doc:"namespace/name of the package the subject version belongs to." example:"community/slack-digest"`
	Version   string `json:"version" example:"0.5.1"`
	// Verdict is the SUBJECT VERSION's verdict, not the finding's state: a
	// finding can be approved while its version stays flagged.
	Verdict string `json:"verdict" enum:"scanning,clean,flagged,rejected" example:"flagged"`

	RaisedAt time.Time `json:"raisedAt" doc:"When the scan that raised this finding recorded it."`

	EvidencePath string `json:"evidencePath,omitempty" doc:"The PRIMARY location's path. Rendered escaped, always: it is bundle content (FR-055)." example:"scripts/digest.sh"`
	EvidenceLine *int   `json:"evidenceLine,omitempty" doc:"Absent when the finding names a file without a line." example:"41"`
}

type FindingsPage struct {
	Findings []FindingSummary `json:"findings" doc:"The requested page, already sorted: highest severity first, then newest."`
	Total    int              `json:"total" doc:"Findings matching every filter, across all pages." example:"4"`
	Page     int              `json:"page" doc:"The page actually returned, which is clamped into range." example:"1"`
	PageSize int              `json:"pageSize" example:"20"`
}

type FindingDetail struct {
	ID        string    `json:"id" format:"uuid"`
	RuleID    string    `json:"ruleId" example:"SH-NET-002"`
	Severity  string    `json:"severity" enum:"low,medium,high" example:"high"`
	State     string    `json:"state" enum:"open,approved,rejected" example:"open"`
	Title     string    `json:"title" example:"Undeclared network egress"`
	PackageID string    `json:"packageId" example:"community/slack-digest"`
	Version   string    `json:"version" example:"0.5.1"`
	Verdict   string    `json:"verdict" enum:"scanning,clean,flagged,rejected" example:"flagged"`
	RaisedAt  time.Time `json:"raisedAt"`

	Detail string `json:"detail,omitempty" doc:"Why this was raised, in prose."`

	// Evidence is EVERY location, not one: a finding legitimately has
	// several, and the primary one is the row whose role says so.
	Evidence []FindingEvidence `json:"evidence" doc:"Every location this finding points at, cause first. Rendered escaped, always (FR-055)."`

	// Checks includes passes: failures-only can't be told from nothing-ran.
	Checks []FindingCheck `json:"checks" doc:"Every check the scan ran and its result, including the ones that passed (FR-025)."`

	Scan     FindingScan      `json:"scan"`
	Override *FindingOverride `json:"override,omitempty" doc:"Present only when a reviewer has accepted this finding."`
}

type FindingEvidence struct {
	Path string `json:"path" example:"scripts/digest.sh"`
	Line *int   `json:"line,omitempty" doc:"Absent when the location names a file without a line." example:"41"`
	// Quote is attacker-controlled bundle content, quoted verbatim. Every
	// consumer must render it escaped.
	Quote string `json:"quote,omitempty"`
	Role  string `json:"role" enum:"primary,supporting" doc:"primary is the location that caused the finding; the rest show its consequences." example:"primary"`
}

type FindingCheck struct {
	CheckID   string `json:"checkId" example:"network-allowlist"`
	Label     string `json:"label" doc:"The check's own label, as the scan recorded it. A screen that mapped check ids to labels itself would stop naming a check added after it shipped." example:"Network allowlist"`
	Result    string `json:"result" enum:"pass,fail,warn" example:"fail"`
	WarnCount int    `json:"warnCount" doc:"How many warnings this check raised. Zero unless the result is warn." example:"2"`
}

type FindingScan struct {
	PackVersion string     `json:"packVersion" doc:"The rule-pack version this scan ran. What makes 'rescan needed' a comparison rather than a guess." example:"1.4.0"`
	StartedAt   time.Time  `json:"startedAt"`
	FinishedAt  *time.Time `json:"finishedAt,omitempty" doc:"Absent while the scan is still in flight."`
	Verdict     string     `json:"verdict" enum:"scanning,clean,flagged,rejected" example:"flagged"`
	TimedOut    bool       `json:"timedOut" doc:"The scan exceeded its budget. Its verdict is not a clean bill of health (FR-031)."`
}

type FindingOverride struct {
	Reviewer  string     `json:"reviewer" doc:"The reviewer's email, or their subject when the identity carries no email." example:"security-lead@example.dev"`
	Note      string     `json:"note,omitempty" example:"Network call is to our own registry"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty" doc:"When this acceptance lapses."`
	DecidedAt time.Time  `json:"decidedAt"`
}

type FindingApproval struct {
	Note          string `json:"note" minLength:"1" maxLength:"2000" doc:"Why this risk is accepted. Required: an override with no stated reason is an unexplained exception, and FR-028 asks for a recorded note." example:"Network call is to our own registry"`
	ExpiresInDays int    `json:"expiresInDays,omitempty" minimum:"1" maximum:"365" doc:"Days until the acceptance lapses. Defaults to 30 when omitted; never unlimited." example:"12"`
}

// FindingRejection carries no expiry: rejection is terminal.
type FindingRejection struct {
	Note string `json:"note,omitempty" maxLength:"2000" doc:"Optional reason, recorded in the audit row." example:"Publisher is shipping a fix in 0.5.2"`
}

type FindingDecision struct {
	ID    string `json:"id" format:"uuid"`
	State string `json:"state" enum:"open,approved,rejected" example:"approved"`
	// Verdict is the SUBJECT VERSION's verdict after the decision: an accept
	// leaves it flagged (the override is what lets it through, subject to
	// the gate), and a reject sets it rejected.
	Verdict   string     `json:"verdict" enum:"scanning,clean,flagged,rejected" example:"flagged"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty" doc:"When the acceptance lapses. Absent on a rejection, which does not."`
}

type AuditEntry struct {
	ID         string    `json:"id" format:"uuid"`
	OccurredAt time.Time `json:"occurredAt"`
	Actor      string    `json:"actor" doc:"The email or subject of the person, or the name of the system role, that acted." example:"kwiatrzyk@example.com"`
	ActorKind  string    `json:"actorKind" enum:"identity,system" doc:"system is a worker with no person behind it, which a screen must not attribute to anybody." example:"identity"`
	Kind       string    `json:"kind" enum:"fetch,scan,approve,profile,share,sync,login,policy,role,category,secret" example:"approve"`
	Text       string    `json:"text" doc:"The human-readable record of what happened. It quotes package and profile names, so it is rendered escaped (FR-055)." example:"override granted for community/aws-cost-explainer@2.0.0"`
	Source     string    `json:"source,omitempty" doc:"web, cli / <host> or system." example:"web"`
}

type AuditPage struct {
	Entries  []AuditEntry `json:"entries" doc:"The requested page, most recent first."`
	Total    int          `json:"total" doc:"Rows in the log. The export returns all of them (FR-051)." example:"512"`
	Page     int          `json:"page" example:"1"`
	PageSize int          `json:"pageSize" example:"50"`
}

// AuditExportTrailer: a streamed response can't fail after headers are
// sent, so a consumer reaching end-of-stream without this line has an
// incomplete export.
type AuditExportTrailer struct {
	Complete bool `json:"complete" doc:"Always true. Its ABSENCE is the signal: a stream that ends without this line was truncated."`
	Rows     int  `json:"rows" doc:"How many audit rows precede this line." example:"512"`
}

// Badges is the shell's counts, scoped to the caller.
type Badges struct {
	Packages int `json:"packages" doc:"Packages visible in the catalog — the same figure the catalog's own total reports with no filters applied." example:"10"`
	Profiles int `json:"profiles" doc:"Profiles this identity may read, and no others (FR-044)." example:"4"`
	// OpenFindings is global rather than per-identity because packages are
	// org-visible: there is no per-caller scoping to apply.
	OpenFindings int `json:"openFindings" doc:"Findings awaiting a decision." example:"4"`
}
