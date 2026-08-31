package contract

import "time"

// The two governance screens' surface: the scanner's headline figures, its
// findings and their adjudication (001 US4), the audit log and its export
// (001 FR-050..FR-052), and the shell's badge counts (003 FR-121).
//
// Like the catalog and the detail page these shapes are emitted rather than
// frozen: the machine-facing contract inventories none of these paths.
//
// Nothing here is a rendered sentence and nothing here is a rendered duration.
// The design's card reads "18s · fetch to verdict" and "expires in 12 days";
// what crosses the wire is a number of seconds and an instant, because which
// words express an age is a rendering choice and a relative string is wrong the
// moment it is cached.

// ScannerSummary is the four headline figures of 001 US4 scenario 1.
type ScannerSummary struct {
	// PeriodDays echoes the window the figures below were computed over, so the
	// screen's "last 30 days" is read from the answer rather than compiled into
	// the caption (FR-121).
	PeriodDays int `json:"periodDays" doc:"The window VersionsScanned and MedianSeconds were computed over." example:"30"`

	// VersionsScanned counts VERSIONS and not scan rows. A version rescanned
	// under a new rule pack has two scans and is one version, and the figure the
	// design labels "Versions scanned" must not double when the rule pack ships.
	VersionsScanned int `json:"versionsScanned" doc:"Distinct versions that reached a verdict inside the period." example:"1284"`

	// Quarantined is the count of LATEST VISIBLE versions carrying a flagged
	// verdict — what is presently blocked from adoption, not how many flagged
	// versions the history holds. A superseded flagged version is not
	// quarantining anything: nothing resolves to it.
	Quarantined int `json:"quarantined" doc:"Packages whose latest visible version is flagged, and so awaits a decision." example:"2"`

	OverridesActive int `json:"overridesActive" doc:"Accepted findings whose override has not expired." example:"1"`
	// NearestExpiry is the soonest of those expiries, absent when no override is
	// active. It is the instant, not the twelve days: see the package note.
	NearestExpiry *time.Time `json:"nearestOverrideExpiry,omitempty" doc:"When the first active override lapses. Absent when none is active."`

	// MedianSeconds is the median scan duration — the scan's own start to its own
	// verdict. Absent when no scan finished inside the period, which is a
	// different statement from zero and must render differently.
	MedianSeconds *float64 `json:"medianScanSeconds,omitempty" doc:"Median seconds from a scan starting to its verdict, over the period." example:"18"`
}

// FindingSummary is one row of the findings list. It carries the primary evidence
// location only; the whole of a finding's evidence is on FindingDetail.
type FindingSummary struct {
	ID       string `json:"id" format:"uuid" doc:"The finding's identifier, as the detail and decision paths take it."`
	RuleID   string `json:"ruleId" doc:"Stable rule identifier (FR-024)." example:"SH-NET-002"`
	Severity string `json:"severity" enum:"low,medium,high" example:"high"`
	State    string `json:"state" enum:"open,approved,rejected" example:"open"`
	Title    string `json:"title" example:"Undeclared network egress"`

	// PackageID and Version are the subject, in the two parts it is made of. The
	// design's `community/slack-digest@0.5.1` is those two joined, which is a
	// rendering decision this deliberately does not make.
	PackageID string `json:"packageId" doc:"namespace/name of the package the subject version belongs to." example:"community/slack-digest"`
	Version   string `json:"version" example:"0.5.1"`
	// Verdict is the SUBJECT VERSION's verdict, not the finding's state. A finding
	// can be approved while its version stays flagged — that is exactly what an
	// override is — and a screen that conflated the two would report a resolved
	// finding as a clean version.
	Verdict string `json:"verdict" enum:"scanning,clean,flagged,rejected" example:"flagged"`

	RaisedAt time.Time `json:"raisedAt" doc:"When the scan that raised this finding recorded it."`

	EvidencePath string `json:"evidencePath,omitempty" doc:"The PRIMARY location's path. Rendered escaped, always: it is bundle content (FR-055)." example:"scripts/digest.sh"`
	EvidenceLine *int   `json:"evidenceLine,omitempty" doc:"Absent when the finding names a file without a line." example:"41"`
}

// FindingsPage is one page of the findings list.
type FindingsPage struct {
	Findings []FindingSummary `json:"findings" doc:"The requested page, already sorted: highest severity first, then newest."`
	Total    int              `json:"total" doc:"Findings matching every filter, across all pages." example:"4"`
	Page     int              `json:"page" doc:"The page actually returned, which is clamped into range." example:"1"`
	PageSize int              `json:"pageSize" example:"20"`
}

// FindingDetail is the detail pane of 001 US4 scenario 2.
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

	// Detail is the prose explanation FR-024 requires. It is the rule pack's own
	// text, not a rendering of the rule id.
	Detail string `json:"detail,omitempty" doc:"Why this was raised, in prose."`

	// Evidence is EVERY location, not one. A finding legitimately has several —
	// SH-FS-007's cause is one line and the writes it lets escape are three
	// others — and the primary one is the row whose role says so.
	Evidence []FindingEvidence `json:"evidence" doc:"Every location this finding points at, cause first. Rendered escaped, always (FR-055)."`

	// Checks is every check that RAN, passes included (FR-025). A pane showing
	// only failures cannot be told apart from one where nothing else ran, which
	// is the distinction 001 US4 scenario 2 exists to preserve.
	Checks []FindingCheck `json:"checks" doc:"Every check the scan ran and its result, including the ones that passed (FR-025)."`

	Scan     FindingScan      `json:"scan"`
	Override *FindingOverride `json:"override,omitempty" doc:"Present only when a reviewer has accepted this finding."`
}

// FindingEvidence is one location a finding points at.
type FindingEvidence struct {
	Path string `json:"path" example:"scripts/digest.sh"`
	Line *int   `json:"line,omitempty" doc:"Absent when the location names a file without a line." example:"41"`
	// Quote is attacker-controlled bundle content, quoted verbatim. Every consumer
	// renders it escaped (FR-055); this field is why that requirement exists.
	Quote string `json:"quote,omitempty"`
	Role  string `json:"role" enum:"primary,supporting" doc:"primary is the location that caused the finding; the rest show its consequences." example:"primary"`
}

// FindingCheck is one check the scan ran.
type FindingCheck struct {
	CheckID string `json:"checkId" example:"network-allowlist"`
	Label   string `json:"label" doc:"The check's own label, as the scan recorded it. A screen that mapped check ids to labels itself would stop naming a check added after it shipped." example:"Network allowlist"`
	Result  string `json:"result" enum:"pass,fail,warn" example:"fail"`
	// WarnCount is the design's "2 warn". It is meaningful only for a warn result
	// and is zero for the others.
	WarnCount int `json:"warnCount" doc:"How many warnings this check raised. Zero unless the result is warn." example:"2"`
}

// FindingScan is the scan that raised the finding: which rule pack saw these
// bytes, and whether it got to finish.
type FindingScan struct {
	PackVersion string     `json:"packVersion" doc:"The rule-pack version this scan ran. What makes 'rescan needed' a comparison rather than a guess." example:"1.4.0"`
	StartedAt   time.Time  `json:"startedAt"`
	FinishedAt  *time.Time `json:"finishedAt,omitempty" doc:"Absent while the scan is still in flight."`
	Verdict     string     `json:"verdict" enum:"scanning,clean,flagged,rejected" example:"flagged"`
	// TimedOut is FR-031 surfaced: a scan that ran out of budget is recorded as
	// such and must never be presented as a clean pass.
	TimedOut bool `json:"timedOut" doc:"The scan exceeded its budget. Its verdict is not a clean bill of health (FR-031)."`
}

// FindingOverride is the recorded decision that accepted a finding (FR-028).
type FindingOverride struct {
	Reviewer  string     `json:"reviewer" doc:"The reviewer's email, or their subject when the identity carries no email." example:"security-lead@example.dev"`
	Note      string     `json:"note,omitempty" example:"Network call is to our own registry"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty" doc:"When this acceptance lapses."`
	DecidedAt time.Time  `json:"decidedAt"`
}

// FindingApproval is the body of accept: the note FR-028 requires recorded, and
// how long the acceptance lasts.
type FindingApproval struct {
	Note string `json:"note" minLength:"1" maxLength:"2000" doc:"Why this risk is accepted. Required: an override with no stated reason is an unexplained exception, and FR-028 asks for a recorded note." example:"Network call is to our own registry"`
	// ExpiresInDays is how long the acceptance lasts. Optional, and defaulted
	// rather than left open: an override with no expiry is a permanent exception,
	// and FR-028 asks for an expiry.
	ExpiresInDays int `json:"expiresInDays,omitempty" minimum:"1" maximum:"365" doc:"Days until the acceptance lapses. Defaults to 30 when omitted; never unlimited." example:"12"`
}

// FindingRejection is the body of reject. It carries no expiry, and that absence
// is the point: rejection is terminal, so there is no instant at which it lapses
// and no field in which to suggest there is one.
type FindingRejection struct {
	Note string `json:"note,omitempty" maxLength:"2000" doc:"Optional reason, recorded in the audit row." example:"Publisher is shipping a fix in 0.5.2"`
}

// FindingDecision is what an accept or a reject answers with: the finding's new
// state and the subject version's, which is the pair a screen has to redraw.
type FindingDecision struct {
	ID    string `json:"id" format:"uuid"`
	State string `json:"state" enum:"open,approved,rejected" example:"approved"`
	// Verdict is the SUBJECT VERSION's verdict after the decision. An accept
	// leaves it flagged — the override is what lets it through, subject to the
	// gate — and a reject sets it rejected, which no gate can let through
	// (FR-029). A screen that assumed accept meant clean would say so wrongly.
	Verdict   string     `json:"verdict" enum:"scanning,clean,flagged,rejected" example:"flagged"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty" doc:"When the acceptance lapses. Absent on a rejection, which does not."`
}

// AuditEntry is one row of the audit log (FR-050).
type AuditEntry struct {
	ID         string    `json:"id" format:"uuid"`
	OccurredAt time.Time `json:"occurredAt"`
	Actor      string    `json:"actor" doc:"The email or subject of the person, or the name of the system role, that acted." example:"kwiatrzyk@example.com"`
	ActorKind  string    `json:"actorKind" enum:"identity,system" doc:"system is a worker with no person behind it, which a screen must not attribute to anybody." example:"identity"`
	Kind       string    `json:"kind" enum:"fetch,scan,approve,profile,share,sync,login,policy,role,category,secret" example:"approve"`
	Text       string    `json:"text" doc:"The human-readable record of what happened. It quotes package and profile names, so it is rendered escaped (FR-055)." example:"override granted for community/aws-cost-explainer@2.0.0"`
	Source     string    `json:"source,omitempty" doc:"web, cli / <host> or system." example:"web"`
}

// AuditPage is one page of the audit log.
type AuditPage struct {
	Entries  []AuditEntry `json:"entries" doc:"The requested page, most recent first."`
	Total    int          `json:"total" doc:"Rows in the log. The export returns all of them (FR-051)." example:"512"`
	Page     int          `json:"page" example:"1"`
	PageSize int          `json:"pageSize" example:"50"`
}

// AuditExportTrailer is the last line of the export stream.
//
// It exists because a streamed response cannot fail: the status line and headers
// are written before the first row is read, so a statement that dies halfway
// through leaves a 200 that simply stops. Every line of the export is a complete
// JSON object, so truncation is invisible without a sentinel — this is it. A
// consumer that reaches end-of-stream without one has an incomplete export and
// must say so rather than file it.
type AuditExportTrailer struct {
	Complete bool `json:"complete" doc:"Always true. Its ABSENCE is the signal: a stream that ends without this line was truncated."`
	Rows     int  `json:"rows" doc:"How many audit rows precede this line." example:"512"`
}

// Badges is the shell's counts (FR-121), scoped to the caller.
//
// One operation and three counts, called once per full page render. Principle
// VIII's single projection allowance is not spent on this: they are indexed
// counts over the base tables, and research R5 records that if they ever measure
// too slow the answer is to drop a badge rather than to add a projection.
type Badges struct {
	Packages int `json:"packages" doc:"Packages visible in the catalog — the same figure the catalog's own total reports with no filters applied." example:"10"`
	Profiles int `json:"profiles" doc:"Profiles this identity may read, and no others (FR-044)." example:"4"`
	// OpenFindings is the badge the design colours. It is global rather than
	// per-identity because packages are org-visible: there is no per-caller
	// scoping to apply and inventing one would be a guess wearing an access check.
	OpenFindings int `json:"openFindings" doc:"Findings awaiting a decision." example:"4"`
}
