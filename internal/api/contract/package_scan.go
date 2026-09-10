package contract

import "time"

// PackageScan is the package detail screen's security section: the latest
// visible version's scan result and every finding it raised, with its
// evidence and any reviewer decision. It is the Scanner screen's own rows
// (FindingScan, FindingCheck, FindingEvidence, FindingOverride,
// governance.go), scoped to one package instead of paged across all of
// them, so the two screens cannot render two different ideas of a finding.
type PackageScan struct {
	Version string `json:"version" doc:"The latest visible version this scan describes." example:"1.3.0"`
	// Scanned is Capabilities.Scanned's own distinction, repeated here for
	// the same reason: a version scanned clean and one never scanned both
	// produce an empty Findings slice, and only this flag tells them apart.
	Scanned bool `json:"scanned"`

	// Scan and Checks are the zero value while Scanned is false: there is no
	// scan to describe yet, not one that ran and found nothing.
	Scan     FindingScan          `json:"scan" doc:"The zero value while Scanned is false."`
	Checks   []FindingCheck       `json:"checks" doc:"Every check the scan ran, passes included (FR-025)."`
	Findings []PackageScanFinding `json:"findings" doc:"Every finding this scan raised against this version."`
}

// PackageScanFinding is one finding, scoped to a package rather than paged
// across the whole hub, so it carries no packageId or version of its own —
// the caller already named both to reach it.
type PackageScanFinding struct {
	ID       string    `json:"id" format:"uuid"`
	RuleID   string    `json:"ruleId" example:"SH-NET-002"`
	Engine   string    `json:"engine" doc:"The analyser that raised it." example:"rulepack"`
	Severity string    `json:"severity" enum:"low,medium,high" example:"high"`
	State    string    `json:"state" enum:"open,approved,rejected" example:"open"`
	Title    string    `json:"title" example:"Undeclared network egress"`
	Detail   string    `json:"detail,omitempty" doc:"Why this was raised, in prose."`
	RaisedAt time.Time `json:"raisedAt"`

	Evidence []FindingEvidence `json:"evidence" doc:"Every location this finding points at, cause first."`
	Override *FindingOverride  `json:"override,omitempty" doc:"Present only when a reviewer has accepted this finding."`
}
