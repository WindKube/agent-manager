package contract

import "time"

// PackageScan is the latest visible version's scan result and findings. It
// reuses the Scanner screen's row types so the two screens can't disagree
// about what a finding is.
type PackageScan struct {
	Version string `json:"version" doc:"The latest visible version this scan describes." example:"1.3.0"`
	// Scanned tells a version scanned clean from one never scanned; both have
	// no findings.
	Scanned bool `json:"scanned"`

	Scan     FindingScan          `json:"scan" doc:"The zero value while Scanned is false."`
	Checks   []FindingCheck       `json:"checks" doc:"Every check the scan ran, passes included."`
	Findings []PackageScanFinding `json:"findings" doc:"Every finding this scan raised against this version."`
}

// PackageScanFinding carries no packageId or version: the caller already
// named both to reach it.
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
