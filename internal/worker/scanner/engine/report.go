package engine

import "errors"

// ErrUnanalysable reports a tree the engine declined to load — a malformed
// package rather than a broken engine. The rule pack's manifest check already
// reports that, so the caller records a blind spot rather than failing the
// version twice.
var ErrUnanalysable = errors.New("engine could not load the package")

// health is GET /health.
type health struct {
	Status    string   `json:"status"`
	Version   string   `json:"version"`
	Analyzers []string `json:"analyzers_available"`
}

// report is POST /scan-upload. IsSafe, MaxSeverity and FindingsCount are the
// engine's own summary of the same scan, and disagreeing with them is how this
// build detects that it is reading a response shape it does not understand.
type report struct {
	ScanID        string    `json:"scan_id"`
	SkillName     string    `json:"skill_name"`
	IsSafe        bool      `json:"is_safe"`
	MaxSeverity   string    `json:"max_severity"`
	FindingsCount int       `json:"findings_count"`
	Duration      float64   `json:"scan_duration_seconds"`
	Findings      []finding `json:"findings"`
}

// finding is one entry of report.Findings.
type finding struct {
	RuleID      string  `json:"rule_id"`
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Remediation string  `json:"remediation"`
	FilePath    string  `json:"file_path"`
	LineNumber  *int    `json:"line_number"`
	Snippet     *string `json:"snippet"`
	Analyzer    string  `json:"analyzer"`
}
