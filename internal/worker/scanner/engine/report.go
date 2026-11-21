package engine

import "errors"

// ErrUnanalysable reports a malformed package the engine declined to load; the
// rule pack already reports it, so the caller records only a blind spot.
var ErrUnanalysable = errors.New("engine could not load the package")

type health struct {
	Status    string   `json:"status"`
	Version   string   `json:"version"`
	Analyzers []string `json:"analyzers_available"`
}

// report is the POST /scan-upload response. Its summary fields are cross-checked
// against Findings to detect a response shape this build does not understand.
type report struct {
	ScanID        string    `json:"scan_id"`
	SkillName     string    `json:"skill_name"`
	IsSafe        bool      `json:"is_safe"`
	MaxSeverity   string    `json:"max_severity"`
	FindingsCount int       `json:"findings_count"`
	Duration      float64   `json:"scan_duration_seconds"`
	Findings      []finding `json:"findings"`
}

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
