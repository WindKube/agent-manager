package engine

import (
	"fmt"
	"sort"
	"strings"

	"agent-manager/internal/worker/scanner/checks"
	"agent-manager/internal/worker/scanner/rules"
)

var labels = map[string]string{
	"static":      "Static rules and signatures",
	"bytecode":    "Compiled Python",
	"pipeline":    "Instruction pipeline",
	"correlation": "Correlated behaviour",
	"behavioral":  "Dataflow",
}

// explanations describe analyzers, not the engine's rule ids, which are not
// enumerable here. They are grounded in the golden reports under testdata/
// rather than guesses about third-party detection logic.
var explanations = map[string]string{
	"static": "Matches the bundle's files against the engine's signature and pattern rules — " +
		"YARA byte signatures plus built-in checks — covering prompt injection, tool-chaining " +
		"abuse, outbound network primitives, obfuscated shell content, and basic manifest " +
		"hygiene such as a missing licence or a vague description.",
	"bytecode": "Looks for compiled Python (`.pyc`) shipped without its source, which hides " +
		"what actually runs behind bytes nobody can read.",
	"pipeline": "One of the engine's four static analyzers. This project's own spec groups it " +
		"with the others as covering encoded or hidden content a text-only pattern cannot see, " +
		"but the pinned engine's own documentation for what it inspects is not vendored in " +
		"this repository, so it cannot be described more precisely than that here.",
	"correlation": "Looks for a chain across the bundle rather than one match on its own — for " +
		"example, content that is decoded or unpacked and then reaches code execution, which " +
		"no single line reveals by itself.",
	"behavioral": "Builds a dataflow graph from the bundle's code and flags dataflow from a " +
		"sensitive read, such as a credential file, to a network write across function " +
		"boundaries — a chain a line-by-line pattern cannot follow.",
}

// severity maps an unrecognised value to high: with a pinned engine it means the
// response changed, and the loud outcome is the safe one.
func severity(raw string) rules.Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "high":
		return rules.SeverityHigh
	case "medium":
		return rules.SeverityMedium
	case "low", "info":
		return rules.SeverityLow
	default:
		return rules.SeverityHigh
	}
}

func rank(s rules.Severity) int {
	switch s {
	case rules.SeverityHigh:
		return 2
	case rules.SeverityMedium:
		return 1
	default:
		return 0
	}
}

// translate counts below-threshold findings on the check row instead of storing
// them. The cross-check compares parsed findings, not stored ones, so
// thresholding never looks like a shape mismatch.
func translate(rep report, threshold rules.Severity) (Result, error) {
	type bucket struct {
		findings []checks.Finding
		below    int
	}
	buckets := make(map[string]*bucket, len(Analyzers))
	for _, name := range Analyzers {
		buckets[name] = &bucket{}
	}

	parsed := 0
	for i := range rep.Findings {
		raw := &rep.Findings[i]
		if strings.TrimSpace(raw.RuleID) == "" {
			continue
		}
		parsed++

		name := analyzerName(raw.Analyzer)
		slot, ok := buckets[name]
		if !ok {
			// Never drop findings from an analyzer this build does not list.
			slot = &bucket{}
			buckets[name] = slot
		}

		level := severity(raw.Severity)
		if rank(level) < rank(threshold) {
			slot.below++
			continue
		}
		slot.findings = append(slot.findings, translateFinding(raw, level))
	}

	if err := crossCheck(rep, parsed); err != nil {
		return Result{}, err
	}

	names := make([]string, 0, len(buckets))
	for name := range buckets {
		names = append(names, name)
	}
	sort.Strings(names)

	result := Result{}
	for _, name := range names {
		slot := buckets[name]
		result.Checks = append(result.Checks, checks.CheckRun{
			CheckID: ID + "/" + name,
			Label:   Label(name),
			Explain: Explain(name),
			Result:  checks.Grade(slot.findings, slot.below),
		})
		result.Findings = append(result.Findings, slot.findings...)
	}
	return result, nil
}

// crossCheck errors when the engine's summary reports findings this build could
// not parse, rather than recording a clean scan for a flagged package.
func crossCheck(rep report, parsed int) error {
	if rep.FindingsCount > 0 && parsed == 0 {
		return fmt.Errorf("%w: the engine counted %d findings and none parsed",
			ErrShapeMismatch, rep.FindingsCount)
	}
	if !rep.IsSafe && parsed == 0 {
		return fmt.Errorf("%w: the engine reported the package unsafe at severity %q and no finding parsed",
			ErrShapeMismatch, rep.MaxSeverity)
	}
	return nil
}

func translateFinding(raw *finding, level rules.Severity) checks.Finding {
	out := checks.Finding{
		RuleID:   raw.RuleID,
		Severity: level,
		Title:    title(raw),
		Detail:   detail(raw),
	}
	if raw.FilePath != "" {
		location := checks.Evidence{Path: raw.FilePath}
		if raw.LineNumber != nil && *raw.LineNumber > 0 {
			location.Line = *raw.LineNumber
		}
		if raw.Snippet != nil {
			location.Quote = checks.Clip(*raw.Snippet)
		}
		out.Evidence = []checks.Evidence{location}
	}
	return out
}

func title(raw *finding) string {
	if t := strings.TrimSpace(raw.Title); t != "" {
		return t
	}
	return raw.RuleID
}

func detail(raw *finding) string {
	parts := make([]string, 0, 3)
	if d := strings.TrimSpace(raw.Description); d != "" {
		parts = append(parts, d)
	}
	if r := strings.TrimSpace(raw.Remediation); r != "" {
		parts = append(parts, "Remediation: "+r)
	}
	attribution := ID
	if name := analyzerName(raw.Analyzer); name != "" {
		attribution += " " + name + " analyzer"
	}
	if c := strings.TrimSpace(raw.Category); c != "" {
		attribution += ", category " + c
	}
	parts = append(parts, "Reported by the "+attribution+".")
	return strings.Join(parts, "\n\n")
}

// analyzerName normalises the engine's two spellings: /health lists
// `static_analyzer` while a finding carries `static`.
func analyzerName(raw string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), "_analyzer")
}

// Label names one analyzer in the checks matrix.
func Label(name string) string {
	if l, ok := labels[name]; ok {
		return l
	}
	return "Engine analyzer " + name
}

// Explain says what one analyzer looks for, for the checks matrix.
func Explain(name string) string {
	if e, ok := explanations[name]; ok {
		return e
	}
	return "An analyzer of the " + ID + " engine this build does not have a description for."
}
