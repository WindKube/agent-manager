package engine

import (
	"fmt"
	"sort"
	"strings"

	"agent-manager/internal/worker/scanner/checks"
	"agent-manager/internal/worker/scanner/rules"
)

// labels name the engine's analyzers in the checks matrix.
var labels = map[string]string{
	"static":      "Static rules and signatures",
	"bytecode":    "Compiled Python",
	"pipeline":    "Instruction pipeline",
	"correlation": "Correlated behaviour",
	"behavioral":  "Dataflow",
}

// explanations say what each of this engine's own analyzers looks for, in
// general. Grounded in what this project can actually verify: the golden
// reports under testdata/ (real responses from the pinned engine) and
// specs/004-scanner-engine/spec.md, not this build's own guess at a
// third-party's detection logic. "pipeline" says so rather than guessing,
// because neither source describes it more precisely than "static".
//
// The individual rule ids these analyzers raise (YARA_prompt_injection_generic
// and the like) are the pinned engine's own and not enumerable here, so this
// explains the ANALYZER, the thing this project's own code names and can keep
// a promise about; the per-finding prose for one of its rules comes from the
// engine's own response instead (detail below).
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

// severities maps the engine's five onto the schema's three. An unrecognised
// value maps to high rather than low: the engine version is pinned, so a
// severity this build has not seen means the response changed under it, and
// the loud outcome is the safe one.
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

// translate turns one engine report into this project's vocabulary.
//
// Findings below the threshold are counted on their analyzer's check row
// instead of being stored, which is what stops a pile of skill-quality
// complaints flagging a version. The count of findings that PARSED — not the
// count stored — is what the response cross-check compares, so thresholding
// never looks like a shape mismatch.
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
			// An analyzer this build does not list still had its findings
			// reported; dropping them would be the one outcome worse than an
			// unexpected row.
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

// crossCheck compares what this build parsed against the engine's own summary
// of the same scan. A count the engine reported but this build could not read
// is a response shape it does not understand, and the alternative to erroring
// is recording a clean scan for a package the engine flagged.
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

// detail carries the engine's prose plus its remediation. Both are the
// engine's own text about its own rule, not bundle content.
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

// Explain says what one analyzer looks for, in general, for the checks
// matrix's hover text.
func Explain(name string) string {
	if e, ok := explanations[name]; ok {
		return e
	}
	return "An analyzer of the " + ID + " engine this build does not have a description for."
}
