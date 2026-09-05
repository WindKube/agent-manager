package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"agent-manager/internal/domain/capability"
	"agent-manager/internal/worker/scanner/rules"
)

// The engine: the only Go code that decides whether a rule fires. Every check
// below is the same three lines — take the rules addressed to me, run them
// through here, grade the result — so a new DETECTION CLASS is a matcher plus a
// `match.kind` value, and there is no per-rule function anywhere in this
// package.

// maxEvidencePerFinding bounds the locations one finding records. The rows
// come from attacker-controlled content and land in `finding_evidence`, so a
// script with 50 000 matching lines must not choose how many rows one scan
// writes; the finding still says how many there were in its own detail, so a
// truncated list does not read as a complete one.
const maxEvidencePerFinding = 8

// maxFindingsPerRule bounds one rule's findings for one bundle: one finding
// per matching FILE, and a bundle of 10 000 scripts is a bundle, not a reason
// for 10 000 rows.
const maxFindingsPerRule = 25

// hit is one match: where it was, and what the rule extracted there.
type hit struct {
	path  string
	line  int
	quote string
	// value is what the condition judged — a host, a path, a dependency spec —
	// kept so the finding's detail can name it.
	value string
}

// run applies every rule addressed to one check.
func run(ctx context.Context, b *Bundle, rs []rules.Rule) ([]Finding, error) {
	var findings []Finding
	// Indexed rather than ranged by value: a Rule carries its compiled pattern
	// and scope, so copying one per iteration is copying the pack per check.
	for i := range rs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raised, err := apply(b, rs[i])
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rs[i].ID, err)
		}
		findings = append(findings, raised...)
	}
	return findings, nil
}

// apply dispatches one rule to its matcher.
func apply(b *Bundle, rule rules.Rule) ([]Finding, error) {
	var hits []hit
	switch rule.Match.Kind {
	case rules.KindShellAST:
		hits = matchShell(b, rule)
	case rules.KindRegex:
		hits = matchRegex(b, rule)
	case rules.KindDepManifest:
		hits = matchDependencies(b, rule)
	case rules.KindSchemaPath:
		hits = matchSchema(b, rule)
	default:
		// Unreachable: rules.Load refuses a kind this build does not
		// implement, so the failure names the file rather than appearing as
		// a bundle that scanned clean.
		return nil, fmt.Errorf("match.kind %q has no matcher", rule.Match.Kind)
	}
	return group(rule, hits), nil
}

// group turns the matches into findings: one finding per FILE, its first match
// the primary location and the rest supporting — a finding is a thing a
// reviewer decides about once, and the other lines are what that decision
// covers.
func group(rule rules.Rule, hits []hit) []Finding {
	if len(hits) == 0 {
		return nil
	}

	byFile := make(map[string][]hit)
	order := make([]string, 0, 4)
	for _, h := range hits {
		if _, seen := byFile[h.path]; !seen {
			order = append(order, h.path)
		}
		byFile[h.path] = append(byFile[h.path], h)
	}
	sort.Strings(order)

	findings := make([]Finding, 0, len(order))
	for _, filePath := range order {
		if len(findings) >= maxFindingsPerRule {
			break
		}
		fileHits := byFile[filePath]
		sort.SliceStable(fileHits, func(i, j int) bool { return fileHits[i].line < fileHits[j].line })

		finding := Finding{
			RuleID:   rule.ID,
			Severity: rule.Severity,
			Title:    rule.Title,
			Detail:   detailFor(rule, fileHits),
		}
		for i, h := range fileHits {
			if i >= maxEvidencePerFinding {
				break
			}
			finding.Evidence = append(finding.Evidence, Evidence{
				Path:       h.path,
				Line:       h.line,
				Quote:      clip(h.quote),
				Supporting: i > 0,
			})
		}
		findings = append(findings, finding)
	}
	return findings
}

// detailFor is the rule's prose plus what this bundle actually matched: the
// prose explains WHY the rule exists, and the appended sentence is the only
// per-bundle text, so a reader is not left to count evidence rows to learn
// that eight of forty are shown.
func detailFor(rule rules.Rule, hits []hit) string {
	detail := strings.TrimSpace(rule.Detail)

	values := make([]string, 0, len(hits))
	seen := make(map[string]struct{}, len(hits))
	for _, h := range hits {
		if h.value == "" {
			continue
		}
		if _, dup := seen[h.value]; dup {
			continue
		}
		seen[h.value] = struct{}{}
		if len(values) < 8 {
			values = append(values, clip(h.value))
		}
	}

	var note strings.Builder
	fmt.Fprintf(&note, "%d location", len(hits))
	if len(hits) != 1 {
		note.WriteString("s")
	}
	note.WriteString(" in " + hits[0].path)
	if len(hits) > maxEvidencePerFinding {
		fmt.Fprintf(&note, "; the first %d are quoted below", maxEvidencePerFinding)
	}
	if len(values) > 0 {
		note.WriteString(". Matched: " + strings.Join(values, ", "))
	}

	if detail == "" {
		return note.String()
	}
	return detail + "\n\n" + note.String()
}

// judge applies a rule's condition to one extracted value.
func judge(b *Bundle, rule rules.Rule, value string) bool {
	switch rule.Match.Condition {
	case rules.ConditionAlways:
		return true

	case rules.ConditionValueMatches:
		return rule.Match.Regexp() != nil && rule.Match.Regexp().MatchString(value)

	case rules.ConditionHostNotInExpected:
		// Where an expected set was recorded, a host inside it is accepted and
		// every other host is surfaced. Where none was recorded, EVERY host is
		// surfaced rather than silently accepted — and a host this analysis
		// could not name is surfaced too, since "cannot be shown to be in the
		// list" is the only sound reading of an unresolvable target.
		if value == "" || capability.Indefinite(value) {
			return true
		}
		declared, ok := b.ExpectedDetail(capability.Network)
		if !ok {
			return true
		}
		return !hostCovered(value, declared)

	case rules.ConditionPathOutsideExpected:
		if value == "" {
			return false
		}
		if capability.Indefinite(value) {
			// A path behind an expansion cannot be shown to stay inside the
			// package, and a `$HOME`-rooted one usually does not.
			return true
		}
		if capability.InsidePackage(value) && !capability.OverBroad(value) {
			return false
		}
		readable, readDeclared := b.ExpectedDetail(capability.FilesystemRead)
		writable, writeDeclared := b.ExpectedDetail(capability.FilesystemWrite)
		if !readDeclared && !writeDeclared {
			return true
		}
		return !pathCovered(value, readable) && !pathCovered(value, writable)

	case rules.ConditionVersionUnpinned:
		return unpinned(value)

	default:
		// Unreachable for the same reason as the kind switch above.
		return false
	}
}

// hostCovered reports whether a declared expectation covers a discovered host.
// A leading dot or `*.` is read as "this domain and its subdomains"; bare
// entries match exactly — `example.com` does NOT cover `evil.example.com`,
// because a suffix match by default is how an allowlist becomes
// allow-anything.
func hostCovered(host string, declared []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, entry := range declared {
		entry = strings.ToLower(strings.TrimSpace(entry))
		switch {
		case entry == "":
			continue
		case entry == host:
			return true
		case strings.HasPrefix(entry, "*."):
			if strings.HasSuffix(host, entry[1:]) {
				return true
			}
		case strings.HasPrefix(entry, "."):
			if strings.HasSuffix(host, entry) {
				return true
			}
		}
	}
	return false
}

// pathCovered reports whether a declared expectation covers a discovered path. A
// declared directory covers what is under it; nothing else is inferred.
func pathCovered(target string, declared []string) bool {
	target = strings.TrimSpace(target)
	for _, entry := range declared {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == target {
			return true
		}
		if strings.HasSuffix(entry, "/") && strings.HasPrefix(target, entry) {
			return true
		}
		if strings.HasPrefix(target, strings.TrimSuffix(entry, "/")+"/") {
			return true
		}
	}
	return false
}

// ruleCheck is every check in this package: one implementation, since there is
// one mechanism. If a check ever needs its own Go logic, that logic is a new
// matcher and `match.kind`, not a bespoke Check: a check that analysed
// something no rule described would be a detection nobody can tune or turn
// off.
type ruleCheck struct {
	id    string
	label string
	// blindSpots counts what this check could not analyse, added to the warn
	// count so a file the parser could not read shows as a warning rather
	// than disappearing into a pass.
	blindSpots func(b *Bundle) int
}

func (c ruleCheck) ID() string    { return c.id }
func (c ruleCheck) Label() string { return c.label }

func (c ruleCheck) Run(ctx context.Context, b *Bundle, rs []rules.Rule) (Result, []Finding, error) {
	findings, err := run(ctx, b, rs)
	if err != nil {
		return Result{}, nil, err
	}
	spots := 0
	if c.blindSpots != nil {
		spots = c.blindSpots(b)
	}
	return grade(findings, spots), findings, nil
}
