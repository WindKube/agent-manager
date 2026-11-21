package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"agent-manager/internal/domain/capability"
	"agent-manager/internal/worker/scanner/rules"
)

// This is the only Go code that decides whether a rule fires. A new detection
// class is a matcher plus a `match.kind` value, not a per-rule function.

// maxEvidencePerFinding keeps a bundle from choosing how many rows a scan writes.
const maxEvidencePerFinding = 8

// maxFindingsPerRule caps one rule's per-file findings for one bundle.
const maxFindingsPerRule = 25

type hit struct {
	path  string
	line  int
	quote string
	// value is what the condition judged, kept so the detail can name it.
	value string
}

func run(ctx context.Context, b *Bundle, rs []rules.Rule) ([]Finding, error) {
	var findings []Finding
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
	case rules.KindPluginSurface:
		hits = matchSurface(b, rule)
	default:
		// Unreachable: rules.Load refuses a kind this build does not implement.
		return nil, fmt.Errorf("match.kind %q has no matcher", rule.Match.Kind)
	}
	return group(rule, hits), nil
}

// group makes one finding per file, with its first match as the primary location.
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
				Quote:      Clip(h.quote),
				Supporting: i > 0,
			})
		}
		findings = append(findings, finding)
	}
	return findings
}

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
			values = append(values, Clip(h.value))
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

func judge(b *Bundle, rule rules.Rule, value string) bool {
	switch rule.Match.Condition {
	case rules.ConditionAlways:
		return true

	case rules.ConditionValueMatches:
		return rule.Match.Regexp() != nil && rule.Match.Regexp().MatchString(value)

	case rules.ConditionHostNotInExpected:
		// Undeclared or unresolvable hosts are surfaced, never silently accepted.
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

	case rules.ConditionLauncherUnpinned:
		return launcherUnpinned(value)

	case rules.ConditionHostNotDeclared:
		if value == "" || capability.Indefinite(value) {
			return true
		}
		return !hostCovered(value, rule.Match.Allow) && !hostCovered(value, b.declaredHosts())

	default:
		return false
	}
}

// hostCovered treats a leading `.` or `*.` as the domain and its subdomains;
// bare entries match exactly.
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

// pathCovered treats a declared directory as covering everything under it.
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

// ruleCheck is the single implementation behind every check in this package.
type ruleCheck struct {
	id      string
	label   string
	explain string
	// blindSpots counts what this check could not analyse; added to the warn count.
	blindSpots func(b *Bundle) int
}

func (c ruleCheck) ID() string      { return c.id }
func (c ruleCheck) Label() string   { return c.label }
func (c ruleCheck) Explain() string { return c.explain }

func (c ruleCheck) Run(ctx context.Context, b *Bundle, rs []rules.Rule) (Result, []Finding, error) {
	findings, err := run(ctx, b, rs)
	if err != nil {
		return Result{}, nil, err
	}
	spots := 0
	if c.blindSpots != nil {
		spots = c.blindSpots(b)
	}
	return Grade(findings, spots), findings, nil
}
