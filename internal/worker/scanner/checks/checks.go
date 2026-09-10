// Package checks is the scanner's check registry and the engine that applies
// rule data to a bundle. Nothing here holds a rule: each check declares an
// id, label and which rules it consumes, and every pattern, command name,
// severity and prose string lives in the pack.
package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"agent-manager/internal/worker/scanner/rules"
)

// Outcome is one check's result, mirroring the `check_result` enum.
type Outcome string

const (
	OutcomePass Outcome = "pass"
	OutcomeFail Outcome = "fail"
	OutcomeWarn Outcome = "warn"
)

// Result is what one check reports for the matrix.
type Result struct {
	Outcome Outcome
	// WarnCount counts sub-high findings plus any file the check could not
	// analyse — a blind spot is a warning, never a pass.
	WarnCount int
}

// Evidence is one location a finding points at.
type Evidence struct {
	Path string
	// Line is 1-based; zero means the finding names a file without a line.
	Line int
	// Quote is bundle content quoted verbatim, attacker-controlled and
	// always rendered escaped.
	Quote string
	// Supporting marks a location that shows a consequence rather than the
	// cause; exactly one location per finding is primary, the first.
	Supporting bool
}

// Finding is one problem a check raised.
type Finding struct {
	RuleID   string
	Severity rules.Severity
	Title    string
	Detail   string
	// Evidence is ordered: the first entry is primary.
	Evidence []Evidence
}

// Primary is the location a finding's own evidence triple copies.
func (f Finding) Primary() Evidence {
	if len(f.Evidence) == 0 {
		return Evidence{}
	}
	return f.Evidence[0]
}

// Check is one analysis in the registry. It receives an already-extracted,
// already-capped Bundle and never touches the network, the filesystem
// outside the bundle, or a subprocess.
type Check interface {
	// ID is stable and is stored on `scan_check.check_id`.
	ID() string
	// Label is what the checks-run matrix renders.
	Label() string
	// Run applies the rules addressed to this check.
	Run(ctx context.Context, b *Bundle, rs []rules.Rule) (Result, []Finding, error)
}

// CheckRun is one row of the checks-run matrix.
type CheckRun struct {
	CheckID string
	Label   string
	Result  Result
}

// Registry is the one list of checks.
type Registry struct {
	checks []Check
}

// NewRegistry builds a registry over the given checks, refusing a duplicate
// id: two checks sharing one would silently drop one result.
func NewRegistry(checks ...Check) (*Registry, error) {
	seen := make(map[string]struct{}, len(checks))
	for _, check := range checks {
		if check == nil {
			return nil, fmt.Errorf("check registry: nil check")
		}
		if check.ID() == "" || check.Label() == "" {
			return nil, fmt.Errorf("check registry: a check has no id or no label")
		}
		if _, dup := seen[check.ID()]; dup {
			return nil, fmt.Errorf("check registry: %s is registered twice", check.ID())
		}
		seen[check.ID()] = struct{}{}
	}
	return &Registry{checks: checks}, nil
}

// Default is the registry the scanner runs, in the order the matrix lists
// them. The seven ids are the `check` enum of the rule-pack contract.
func Default() (*Registry, error) {
	return NewRegistry(
		ManifestSchema(),
		NetworkAllowlist(),
		ShellAudit(),
		SecretExfiltration(),
		PromptInjection(),
		FilesystemScope(),
		DependencyPinning(),
	)
}

// IDs are the registered check ids in registration order.
func (r *Registry) IDs() []string {
	out := make([]string, 0, len(r.checks))
	for _, check := range r.checks {
		out = append(out, check.ID())
	}
	return out
}

// Checks returns the registered checks in registration order.
func (r *Registry) Checks() []Check { return append([]Check(nil), r.checks...) }

// Run applies every registered check to one bundle. Every check produces a
// row, including passes and ones the pack addresses no rule to.
func (r *Registry) Run(ctx context.Context, b *Bundle, pack *rules.Pack) ([]CheckRun, []Finding, error) {
	if b == nil {
		return nil, nil, fmt.Errorf("check run: no bundle")
	}
	if pack == nil {
		return nil, nil, fmt.Errorf("check run: no rule pack")
	}

	runs := make([]CheckRun, 0, len(r.checks))
	var findings []Finding

	for _, check := range r.checks {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		result, raised, err := check.Run(ctx, b, pack.For(check.ID()))
		if err != nil {
			return nil, nil, fmt.Errorf("check %s: %w", check.ID(), err)
		}
		runs = append(runs, CheckRun{CheckID: check.ID(), Label: check.Label(), Result: result})
		findings = append(findings, raised...)
	}

	// Ordered by severity then rule and location, for deterministic rows.
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.Severity != right.Severity {
			return severityRank(left.Severity) > severityRank(right.Severity)
		}
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		if left.Primary().Path != right.Primary().Path {
			return left.Primary().Path < right.Primary().Path
		}
		return left.Primary().Line < right.Primary().Line
	})
	return runs, findings, nil
}

func severityRank(s rules.Severity) int {
	switch s {
	case rules.SeverityHigh:
		return 2
	case rules.SeverityMedium:
		return 1
	default:
		return 0
	}
}

// grade turns a check's findings into its matrix result: a high-severity
// finding fails the check, anything else warns with a count.
func grade(findings []Finding, blindSpots int) Result {
	result := Result{Outcome: OutcomePass, WarnCount: blindSpots}
	for _, finding := range findings {
		if finding.Severity == rules.SeverityHigh {
			result.Outcome = OutcomeFail
			continue
		}
		result.WarnCount++
	}
	if result.Outcome == OutcomePass && result.WarnCount > 0 {
		result.Outcome = OutcomeWarn
	}
	return result
}

// clip bounds a quote taken from bundle content: attacker-controlled, so
// neither its size nor its control characters may be trusted.
const maxQuoteBytes = 240

func clip(text string) string {
	text = strings.Map(func(r rune) rune {
		switch {
		case r == '\t', r == '\n', r == '\r':
			return ' '
		case r < 0x20, r == 0x7f:
			return -1
		default:
			return r
		}
	}, text)
	text = strings.Join(strings.Fields(text), " ")
	if len(text) <= maxQuoteBytes {
		return text
	}

	// Cut on a rune boundary so the stored quote stays valid UTF-8.
	cut := maxQuoteBytes
	for cut > 0 && !isRuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "…"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
