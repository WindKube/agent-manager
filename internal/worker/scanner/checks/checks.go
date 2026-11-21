// Package checks is the scanner's check registry and the engine that applies
// rule data to a bundle. Every pattern, severity and prose string lives in the
// rule pack, not here.
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
	// WarnCount counts sub-high findings plus blind spots; a blind spot is never a pass.
	WarnCount int
}

// Evidence is one location a finding points at.
type Evidence struct {
	Path string
	// Line is 1-based; zero means the finding names a file without a line.
	Line int
	// Quote is attacker-controlled bundle content and must always be rendered escaped.
	Quote string
	// Supporting marks a consequence rather than the cause; only the first
	// location is primary.
	Supporting bool
}

// Finding is one problem a check raised.
type Finding struct {
	RuleID string
	// Engine disambiguates rule ids shared by two engines.
	Engine   string
	Severity rules.Severity
	Title    string
	Detail   string
	Evidence []Evidence
}

// Primary returns the first evidence location, or the zero value.
func (f Finding) Primary() Evidence {
	if len(f.Evidence) == 0 {
		return Evidence{}
	}
	return f.Evidence[0]
}

// Check is one analysis in the registry. It never touches the network, the
// filesystem outside the bundle, or a subprocess.
type Check interface {
	// ID is stable and is stored on `scan_check.check_id`.
	ID() string
	Label() string
	// Explain says in general what a warn or fail on this row means. Required.
	Explain() string
	Run(ctx context.Context, b *Bundle, rs []rules.Rule) (Result, []Finding, error)
}

// CheckRun is one row of the checks-run matrix.
type CheckRun struct {
	CheckID string
	Engine  string
	Label   string
	Explain string
	Result  Result
}

type Registry struct {
	checks []Check
}

// NewRegistry refuses a duplicate id, which would silently drop one result.
func NewRegistry(checks ...Check) (*Registry, error) {
	seen := make(map[string]struct{}, len(checks))
	for _, check := range checks {
		if check == nil {
			return nil, fmt.Errorf("check registry: nil check")
		}
		if check.ID() == "" || check.Label() == "" || strings.TrimSpace(check.Explain()) == "" {
			return nil, fmt.Errorf("check registry: %s has no id, no label, or no explanation", check.ID())
		}
		if _, dup := seen[check.ID()]; dup {
			return nil, fmt.Errorf("check registry: %s is registered twice", check.ID())
		}
		seen[check.ID()] = struct{}{}
	}
	return &Registry{checks: checks}, nil
}

// Default is the registry the scanner runs, in matrix order. The ids are the
// rule-pack contract's `check` enum.
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

// Run applies every check to one bundle. Every check produces a row, even with
// no rules addressed to it.
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
		runs = append(runs, CheckRun{
			CheckID: check.ID(), Label: check.Label(), Explain: check.Explain(), Result: result,
		})
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

// Grade fails a check on any high-severity finding and otherwise warns with a
// count. Exported so analysers outside this package grade the same way.
func Grade(findings []Finding, blindSpots int) Result {
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

const maxQuoteBytes = 240

// Clip is the one way bundle content becomes a stored quote: control characters
// stripped and length capped. Exported so no laxer copy appears elsewhere.
func Clip(text string) string {
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

	cut := maxQuoteBytes
	for cut > 0 && !isRuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "…"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
