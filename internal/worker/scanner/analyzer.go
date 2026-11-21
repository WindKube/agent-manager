package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"agent-manager/internal/metrics"
	"agent-manager/internal/worker/scanner/checks"
	"agent-manager/internal/worker/scanner/engine"
	"agent-manager/internal/worker/scanner/rules"
)

// analyzer is one engine that grades a bundle. All implementations share the
// same result types so nothing downstream depends on which engine ran.
type analyzer interface {
	// ID is recorded on `finding.engine` and `scan_check.engine`.
	ID() string
	// Fingerprint is part of the scan idempotency key. It never errors, because
	// failing here would leave a version at `scanning` forever.
	Fingerprint(ctx context.Context) string
	Analyze(ctx context.Context, b *checks.Bundle) ([]checks.CheckRun, []checks.Finding, error)
}

// unavailable is the Fingerprint of an unreachable analyzer. It differs from
// every real one, so a version scanned during an outage is rescanned afterwards.
const unavailable = "unavailable"

type rulepackAnalyzer struct {
	registry *checks.Registry
	pack     *rules.Pack
}

func (a rulepackAnalyzer) ID() string { return RulepackEngineID }

func (a rulepackAnalyzer) Fingerprint(context.Context) string { return a.pack.Version() }

func (a rulepackAnalyzer) Analyze(ctx context.Context, b *checks.Bundle) ([]checks.CheckRun, []checks.Finding, error) {
	return a.registry.Run(ctx, b, a.pack)
}

// RulepackEngineID is the rule pack's engine id and the `engine` column default.
const RulepackEngineID = "rulepack"

type engineAnalyzer struct {
	client engine.Client
	log    zerolog.Logger
	// required fails a version the engine could not analyse; otherwise an outage
	// is recorded as a blind spot.
	required bool
}

func (a engineAnalyzer) ID() string { return engine.ID }

func (a engineAnalyzer) Fingerprint(ctx context.Context) string {
	version, err := a.client.Version(ctx)
	if err != nil || strings.TrimSpace(version) == "" {
		return unavailable
	}
	return version
}

// unavailableRuleID is a synthetic rule id, not from either engine's rules.
const unavailableRuleID = "ENG-UNAVAILABLE"

func (a engineAnalyzer) Analyze(ctx context.Context, b *checks.Bundle) ([]checks.CheckRun, []checks.Finding, error) {
	result, err := a.client.Scan(ctx, b)
	switch {
	case err == nil:
		return result.Checks, result.Findings, nil

	case errors.Is(err, engine.ErrOverCap), errors.Is(err, engine.ErrUnanalysable):
		// A property of the package, not an engine failure: record a blind spot
		// rather than a finding that would fail every large package twice.
		metrics.ScanEngineErrors.WithLabelValues("unanalysable").Inc()
		a.log.Warn().Err(err).Msg("the engine did not analyse this package; recording a blind spot")
		return a.rows(checks.Result{Outcome: checks.OutcomeWarn, WarnCount: 1}), nil, nil

	case ctx.Err() != nil:
		// classifyClock tells the scan budget apart from a shutdown.
		return nil, nil, err

	default:
		metrics.ScanEngineErrors.WithLabelValues("failed").Inc()
		// Fail closed where policy requires it; a silent pass would drop the
		// engine's coverage across the whole catalog.
		if !a.required {
			a.log.Error().Err(err).Msg("the engine failed and is not required; recording a blind spot")
			return a.rows(checks.Result{Outcome: checks.OutcomeWarn, WarnCount: 1}), nil, nil
		}
		a.log.Error().Err(err).Msg("the engine failed and is required; failing the version")
		return a.rows(checks.Result{Outcome: checks.OutcomeFail}), a.unavailableFindings(err), nil
	}
}

// rows records the same result for every engine analyzer so the matrix shows
// what was not covered instead of omitting the rows.
func (a engineAnalyzer) rows(result checks.Result) []checks.CheckRun {
	runs := make([]checks.CheckRun, 0, len(engine.Analyzers))
	for _, name := range engine.Analyzers {
		runs = append(runs, checks.CheckRun{
			CheckID: engine.ID + "/" + name,
			Label:   engine.Label(name),
			Explain: engine.Explain(name),
			Result:  result,
		})
	}
	return runs
}

func (a engineAnalyzer) unavailableFindings(cause error) []checks.Finding {
	return []checks.Finding{{
		RuleID:   unavailableRuleID,
		Severity: rules.SeverityHigh,
		Title:    "Second scan engine did not run",
		Detail: "This version was analysed by the rule pack only: the " + engine.ID +
			" engine could not be reached, so the analyses it contributes — signature " +
			"matching, compiled code, obfuscation and dataflow — did not run. This is not " +
			"a finding about the package. It is recorded as one because a version cleared " +
			"without the coverage the policy requires is not cleared.\n\n" +
			checks.Clip(cause.Error()),
	}}
}

// fingerprint is half of `unique (version_id, pack_version)`. It names every
// analyzer, so upgrading any one makes the next scan of a scanned version run.
func fingerprint(ctx context.Context, analyzers []analyzer) string {
	parts := make([]string, 0, len(analyzers))
	for _, a := range analyzers {
		parts = append(parts, a.ID()+"="+a.Fingerprint(ctx))
	}
	return strings.Join(parts, " ")
}

// newAnalyzers puts the rule pack first so its rows lead the matrix.
func newAnalyzers(registry *checks.Registry, pack *rules.Pack, client engine.Client, required bool, log zerolog.Logger) ([]analyzer, error) {
	if registry == nil || pack == nil {
		return nil, fmt.Errorf("scanner: no rule pack to analyse with")
	}
	analyzers := []analyzer{rulepackAnalyzer{registry: registry, pack: pack}}
	if client != nil {
		analyzers = append(analyzers, engineAnalyzer{client: client, required: required, log: log})
	}
	return analyzers, nil
}
