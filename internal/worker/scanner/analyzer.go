package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"agent-manager/internal/worker/scanner/checks"
	"agent-manager/internal/worker/scanner/engine"
	"agent-manager/internal/worker/scanner/rules"
)

// analyzer is one engine that grades a bundle. Both implementations answer in
// the same vocabulary, so everything downstream of a scan — grading, the record
// transaction, the verdict, the api, the ui — sees what it already saw.
type analyzer interface {
	// ID is recorded on `finding.engine` and `scan_check.engine`.
	ID() string
	// Fingerprint identifies what this analyzer will apply, and is half of the
	// scan idempotency key. It never errors: an analyzer that cannot say
	// reports so as a value, because the alternative is a version left at
	// `scanning` for ever.
	Fingerprint(ctx context.Context) string
	// Analyze grades one bundle.
	Analyze(ctx context.Context, b *checks.Bundle) ([]checks.CheckRun, []checks.Finding, error)
}

// unavailable is the Fingerprint of an analyzer that could not be reached. It
// differs from every real one, so a version scanned while the engine was down
// is scanned again once it is back rather than suppressed by its own guard.
const unavailable = "unavailable"

// rulepackAnalyzer is the project's own rule pack.
type rulepackAnalyzer struct {
	registry *checks.Registry
	pack     *rules.Pack
}

func (a rulepackAnalyzer) ID() string { return RulepackEngineID }

func (a rulepackAnalyzer) Fingerprint(context.Context) string { return a.pack.Version() }

func (a rulepackAnalyzer) Analyze(ctx context.Context, b *checks.Bundle) ([]checks.CheckRun, []checks.Finding, error) {
	return a.registry.Run(ctx, b, a.pack)
}

// RulepackEngineID is what the rule pack's rows carry, and the default of the
// `engine` column for every row written before there was a second engine.
const RulepackEngineID = "rulepack"

// engineAnalyzer is the external static-analysis engine.
type engineAnalyzer struct {
	client engine.Client
	log    zerolog.Logger
	// required fails a version the engine could not analyse. Off, an engine
	// outage is recorded as a blind spot and the rule pack's verdict stands
	// alone.
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

// unavailableRuleID marks the finding a failed engine raises. It is not an id
// from either engine's rules.
const unavailableRuleID = "ENG-UNAVAILABLE"

func (a engineAnalyzer) Analyze(ctx context.Context, b *checks.Bundle) ([]checks.CheckRun, []checks.Finding, error) {
	result, err := a.client.Scan(ctx, b)
	switch {
	case err == nil:
		return result.Checks, result.Findings, nil

	case errors.Is(err, engine.ErrOverCap), errors.Is(err, engine.ErrUnanalysable):
		// A property of the package, not a failure of the engine. The rule pack
		// still ran, so the honest record is a visible blind spot rather than a
		// finding that would fail every large or malformed package twice.
		a.log.Warn().Err(err).Msg("the engine did not analyse this package; recording a blind spot")
		return a.rows(checks.Result{Outcome: checks.OutcomeWarn, WarnCount: 1}), nil, nil

	case ctx.Err() != nil:
		// The scan clock or a shutdown. handler.classifyClock decides which.
		return nil, nil, err

	default:
		// The engine failed. Recording this as a pass would quietly drop one
		// engine's coverage across the whole catalog, so it fails closed
		// wherever policy allows.
		if !a.required {
			a.log.Error().Err(err).Msg("the engine failed and is not required; recording a blind spot")
			return a.rows(checks.Result{Outcome: checks.OutcomeWarn, WarnCount: 1}), nil, nil
		}
		a.log.Error().Err(err).Msg("the engine failed and is required; failing the version")
		return a.rows(checks.Result{Outcome: checks.OutcomeFail}), a.unavailableFindings(err), nil
	}
}

// rows records the same result for every analyzer that did not run, so the
// matrix shows what was not covered rather than leaving the engine's rows out.
func (a engineAnalyzer) rows(result checks.Result) []checks.CheckRun {
	runs := make([]checks.CheckRun, 0, len(engine.Analyzers))
	for _, name := range engine.Analyzers {
		runs = append(runs, checks.CheckRun{
			CheckID: engine.ID + "/" + name,
			Label:   engine.Label(name),
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

// fingerprint is what a scan records on `scan.pack_version`, and half of
// `unique (version_id, pack_version)`. It names every analyzer that ran, so
// upgrading either one makes the next scan of an already-scanned version run.
func fingerprint(ctx context.Context, analyzers []analyzer) string {
	parts := make([]string, 0, len(analyzers))
	for _, a := range analyzers {
		parts = append(parts, a.ID()+"="+a.Fingerprint(ctx))
	}
	return strings.Join(parts, " ")
}

// newAnalyzers is the list a Worker runs, rule pack first so its rows lead the
// matrix.
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
