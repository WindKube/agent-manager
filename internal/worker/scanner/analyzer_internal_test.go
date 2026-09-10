package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/worker/scanner/checks"
	"agent-manager/internal/worker/scanner/engine"
	"agent-manager/internal/worker/scanner/rules"
)

// stubEngine stands in for the engine service.
type stubEngine struct {
	version    string
	versionErr error
	result     engine.Result
	scanErr    error
}

func (s stubEngine) Version(context.Context) (string, error) {
	return s.version, s.versionErr
}

func (s stubEngine) Scan(context.Context, engine.Tree) (engine.Result, error) {
	return s.result, s.scanErr
}

func quietLog() zerolog.Logger { return zerolog.New(io.Discard) }

func newEngineAnalyzer(stub stubEngine, required bool) engineAnalyzer {
	return engineAnalyzer{client: stub, required: required, log: quietLog()}
}

// The property under test is the one that decides whether this feature is worth
// having: a scan that did not get the coverage the policy asks for must not be
// recorded clean. A silent pass would narrow the whole catalog's coverage the
// first time the engine restarted.

func TestAnEngineFailureDoesNotClearAVersion(t *testing.T) {
	broken := stubEngine{scanErr: errors.New("connection refused")}

	t.Run("required: a high finding, so the version is flagged", func(t *testing.T) {
		runs, findings, err := newEngineAnalyzer(broken, true).Analyze(context.Background(), nil)
		require.NoError(t, err, "the scan still records; it just does not clear")

		require.Len(t, findings, 1)
		require.Equal(t, unavailableRuleID, findings[0].RuleID)
		require.Equal(t, rules.SeverityHigh, findings[0].Severity)
		require.Contains(t, findings[0].Detail, "connection refused")

		require.Len(t, runs, len(engine.Analyzers))
		for _, run := range runs {
			require.Equal(t, checks.OutcomeFail, run.Result.Outcome, run.CheckID)
		}

		// verdictOf is what turns that finding into the verdict.
		require.Equal(t, "flagged", string(verdictOf(analysis{findings: findings})))
	})

	t.Run("not required: a visible blind spot and no finding", func(t *testing.T) {
		runs, findings, err := newEngineAnalyzer(broken, false).Analyze(context.Background(), nil)
		require.NoError(t, err)
		require.Empty(t, findings)
		for _, run := range runs {
			require.Equal(t, checks.OutcomeWarn, run.Result.Outcome, run.CheckID)
			require.Equal(t, 1, run.Result.WarnCount)
		}
		// A warn is not a pass, and it is also not a flag: the rule pack's
		// verdict stands alone, which is what this setting asks for.
		require.Equal(t, "clean", string(verdictOf(analysis{checks: runs})))
	})
}

func TestAPackageTheEngineWillNotTakeIsABlindSpotAndNotAFailure(t *testing.T) {
	// A 600-file package is valid here and past the engine's upload cap, and a
	// malformed one the engine declines is already reported by the rule pack's
	// manifest check. Neither is an engine outage, so neither fails the version
	// even when the engine is required.
	for name, cause := range map[string]error{
		"over the engine's upload cap": fmt.Errorf("%w: 600 files", engine.ErrOverCap),
		"the engine declined to load":  fmt.Errorf("%w: 422", engine.ErrUnanalysable),
	} {
		t.Run(name, func(t *testing.T) {
			runs, findings, err := newEngineAnalyzer(stubEngine{scanErr: cause}, true).Analyze(context.Background(), nil)
			require.NoError(t, err)
			require.Empty(t, findings)
			for _, run := range runs {
				require.Equal(t, checks.OutcomeWarn, run.Result.Outcome, run.CheckID)
			}
		})
	}
}

func TestAShapeMismatchFailsClosed(t *testing.T) {
	// Recording a clean scan off a response this build could not read is the
	// one outcome worse than an outage.
	runs, findings, err := newEngineAnalyzer(
		stubEngine{scanErr: fmt.Errorf("%w: counted 3, parsed 0", engine.ErrShapeMismatch)}, true,
	).Analyze(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, unavailableRuleID, findings[0].RuleID)
	require.Equal(t, checks.OutcomeFail, runs[0].Result.Outcome)
}

func TestACancelledScanIsNotADegradedOne(t *testing.T) {
	// The budget running out and the process shutting down are the caller's to
	// classify. Turning either into a finding about the package would be a lie,
	// and would also suppress the retry.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := newEngineAnalyzer(stubEngine{scanErr: context.Canceled}, true).Analyze(ctx, nil)
	require.ErrorIs(t, err, context.Canceled)
}

func TestTheFingerprintNamesEveryAnalyzer(t *testing.T) {
	pack, err := rules.Builtin()
	require.NoError(t, err)
	registry, err := checks.Default()
	require.NoError(t, err)

	rulepackOnly, err := newAnalyzers(registry, pack, nil, true, quietLog())
	require.NoError(t, err)
	require.Len(t, rulepackOnly, 1)

	withEngine, err := newAnalyzers(registry, pack, stubEngine{version: "2.1.0"}, true, quietLog())
	require.NoError(t, err)
	require.Len(t, withEngine, 2)

	ctx := context.Background()
	bare := fingerprint(ctx, rulepackOnly)
	both := fingerprint(ctx, withEngine)

	require.Contains(t, bare, RulepackEngineID+"="+pack.Version())
	require.NotContains(t, bare, engine.ID)
	require.Contains(t, both, engine.ID+"=2.1.0")

	t.Run("adding an engine re-fingerprints, so every version is scanned again", func(t *testing.T) {
		require.NotEqual(t, bare, both)
	})

	t.Run("upgrading the engine re-fingerprints", func(t *testing.T) {
		upgraded, err := newAnalyzers(registry, pack, stubEngine{version: "2.2.0"}, true, quietLog())
		require.NoError(t, err)
		require.NotEqual(t, both, fingerprint(ctx, upgraded))
	})

	t.Run("an unreachable engine fingerprints differently from every version", func(t *testing.T) {
		// So a version scanned during an outage is scanned again once the
		// engine is back, rather than being held clean by its own guard.
		down, err := newAnalyzers(registry, pack,
			stubEngine{versionErr: errors.New("connection refused")}, true, quietLog())
		require.NoError(t, err)
		stamp := fingerprint(ctx, down)
		require.Contains(t, stamp, engine.ID+"="+unavailable)
		require.NotEqual(t, both, stamp)
	})
}
