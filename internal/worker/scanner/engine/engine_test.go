package engine

import (
	"encoding/json"
	"mime"
	"mime/multipart"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/worker/scanner/rules"
)

// The golden reports are real `POST /scan-upload` responses from the pinned
// engine. Its finding fields are undocumented, so a change must fail here.

func loadReport(t *testing.T, name string) report {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	var rep report
	require.NoError(t, json.Unmarshal(raw, &rep))
	return rep
}

func TestTranslateAHostileReport(t *testing.T) {
	rep := loadReport(t, "hostile-report.json")
	require.False(t, rep.IsSafe)
	require.Equal(t, 8, rep.FindingsCount)

	result, err := translate(rep, rules.SeverityMedium)
	require.NoError(t, err)

	t.Run("the two skill-quality complaints are counted, not stored", func(t *testing.T) {
		// SOCIAL_ENG_VAGUE_DESCRIPTION (low) and MANIFEST_MISSING_LICENSE (info).
		require.Len(t, result.Findings, 6)
		for _, finding := range result.Findings {
			require.NotEqual(t, rules.SeverityLow, finding.Severity)
		}
	})

	t.Run("the obfuscated execution flow is stored at high", func(t *testing.T) {
		// A base64 payload piped into a shell, opaque to the rule pack's matchers.
		found := false
		for _, finding := range result.Findings {
			if finding.RuleID != "CORRELATED_OBFUSCATION_EXECUTION_FLOW" {
				continue
			}
			found = true
			require.Equal(t, rules.SeverityHigh, finding.Severity)
			require.Len(t, finding.Evidence, 1)
			require.Equal(t, "setup.sh", finding.Evidence[0].Path)
			require.Equal(t, 3, finding.Evidence[0].Line)
		}
		require.True(t, found, "the correlation analyzer's finding was dropped")
	})

	t.Run("critical collapses onto high", func(t *testing.T) {
		for _, finding := range result.Findings {
			if finding.RuleID == "YARA_prompt_injection_generic" {
				require.Equal(t, rules.SeverityHigh, finding.Severity)
			}
		}
	})

	t.Run("every enabled analyzer gets a row, graded from its own findings", func(t *testing.T) {
		byID := make(map[string]int, len(result.Checks))
		for i, run := range result.Checks {
			byID[run.CheckID] = i
		}
		require.Len(t, result.Checks, len(Analyzers))

		static := result.Checks[byID[ID+"/static"]]
		require.Equal(t, "fail", string(static.Result.Outcome))
		// Two medium findings plus the two counted below the threshold.
		require.Equal(t, 4, static.Result.WarnCount)

		correlation := result.Checks[byID[ID+"/correlation"]]
		require.Equal(t, "fail", string(correlation.Result.Outcome))

		for _, name := range []string{"bytecode", "pipeline", "behavioral"} {
			require.Equal(t, "pass", string(result.Checks[byID[ID+"/"+name]].Result.Outcome), name)
		}
	})
}

func TestTranslateABenignReport(t *testing.T) {
	rep := loadReport(t, "benign-report.json")
	require.True(t, rep.IsSafe)
	require.Zero(t, rep.FindingsCount)

	result, err := translate(rep, rules.SeverityMedium)
	require.NoError(t, err)
	require.Empty(t, result.Findings)
	require.Len(t, result.Checks, len(Analyzers))
	for _, run := range result.Checks {
		require.Equal(t, "pass", string(run.Result.Outcome), run.CheckID)
	}
}

func TestAResponseThisBuildCannotReadIsNotACleanScan(t *testing.T) {
	// Guards against the engine renaming a field so every finding parses to nothing.
	t.Run("a counted finding that did not parse", func(t *testing.T) {
		_, err := translate(report{
			IsSafe:        false,
			MaxSeverity:   "CRITICAL",
			FindingsCount: 3,
			Findings:      []finding{{Severity: "HIGH"}, {Severity: "HIGH"}, {Severity: "HIGH"}},
		}, rules.SeverityMedium)
		require.ErrorIs(t, err, ErrShapeMismatch)
	})

	t.Run("unsafe with nothing parsed", func(t *testing.T) {
		_, err := translate(report{IsSafe: false, MaxSeverity: "HIGH"}, rules.SeverityMedium)
		require.ErrorIs(t, err, ErrShapeMismatch)
	})

	t.Run("but thresholding is not a mismatch", func(t *testing.T) {
		result, err := translate(report{
			IsSafe:        false,
			MaxSeverity:   "LOW",
			FindingsCount: 2,
			Findings: []finding{
				{RuleID: "A", Severity: "LOW", Analyzer: "static"},
				{RuleID: "B", Severity: "INFO", Analyzer: "static"},
			},
		}, rules.SeverityMedium)
		require.NoError(t, err)
		require.Empty(t, result.Findings)
	})
}

func TestSeverityMapping(t *testing.T) {
	for raw, want := range map[string]rules.Severity{
		"CRITICAL": rules.SeverityHigh,
		"HIGH":     rules.SeverityHigh,
		"MEDIUM":   rules.SeverityMedium,
		"LOW":      rules.SeverityLow,
		"INFO":     rules.SeverityLow,
		"critical": rules.SeverityHigh,
		// An unseen severity means the pinned engine's response changed.
		"CATASTROPHIC": rules.SeverityHigh,
		"":             rules.SeverityHigh,
	} {
		require.Equal(t, want, severity(raw), raw)
	}
}

// Walks Analyzers rather than the maps, because Label and Explain fall back to
// a generic string that would hide a missing entry.
func TestEveryEnabledAnalyzerHasALabelAndAnExplanation(t *testing.T) {
	for _, name := range Analyzers {
		label, ok := labels[name]
		require.Truef(t, ok, "%s has no entry in labels", name)
		require.NotEmpty(t, strings.TrimSpace(label), "%s has a blank label", name)

		explain, ok := explanations[name]
		require.Truef(t, ok, "%s has no entry in explanations", name)
		require.NotEmpty(t, strings.TrimSpace(explain), "%s has a blank explanation", name)
	}
}

func TestAnalyzerNameNormalisesBothSpellings(t *testing.T) {
	// /health lists static_analyzer; a finding carries static.
	require.Equal(t, "static", analyzerName("static_analyzer"))
	require.Equal(t, "static", analyzerName("static"))
	require.Equal(t, "behavioral", analyzerName("Behavioral_Analyzer"))
}

func TestNoRequestCanReachANetworkAnalyzer(t *testing.T) {
	client, err := New(Options{BaseURL: "http://engine:8000"})
	require.NoError(t, err)

	body, contentType, err := client.(*service).uploadBody([]byte("PK\x03\x04"))
	require.NoError(t, err)

	_, params, err := mime.ParseMediaType(contentType)
	require.NoError(t, err)
	reader := multipart.NewReader(strings.NewReader(string(body)), params["boundary"])
	form, err := reader.ReadForm(1 << 20)
	require.NoError(t, err)

	for _, name := range []string{"use_llm", "use_virustotal", "use_aidefense", "use_trigger", "use_osv", "enable_meta"} {
		require.Equal(t, []string{"false"}, form.Value[name], name)
	}
	require.Equal(t, []string{"true"}, form.Value["use_behavioral"])
	require.Equal(t, []string{PolicyBalanced}, form.Value["policy"])

	// API keys travel as headers; none is sent, so no cloud analyzer can run.
	require.Empty(t, form.Value["vt_api_key"])
	require.Empty(t, form.Value["aidefense_api_url"])

	// The engine rejects an upload whose filename does not end in .zip.
	require.Len(t, form.File["file"], 1)
	require.True(t, strings.HasSuffix(form.File["file"][0].Filename, ".zip"))
}

func TestOptionsRefuseWhatTheEngineWouldNotAccept(t *testing.T) {
	for name, opts := range map[string]Options{
		"no url":       {},
		"bad scheme":   {BaseURL: "ftp://engine"},
		"no host":      {BaseURL: "http://"},
		"bad policy":   {BaseURL: "http://engine", Policy: "paranoid"},
		"bad severity": {BaseURL: "http://engine", Threshold: rules.Severity("catastrophic")},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(opts)
			require.Error(t, err)
		})
	}

	t.Run("defaults are the safe ones", func(t *testing.T) {
		client, err := New(Options{BaseURL: "http://engine:8000"})
		require.NoError(t, err)
		opts := client.(*service).opts
		require.Equal(t, PolicyBalanced, opts.Policy)
		require.Equal(t, rules.SeverityMedium, opts.Threshold)
		require.Equal(t, 60*time.Second, opts.Timeout)
	})
}
