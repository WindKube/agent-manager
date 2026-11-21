package scanner

import (
	"agent-manager/internal/config"
	"agent-manager/internal/worker/scanner/engine"
	"agent-manager/internal/worker/scanner/rules"
)

// engineClient returns nil when no engine is configured. A configured engine
// that fails to build is a startup error so a mistyped URL never silently
// degrades to the rule pack alone.
func engineClient(cfg config.Scanner) (engine.Client, error) {
	if cfg.ScanEngineURL == "" {
		return nil, nil
	}
	return engine.New(engine.Options{
		BaseURL:   cfg.ScanEngineURL,
		Timeout:   cfg.ScanEngineTimeout,
		Policy:    cfg.ScanEnginePolicy,
		Threshold: rules.Severity(cfg.ScanEngineThreshold),
	})
}
