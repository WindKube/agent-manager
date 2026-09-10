package scanner

import (
	"agent-manager/internal/config"
	"agent-manager/internal/worker/scanner/engine"
	"agent-manager/internal/worker/scanner/rules"
)

// engineClient builds the second engine from the role's config, or nil when no
// engine is configured. A configured engine that will not build is a startup
// error: running the rule pack alone because a url was mistyped is the failure
// this role must not have.
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
