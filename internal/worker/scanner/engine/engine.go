// Package engine is the scanner's second analysis engine: a pinned,
// third-party static analyser reached over its own REST interface.
//
// The engine parses attacker-controlled input with a C extension, so it runs as
// a separate service with no credentials of this system and no egress.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"agent-manager/internal/worker/scanner/checks"
	"agent-manager/internal/worker/scanner/rules"
)

// ID is recorded on `finding.engine` and `scan_check.engine`.
const ID = "skill-scanner"

// Analyzers are the enabled engine analyses, all static and credential-free.
// Analyzers that need an API key or network call are deliberately not configurable.
var Analyzers = []string{"static", "bytecode", "pipeline", "correlation", "behavioral"}

// Policy presets the engine accepts.
const (
	PolicyStrict     = "strict"
	PolicyBalanced   = "balanced"
	PolicyPermissive = "permissive"
)

type Result struct {
	Checks []checks.CheckRun
	// Findings holds only findings at or above the threshold.
	Findings []checks.Finding
}

type Client interface {
	// Version errors rather than substituting a placeholder; the caller decides
	// what an unreachable engine means.
	Version(ctx context.Context) (string, error)
	Scan(ctx context.Context, tree Tree) (Result, error)
}

// ErrOverCap reports a tree the engine's upload limits would refuse; a property
// of the package, not an engine failure.
var ErrOverCap = errors.New("tree exceeds the engine's upload limits")

// ErrShapeMismatch stops a drifted engine response from being recorded as a clean scan.
var ErrShapeMismatch = errors.New("engine response did not match the expected shape")

type Options struct {
	// BaseURL is AGENT_MANAGER_SCAN_ENGINE_URL.
	BaseURL string
	Timeout time.Duration
	Policy  string
	// Threshold is the lowest severity stored as a finding; lower ones only count
	// on the check row, since the engine reports quality nits at low severity.
	Threshold rules.Severity
}

const (
	defaultTimeout   = 60 * time.Second
	defaultPolicy    = PolicyBalanced
	defaultThreshold = rules.SeverityMedium
)

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.Policy == "" {
		o.Policy = defaultPolicy
	}
	if o.Threshold == "" {
		o.Threshold = defaultThreshold
	}
	return o
}

func (o Options) validate() error {
	if strings.TrimSpace(o.BaseURL) == "" {
		return errors.New("engine: no base url")
	}
	parsed, err := url.Parse(o.BaseURL)
	if err != nil {
		return fmt.Errorf("engine: base url %q: %w", o.BaseURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("engine: base url %q has scheme %q", o.BaseURL, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("engine: base url %q names no host", o.BaseURL)
	}

	switch o.Policy {
	case PolicyStrict, PolicyBalanced, PolicyPermissive:
	default:
		return fmt.Errorf("engine: policy %q is not one the engine accepts", o.Policy)
	}

	switch o.Threshold {
	case rules.SeverityLow, rules.SeverityMedium, rules.SeverityHigh:
	default:
		return fmt.Errorf("engine: threshold %q is not a severity", o.Threshold)
	}
	return nil
}
