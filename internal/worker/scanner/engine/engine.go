// Package engine is the scanner's second analysis engine: a pinned,
// third-party static analyser reached over its own REST interface.
//
// Nothing here executes, sources, imports or evaluates bundle content. The
// engine reads an extracted tree and answers with findings, and it runs in a
// service holding no credential of this system's on a network with no egress —
// it parses attacker-controlled input with a C extension, so the process doing
// that must not be the one holding the database credential.
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

// Analyzers are the engine analyses this project enables. Every one is static
// and needs no credential. The engine's llm, virustotal and aidefense
// analyzers each need an API key and a network call, so they are absent from
// this list and from Options: not configurable, therefore not reachable.
var Analyzers = []string{"static", "bytecode", "pipeline", "correlation", "behavioral"}

// Policy presets the engine accepts.
const (
	PolicyStrict     = "strict"
	PolicyBalanced   = "balanced"
	PolicyPermissive = "permissive"
)

// Result is one engine scan in this project's vocabulary.
type Result struct {
	// Checks is one row per enabled analyzer.
	Checks []checks.CheckRun
	// Findings are the findings at or above the report threshold.
	Findings []checks.Finding
}

// Client is the engine as the scanner uses it.
type Client interface {
	// Version identifies the running engine, for the scan fingerprint. It
	// errors rather than substituting a placeholder: what an unreachable
	// engine means is the caller's decision, not this package's.
	Version(ctx context.Context) (string, error)
	// Scan submits one extracted tree.
	Scan(ctx context.Context, tree Tree) (Result, error)
}

// ErrOverCap reports a tree the engine's upload endpoint would refuse. It is a
// property of the package rather than a failure of the engine, so the caller
// records a blind spot instead of failing the version.
var ErrOverCap = errors.New("tree exceeds the engine's upload limits")

// ErrShapeMismatch reports a response this build could not read: the engine
// counted findings that did not parse. Pinning the engine version is what
// normally prevents it; this error is what stops a drifted response being
// recorded as a clean scan.
var ErrShapeMismatch = errors.New("engine response did not match the expected shape")

// Options configure the client.
type Options struct {
	// BaseURL is the engine service, AGENT_MANAGER_SCAN_ENGINE_URL.
	BaseURL string
	// Timeout bounds one request.
	Timeout time.Duration
	// Policy is the engine's own preset.
	Policy string
	// Threshold is the lowest severity stored as a finding. Below it a finding
	// is counted on its analyzer's check row: the engine reports skill-quality
	// complaints at low severity, and flagging a version for a short
	// description would make every verdict worthless.
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
