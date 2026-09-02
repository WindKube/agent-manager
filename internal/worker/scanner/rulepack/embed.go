// Package rulepack is the rule pack this build ships, as data.
//
// It is embedded so that a container with nothing mounted still scans. A scanner
// that came up with no rules would report every check passing and every bundle
// clean, which is a worse outcome than refusing to start — so the shipped pack is
// the floor, and AGENT_MANAGER_RULEPACK_DIR replaces it when a directory is
// mounted there (rules.Open). Replaces, not merges: two packs merged have no
// single version to record in `scan.pack_version`, and an operator editing a rule
// needs to know which file the scanner actually read.
//
// Adding or tuning a rule is a YAML file in rules/ plus its two fixtures. No Go
// change, no rebuild — the constitution's Development Workflow requires exactly
// that, and it is why the engine in ../checks holds no rule content at all.
package rulepack

import (
	"embed"
	"io/fs"
)

// Files is the pack: its manifest, its rules and the fixtures each rule ships.
//
// The fixtures are embedded alongside the rules rather than left in the tree for
// the test to find, so that TestEveryRuleTripsItsHostileFixture exercises the
// pack as shipped — including inside the image, where the repository is not
// present.
//
//go:embed pack.yaml rules fixtures
var Files embed.FS

// FS is the pack's root filesystem.
func FS() fs.FS { return Files }
