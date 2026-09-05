// Package rulepack embeds the pack's floor rule set, replaced (not merged) by AGENT_MANAGER_RULEPACK_DIR.
package rulepack

import (
	"embed"
	"io/fs"
)

//go:embed pack.yaml rules fixtures
var Files embed.FS

func FS() fs.FS { return Files }
