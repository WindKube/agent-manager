package checks

import (
	"agent-manager/internal/domain/capability"
	"agent-manager/internal/worker/scanner/rules"
)

// matchRegex is the `regex` matcher: an RE2 pattern applied line by line.
//
// RE2 rather than a backtracking engine is not a style choice — the pattern is
// data an operator edits and the input is attacker-controlled, so a catastrophic
// pattern would be a denial of service an operator could write by accident. RE2
// has no backtracking to exploit (constitution, Scanner analysis).
//
// The scope defaults to the instruction files, which is what the contract's
// `regex` description states. A rule that wants to read scripts or a manifest as
// text says so with `paths`, and then it is reading them deliberately rather than
// because a default was wide.
func matchRegex(b *Bundle, rule rules.Rule) []hit {
	pattern := rule.Match.Regexp()
	if pattern == nil {
		// Unreachable: rules.Load refuses a regex rule with no pattern.
		return nil
	}

	var hits []hit
	for _, file := range b.Artefacts.Files {
		if len(rule.Match.Paths) == 0 {
			if file.Class != capability.ClassInstruction {
				continue
			}
		} else if !rule.Match.InScope(file.Path) {
			continue
		}

		for number, text := range b.Lines(file.Path) {
			for _, match := range pattern.FindAllString(text, -1) {
				value := valueOfMatch(match, rule.Match.Extract)
				if !judge(b, rule, value) {
					continue
				}
				quote := text
				if rule.Evidence.Quote == rules.QuoteMatchedNode {
					quote = match
				}
				hits = append(hits, hit{
					path:  file.Path,
					line:  number + 1,
					quote: quote,
					value: value,
				})
			}
		}
	}
	return hits
}

func valueOfMatch(match string, extract rules.Extract) string {
	switch extract {
	case rules.ExtractURLArgument:
		return capability.HostOf(match)
	default:
		// path-argument and matched-text both judge the matched text itself; the
		// difference is which condition the rule then names.
		return match
	}
}
