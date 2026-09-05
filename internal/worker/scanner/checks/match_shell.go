package checks

import (
	"agent-manager/internal/domain/capability"
	"agent-manager/internal/worker/scanner/rules"
)

// matchShell is the `shell-ast` matcher: it reads the commands the parser
// recovered, not the text of the script. Which arguments are hosts, and which
// are paths a command reads or writes, is internal/domain/capability's
// judgement, reached through its exported extractors — the scanner does not
// carry a second copy, or a finding and the capabilities panel could disagree
// about the same command.
func matchShell(b *Bundle, rule rules.Rule) []hit {
	wanted := make(map[string]struct{}, len(rule.Match.Command))
	for _, name := range rule.Match.Command {
		wanted[name] = struct{}{}
	}

	var hits []hit
	for i := range b.Commands {
		command := &b.Commands[i]
		if !rule.Match.InScope(command.File) {
			continue
		}
		if len(wanted) > 0 {
			if _, ok := wanted[command.Name]; !ok {
				continue
			}
		}

		for _, value := range extractFromCommand(command, rule.Match.Extract) {
			if !judge(b, rule, value) {
				continue
			}
			hits = append(hits, hit{
				path:  command.File,
				line:  command.Line,
				quote: quoteOfCommand(command, rule.Evidence.Quote),
				value: value,
			})
		}
	}
	return hits
}

// extractFromCommand yields the values a condition will judge. It returns at
// least one value for a command the rule selected — the empty string when the
// extractor found nothing — so a condition that fails closed on an
// unresolvable target still sees it, rather than grading `curl
// "$EXFIL_URL"` as no network reach at all.
func extractFromCommand(command *Command, extract rules.Extract) []string {
	switch extract {
	case rules.ExtractURLArgument:
		hosts := make([]string, 0, 2)
		for _, arg := range command.Args {
			if host := capability.HostOf(arg); host != "" {
				hosts = append(hosts, host)
			}
		}
		if len(hosts) == 0 {
			return []string{""}
		}
		return hosts

	case rules.ExtractPathArgument:
		// Both directions in one pass; a rule that cares about only one says
		// so through its `command` list, keeping the direction in the pack
		// rather than in this switch.
		targets := capability.CommandTargets(command.Command, true)
		targets = append(targets, capability.CommandTargets(command.Command, false)...)
		if len(targets) == 0 {
			return nil
		}
		return targets

	case rules.ExtractMatchedText:
		return []string{command.Name}

	default:
		return nil
	}
}

func quoteOfCommand(command *Command, quote rules.Quote) string {
	switch quote {
	case rules.QuoteMatchedLine:
		if command.Text != "" {
			return command.Text
		}
		return command.Node
	default:
		// matched-node. A schema-error quote cannot arise here: rules.Load
		// refuses it on any kind but schema-path.
		if command.Node != "" {
			return command.Node
		}
		return command.Text
	}
}
