package checks

import (
	"agent-manager/internal/domain/capability"
	"agent-manager/internal/worker/scanner/rules"
)

// matchShell is the `shell-ast` matcher: it reads the commands the parser
// recovered, not the text of the script.
//
// Which arguments are hosts, and which are paths a command reads or writes, is
// internal/domain/capability's judgement and is reached through its exported
// extractors. The scanner does not carry a second copy of it: `scp` writing to
// its last operand unless that operand is a host, `sed` reading unless `-i`, a
// bare dotted word being a filename rather than a hostname — those have edge
// cases, and two implementations of them would put a finding and the capabilities
// panel in disagreement about the same command.
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
// extractor found nothing — so that a condition which fails closed on an
// unresolvable target still sees it. Dropping the command instead would grade
// `curl "$EXFIL_URL"` as no network reach at all.
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
		// Both directions in one pass. A rule that cares about only one of them says
		// so through its `command` list — `tee` and `rm` write, `cat` and `source`
		// read — which keeps the direction in the pack rather than in this switch.
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
		// matched-node. A schema-error quote cannot arise here: rules.Load refuses it
		// on any kind but schema-path.
		if command.Node != "" {
			return command.Node
		}
		return command.Text
	}
}
