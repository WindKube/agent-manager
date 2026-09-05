package checks

import (
	"agent-manager/internal/domain/capability"
	"agent-manager/internal/worker/scanner/rules"
)

// matchShell is the `shell-ast` matcher: it reads the commands the parser
// recovered, not the text of the script, and judges host/path arguments
// through internal/domain/capability's own extractors.
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

// extractFromCommand yields the values a condition will judge: at least one
// per selected command, "" when the extractor found nothing, so a
// fail-closed condition still sees an unresolvable target.
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
		// matched-node; a schema-error quote cannot arise for a shell match.
		if command.Node != "" {
			return command.Node
		}
		return command.Text
	}
}
