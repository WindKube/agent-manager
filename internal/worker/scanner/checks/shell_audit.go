package checks

// ShellAudit reads what the scripts in a bundle do, structurally. This is the
// load-bearing check: the network and filesystem rules are conditions over the
// same parsed commands, so a script this check cannot read is a hole under
// three checks rather than one — which is why an unparseable script is a
// warning here rather than silently ignored.
func ShellAudit() Check {
	return ruleCheck{
		id:         "shell-audit",
		label:      "Shell command audit",
		blindSpots: func(b *Bundle) int { return len(b.Unparsed) },
	}
}
