package checks

// ShellAudit reads what the scripts in a bundle do, structurally. The
// network and filesystem checks are conditions over these same parsed
// commands, so an unparseable script is a warning here, not silently ignored.
func ShellAudit() Check {
	return ruleCheck{
		id:         "shell-audit",
		label:      "Shell command audit",
		blindSpots: func(b *Bundle) int { return len(b.Unparsed) },
	}
}
