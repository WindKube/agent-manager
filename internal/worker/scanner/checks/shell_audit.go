package checks

// ShellAudit reads what the scripts in a bundle do, structurally.
func ShellAudit() Check {
	return ruleCheck{
		id:    "shell-audit",
		label: "Shell command audit",
		explain: "Flags `eval`, `source` and `.` running text built at run time — from a " +
			"command substitution, a variable or a downloaded file — rather than text shipped " +
			"in the bundle. This is the pattern behind a `curl | bash` install: the archive " +
			"passes review because the payload is not in it yet. A script this analysis could " +
			"not parse is reported as a warning here, never silently skipped.",
		blindSpots: func(b *Bundle) int { return len(b.Unparsed) },
	}
}
