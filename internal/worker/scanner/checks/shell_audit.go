package checks

// ShellAudit reads what the scripts in a bundle do, structurally (FR-026).
//
// This is the load-bearing check: the network and filesystem rules are conditions
// over the same parsed commands, so a script this check cannot read is a hole
// under three checks rather than one. That is why an unparseable script is counted
// as a warning here rather than ignored — a blind spot reported as `pass` is the
// single most dangerous output this system could produce, and the file a payload
// would most like to be in is the one the parser choked on.
func ShellAudit() Check {
	return ruleCheck{
		id:         "shell-audit",
		label:      "Shell command audit",
		blindSpots: func(b *Bundle) int { return len(b.Unparsed) },
	}
}
