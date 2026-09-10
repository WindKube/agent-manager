package checks

// NetworkAllowlist compares every host the bytes name against the version's
// declared capability set.
func NetworkAllowlist() Check {
	return ruleCheck{
		id:    "network-allowlist",
		label: "Network allowlist",
		explain: "Compares every host a script or an instruction file names — via curl, wget, " +
			"scp and similar commands, or a bare URL in prose — against the version's declared " +
			"network capability set, and flags one outside it. Where nothing was declared, or " +
			"where a host is hidden behind a shell expansion this analysis cannot resolve, " +
			"every host is flagged rather than silently passed.",
	}
}
