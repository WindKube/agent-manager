package checks

// NetworkAllowlist compares every host the bytes name against the version's
// EXPECTED capability set: inferred-versus-expected rather than
// manifest-versus-behaviour, since a self-declared allowlist proves nothing.
func NetworkAllowlist() Check {
	return ruleCheck{id: "network-allowlist", label: "Network allowlist"}
}
