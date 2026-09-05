package checks

// NetworkAllowlist compares every host the bytes name against the version's
// EXPECTED capability set and flags anything outside it. The comparison is
// inferred-versus-expected rather than manifest-versus-behaviour: a
// self-declared allowlist is worthless as security, since whoever writes the
// payload writes the manifest. Where no expected set was recorded, every
// discovered host is surfaced rather than silently accepted, or "declare
// nothing" would be the way to pass this check.
//
// Hosts come from two places, and both are network reach: the shell AST, and
// the URLs in instruction files — an instruction telling an agent to POST
// somewhere reaches that host just as surely as a `curl` does.
func NetworkAllowlist() Check {
	return ruleCheck{id: "network-allowlist", label: "Network allowlist"}
}
