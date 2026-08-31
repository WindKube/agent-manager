package checks

// NetworkAllowlist compares every host the bytes name against the version's
// EXPECTED capability set and flags anything outside it (FR-027).
//
// The comparison is inferred-versus-expected and not manifest-versus-behaviour,
// which is research R1's inversion and a strictly better control: a self-declared
// allowlist is worthless as security, because whoever writes the payload writes
// the manifest. Where no expected set was recorded, every discovered host is
// surfaced for review rather than silently accepted — FR-027 says so explicitly,
// and the alternative would make "declare nothing" the way to pass this check.
//
// Hosts come from two places, and both are network reach: the shell AST, and the
// URLs in instruction files. An instruction telling an agent to POST somewhere
// reaches that host just as surely as a `curl` does, and it does not need a script
// in the bundle to do it.
func NetworkAllowlist() Check {
	return ruleCheck{id: "network-allowlist", label: "Network allowlist"}
}
