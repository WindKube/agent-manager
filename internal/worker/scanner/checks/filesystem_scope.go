package checks

// FilesystemScope judges the paths a bundle's scripts read and write against
// what its publisher declared. Writing inside its own tree is not a finding —
// flagging that would train reviewers to dismiss the check — so what's left is
// an absolute path, a `~`-rooted one, a `..` that climbs out, an unenumerable
// `**`, or a target behind a shell expansion.
func FilesystemScope() Check {
	return ruleCheck{id: "filesystem-scope", label: "Filesystem scope"}
}
