package checks

// FilesystemScope judges the paths a bundle's scripts read and write against what
// its publisher declared (FR-018, FR-022).
//
// Writing inside its own tree is not a finding, and that exemption is what makes
// the check usable: a package that writes a build output or a cache under its own
// directory is doing what packages do, and flagging it would train reviewers to
// dismiss this check. What is left is the interesting set — an absolute path, a
// `~`-rooted one, a `..` that climbs out, a `**` nobody can enumerate, or a target
// behind an expansion that only a running shell would resolve.
func FilesystemScope() Check {
	return ruleCheck{id: "filesystem-scope", label: "Filesystem scope"}
}
