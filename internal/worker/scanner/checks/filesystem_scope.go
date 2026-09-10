package checks

// FilesystemScope judges the paths a bundle's scripts read and write against
// what its publisher declared.
func FilesystemScope() Check {
	return ruleCheck{
		id:    "filesystem-scope",
		label: "Filesystem scope",
		explain: "Judges the paths a script's file-touching commands (`tee`, `rm`, `mkdir`, " +
			"`chmod`, `chown`, `cp`, `mv`, `sed` and similar) read or write against the " +
			"version's declared filesystem scope. Writing inside the package's own directory " +
			"is not reported; what is flagged is a target that leaves it and that the " +
			"declaration does not cover — an absolute path, `~`, a `..` that climbs out, a " +
			"glob, or a target behind a shell expansion this analysis cannot resolve.",
	}
}
