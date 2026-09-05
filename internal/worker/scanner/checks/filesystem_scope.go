package checks

// FilesystemScope judges the paths a bundle's scripts read and write against
// what its publisher declared: an absolute path, `~`, `..`, `**` or a target
// behind a shell expansion.
func FilesystemScope() Check {
	return ruleCheck{id: "filesystem-scope", label: "Filesystem scope"}
}
