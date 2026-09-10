package checks

// DependencyPinning judges dependency specifiers, not dependency names.
func DependencyPinning() Check {
	return ruleCheck{
		id:    "dependency-pinning",
		label: "Dependency pinning",
		explain: "Reads dependency specifiers in `package.json`, `requirements.txt` and " +
			"`go.mod` and flags one that does not pin to a single release. An unpinned " +
			"specifier resolves to whatever the registry serves at install time, so the bytes " +
			"a reviewer approved are not the bytes the next machine installs — the package " +
			"need not be hostile itself for that to be true.",
	}
}
