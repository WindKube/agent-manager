package checks

// DependencyPinning judges dependency specifiers, not dependency names: an
// unpinned specifier resolves at install time to whatever the registry
// serves, so the verdict says nothing about the tree that will actually run.
func DependencyPinning() Check {
	return ruleCheck{id: "dependency-pinning", label: "Dependency pinning"}
}
