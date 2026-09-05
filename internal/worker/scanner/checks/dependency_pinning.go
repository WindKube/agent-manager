package checks

// DependencyPinning judges dependency specifiers, not dependency names: an
// unpinned specifier like `^6.0.0` resolves at install time to whatever the
// registry serves, so the scan verdict on this version says nothing about the
// tree that will actually run.
func DependencyPinning() Check {
	return ruleCheck{id: "dependency-pinning", label: "Dependency pinning"}
}
