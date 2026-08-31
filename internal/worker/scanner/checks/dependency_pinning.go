package checks

// DependencyPinning judges dependency specifiers, not dependency names (FR-022).
//
// An unpinned specifier means the bytes a reviewer approved are not the bytes the
// next machine installs: `^6.0.0` resolves at install time to whatever the
// registry serves, so the scan verdict on this version says nothing about the tree
// that will actually run. That is the whole finding — the package need not be
// hostile itself for the resolution to be.
func DependencyPinning() Check {
	return ruleCheck{id: "dependency-pinning", label: "Dependency pinning"}
}
