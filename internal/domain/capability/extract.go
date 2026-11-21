package capability

// These export Infer's judgements so the scanner's rule engine doesn't carry
// a divergent copy.

// HostOf returns "" when the token names no host. Expansions are returned
// verbatim, never resolved.
func HostOf(token string) string { return hostOf(token) }

// CommandTargets returns the paths one command reads or writes, redirections
// included.
func CommandTargets(c Command, write bool) []string { return filesystemTargets(&c, write) }

// InsidePackage is false for absolute, `~`-relative and `..`-escaping paths.
func InsidePackage(target string) bool { return insideTree(target) }

// Indefinite reports whether a token carries a shell expansion or template
// placeholder.
func Indefinite(token string) bool { return isDynamic(token) }

func Sensitive(target string) bool { return sensitivePath(target) }

// OverBroad reports a recursive glob or a glob at an absolute root.
func OverBroad(target string) bool { return overBroad(target) }
