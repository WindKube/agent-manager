package capability

// These wrap the unexported judgements Infer already applies, exported so
// the rule engine in internal/worker/scanner/checks doesn't carry a second,
// divergent copy of security judgements like "which token names a host".

// HostOf returns "" when the token names no host. An expansion is returned
// verbatim rather than resolved, since resolving it would mean running the
// script.
func HostOf(token string) string { return hostOf(token) }

// CommandTargets is the filesystem paths one command reads (write false) or
// writes (write true), including its redirection targets.
func CommandTargets(c Command, write bool) []string { return filesystemTargets(&c, write) }

// InsidePackage: absolute paths, `~`-relative paths and anything that
// climbs out with `..` are not.
func InsidePackage(target string) bool { return insideTree(target) }

// Indefinite reports whether a token carries a shell expansion or template
// placeholder, naming something only a running shell would know.
func Indefinite(token string) bool { return isDynamic(token) }

func Sensitive(target string) bool { return sensitivePath(target) }

// OverBroad reports whether a target names a set nobody can enumerate by
// reading the script — a recursive glob, or a glob at an absolute root.
func OverBroad(target string) bool { return overBroad(target) }
