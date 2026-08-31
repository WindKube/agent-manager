package capability

// The extraction vocabulary, exported for the scanner's rule engine.
//
// These four are wrappers over the unexported judgements Infer already applies,
// and they exist so that the rule engine in internal/worker/scanner/checks does
// not carry a second copy of them. That duplication is the failure worth avoiding
// here: "which token names a host", "which argument is a path this command
// writes" and "does this path stay inside the package" are security judgements
// with edge cases (a bare dotted word is a filename, `scp` writes to its last
// operand unless that operand is a host, a `..` is not merely outside), and two
// implementations of them would disagree the first time one is tuned — with the
// panel and the finding then describing different behaviour of the same bundle.
//
// The scanner needs them separately from Infer because a Capability carries no
// evidence: the panel reads levels and target lists, a finding has to quote a file
// and a line (FR-024), and only the per-command extraction can produce both from
// the same pass.

// HostOf returns the host a command-line token names, or "" when it names none.
// An expansion is returned verbatim rather than resolved — resolving it would
// mean running the script, which FR-021 forbids outright.
func HostOf(token string) string { return hostOf(token) }

// CommandTargets is the filesystem paths one command reads (write false) or
// writes (write true), including its redirection targets.
func CommandTargets(c Command, write bool) []string { return filesystemTargets(&c, write) }

// InsidePackage reports whether a path stays under the package root. Absolute
// paths, `~`-relative paths and anything that climbs out with `..` do not.
func InsidePackage(target string) bool { return insideTree(target) }

// Indefinite reports whether a token carries a shell expansion or a template
// placeholder, and therefore names something only a running shell would know.
func Indefinite(token string) bool { return isDynamic(token) }

// Sensitive reports whether a path is one of the credential, key and
// machine-configuration locations that are the reason the filesystem checks
// exist.
func Sensitive(target string) bool { return sensitivePath(target) }

// OverBroad reports whether a target names a set nobody can enumerate by reading
// the script — a recursive glob, or a glob at the root of an absolute path.
func OverBroad(target string) bool { return overBroad(target) }
