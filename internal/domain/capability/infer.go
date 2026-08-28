package capability

import (
	"net/url"
	"path"
	"strings"
)

// Infer is T056: the capability set a version demands, read off the scan
// artefacts and nothing else (FR-018).
//
// A capability appears only when something in the bytes puts it there. An empty
// result is a package that does not reach the network, does not touch the
// filesystem outside what it ships, and runs no commands — and that is a real
// answer, not a missing one. The caller distinguishes "inferred nothing" from
// "never scanned" by whether a scan row exists, never by the length of this
// slice.
func Infer(a Artefacts) []Capability {
	rows := make([]Capability, 0, len(Names))
	for _, build := range []func(Artefacts) (Capability, bool){
		inferNetwork, inferFilesystemRead, inferFilesystemWrite, inferShell,
	} {
		if row, ok := build(a); ok {
			rows = append(rows, finish(row))
		}
	}
	return order(rows)
}

// ---- network -----------------------------------------------------------------

// transferCommands are the commands whose entire purpose is moving bytes over a
// network. One of these with no resolvable host still means network reach, which
// is why the set exists separately from "an argument happened to be a URL".
var transferCommands = map[string]struct{}{
	"curl": {}, "wget": {}, "http": {}, "https": {}, "httpie": {}, "xh": {},
	"nc": {}, "ncat": {}, "netcat": {}, "telnet": {}, "ftp": {}, "sftp": {},
	"ssh": {}, "scp": {}, "rsync": {}, "git": {},
}

// registryCommands reach a default registry when no host is written down. They
// are network reach with an INDEFINITE target rather than no target: `npm i -g
// @octoflow/notes-cli` talks to registry.npmjs.org, which appears nowhere in the
// command. Recording them as a definite empty set would be a network capability
// that reads as reaching nothing.
var registryCommands = map[string]struct{}{
	"npm": {}, "npx": {}, "pnpm": {}, "yarn": {}, "bun": {},
	"pip": {}, "pip3": {}, "pipx": {}, "uv": {}, "poetry": {},
	"gem": {}, "bundle": {}, "cargo": {}, "go": {}, "brew": {},
	"apt": {}, "apt-get": {}, "apk": {}, "dnf": {}, "yum": {},
	"docker": {}, "helm": {}, "kubectl": {}, "terraform": {},
	"aws": {}, "gcloud": {}, "az": {}, "gh": {},
}

// inferNetwork collects every host the bytes name, from the shell AST and from
// the URLs in instruction files (FR-018).
//
// A network capability is never Scoped, and that is not a threshold that
// happened not to be reached: Scoped means the target stays inside the package,
// and a host is outside it by definition. The two levels available are
// Allowlisted — a definite list a reviewer can accept once — and Review.
func inferNetwork(a Artefacts) (Capability, bool) {
	row := Capability{Name: Network, Source: SourceInferred, Level: LevelAllowlisted}
	found := false

	record := func(host string) {
		found = true
		switch {
		case host == "":
			row.Indefinite = true
		case isDynamic(host):
			// The host is behind an expansion, so the script reaches somewhere this
			// analysis cannot name. FR-021 forbids resolving it by running anything.
			row.Indefinite = true
			row.Level = LevelReview
		default:
			row.Detail = append(row.Detail, host)
			if sensitiveHost(host) {
				row.Level = LevelReview
			}
		}
	}

	for _, ref := range a.URLs {
		if host := hostOf(ref.Raw); host != "" {
			record(host)
		}
	}

	for i := range a.Commands {
		command := &a.Commands[i]
		hosts := commandHosts(command)
		for _, host := range hosts {
			record(host)
		}
		if len(hosts) > 0 {
			continue
		}
		_, transfer := transferCommands[command.Name]
		_, registry := registryCommands[command.Name]
		if transfer || registry {
			record("")
		}
	}

	if !found {
		return Capability{}, false
	}
	return row, true
}

// commandHosts pulls every host out of one command's arguments. Arguments are
// read as URLs, as `host:port`, and as scp's `user@host:path` — the three shapes
// a host actually appears in on a command line.
func commandHosts(c *Command) []string {
	hosts := make([]string, 0, 2)
	for _, arg := range c.Args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if host := hostOf(arg); host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// hostOf reads a host out of one token, or returns "" when the token names none.
//
// A host must be EXPLICIT: written with a scheme, with a `user@`, or with a
// `:port`. A bare dotted word is never one. That rule costs a little — `curl
// example.dev/x` yields no host here — and it is still the right one, because a
// bare dotted word is also what every filename looks like: `scp report.txt
// deploy@files.example.dev:/srv/` has exactly one host in it, and a rule loose
// enough to find `report.txt` would put filenames in the network panel of every
// package in the catalog. Nothing is lost by refusing to guess, because a
// transfer command whose host this cannot name records an INDEFINITE target
// instead, which grades Review — so the miss fails closed and stays visible.
//
// It never resolves anything either: an expansion is returned verbatim so the
// caller can see it is dynamic. Resolving one would mean running the script,
// which FR-021 forbids.
func hostOf(token string) string {
	token = strings.Trim(token, `"'`)
	if token == "" {
		return ""
	}

	if strings.Contains(token, "://") {
		parsed, err := url.Parse(token)
		if err != nil || parsed.Host == "" {
			// A URL-shaped token this cannot parse still names a host somewhere; say
			// so rather than dropping it, and let the caller mark it indefinite.
			return strings.TrimSpace(strings.SplitN(strings.TrimPrefix(token, "//"), "/", 2)[0])
		}
		return parsed.Hostname()
	}

	// scp and ssh: user@host:path, or user@host.
	if at := strings.LastIndex(token, "@"); at >= 0 {
		rest := token[at+1:]
		rest, _, _ = strings.Cut(rest, ":")
		if looksLikeHost(rest) {
			return rest
		}
		return ""
	}

	// host:port, but not a Windows drive or a time.
	if host, port, ok := strings.Cut(token, ":"); ok && isDigits(port) && looksLikeHost(host) {
		return host
	}
	return ""
}

// looksLikeHost validates a token that its CONTEXT has already said is a host —
// the part after an `@`, or the part before a `:port`. It is not a test for
// whether an arbitrary word is a hostname; see hostOf for why there is no such
// test here.
func looksLikeHost(token string) bool {
	if isDynamic(token) {
		return true
	}
	if token == "" || strings.ContainsAny(token, "/\\ \t") {
		return false
	}
	labels := strings.Split(token, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
		for _, r := range label {
			if r != '-' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	if isDigits(last) {
		// All-numeric last label: an IPv4 literal. It is a host, and a numeric one
		// is exactly the shape a metadata endpoint takes.
		return isDigits(strings.Join(labels, ""))
	}
	return true
}

// sensitiveHosts are the destinations that make a network capability a Review
// whatever else the list contains: the cloud metadata endpoints, which are the
// canonical SSRF and credential-theft targets, and loopback, which in a package
// that is supposed to be portable means it expects something local to be
// listening. internal/fetch refuses to CONNECT to these; this is the static half.
var sensitiveHosts = map[string]struct{}{
	"169.254.169.254": {}, "metadata.google.internal": {}, "metadata.goog": {},
	"localhost": {}, "127.0.0.1": {}, "0.0.0.0": {}, "::1": {},
}

func sensitiveHost(host string) bool {
	_, sensitive := sensitiveHosts[strings.ToLower(host)]
	return sensitive
}

// ---- filesystem ---------------------------------------------------------------

// readCommands read their path-shaped arguments.
var readCommands = map[string]struct{}{
	"cat": {}, "head": {}, "tail": {}, "less": {}, "more": {}, "grep": {},
	"egrep": {}, "fgrep": {}, "rg": {}, "awk": {}, "wc": {}, "sort": {},
	"uniq": {}, "diff": {}, "cut": {}, "md5sum": {}, "sha256sum": {},
	"shasum": {}, "source": {}, ".": {}, "jq": {}, "yq": {}, "stat": {},
	"file": {}, "openssl": {},
}

// writeCommands write their path-shaped arguments.
var writeCommands = map[string]struct{}{
	"tee": {}, "rm": {}, "rmdir": {}, "mkdir": {}, "touch": {}, "truncate": {},
	"chmod": {}, "chown": {}, "ln": {}, "unlink": {}, "shred": {}, "dd": {},
}

// transferPairCommands read every path argument but the last and write the last.
// `cp a b`, `mv a b`, `install -m 0644 src dst`, `rsync src dst`.
var transferPairCommands = map[string]struct{}{
	"cp": {}, "mv": {}, "install": {}, "rsync": {}, "scp": {},
}

// sedInPlace is the one command whose direction depends on a flag: `sed` reads,
// `sed -i` writes. Special-casing it is cheaper than pretending it does not
// exist, and it is common enough in postinstall scripts to matter.
const sedInPlace = "-i"

func inferFilesystemRead(a Artefacts) (Capability, bool) {
	return inferFilesystem(a, FilesystemRead)
}

func inferFilesystemWrite(a Artefacts) (Capability, bool) {
	return inferFilesystem(a, FilesystemWrite)
}

// inferFilesystem collects the read or write targets and grades them.
//
// The grading is the whole content of FR-018's "filesystem scope from read and
// write targets": Scoped means every target stays inside the package, so a
// reviewer has nothing outside the bundle to think about; Allowlisted means a
// definite set of outside paths; Review means the set is not definite at all —
// an expansion, a `..`, a `**`, or somewhere whose name is the reason the check
// exists.
func inferFilesystem(a Artefacts, name string) (Capability, bool) {
	write := name == FilesystemWrite
	row := Capability{Name: name, Source: SourceInferred, Level: LevelScoped}
	found := false

	record := func(target string) {
		if target == "" {
			return
		}
		found = true
		switch {
		case isDynamic(target):
			row.Indefinite = true
			row.Level = LevelReview
		case sensitivePath(target), overBroad(target), escapesTree(target):
			row.Detail = append(row.Detail, target)
			row.Level = LevelReview
		case insideTree(target):
			row.Detail = append(row.Detail, target)
		default:
			row.Detail = append(row.Detail, target)
			row.Level = stricter(row.Level, LevelAllowlisted)
		}
	}

	for i := range a.Commands {
		for _, target := range filesystemTargets(&a.Commands[i], write) {
			record(target)
		}
	}

	if !found {
		return Capability{}, false
	}
	return row, true
}

// filesystemTargets is the syntax-to-effect step: which of a command's arguments
// and redirections are paths it reads, or paths it writes.
func filesystemTargets(c *Command, write bool) []string {
	targets := make([]string, 0, 2)

	for _, redirect := range c.Redirects {
		if redirect.Write == write {
			targets = append(targets, redirect.Path)
		}
	}

	if isPair(c.Name) {
		return append(targets, pairTargets(c.Args, write)...)
	}

	paths := pathArgs(c.Args, expressionCommands[c.Name])
	switch {
	case len(paths) == 0:
		return targets

	case c.Name == "sed":
		if write == containsArg(c.Args, sedInPlace) {
			targets = append(targets, paths...)
		}
		return targets
	}

	set := readCommands
	if write {
		set = writeCommands
	}
	if _, ok := set[c.Name]; ok {
		targets = append(targets, paths...)
	}
	return targets
}

func isPair(name string) bool {
	_, ok := transferPairCommands[name]
	return ok
}

// pairTargets splits `cp a b` into the source it reads and the destination it
// writes.
//
// The split is taken over the ARGUMENT positions, not over the filtered path
// list, because the destination is defined by where it sits and may not be a
// local path at all: `scp report.txt deploy@host:/srv/` has a source and no
// local destination, and picking the last surviving path would file the source
// itself as the thing being written.
func pairTargets(args []string, write bool) []string {
	operands := make([]string, 0, len(args))
	for _, arg := range args {
		arg = strings.Trim(arg, `"'`)
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		operands = append(operands, arg)
	}
	if len(operands) < 2 {
		return nil
	}

	last := operands[len(operands)-1]
	if write {
		if hostOf(last) != "" || !isPathish(last) {
			return nil
		}
		return []string{last}
	}

	sources := make([]string, 0, len(operands)-1)
	for _, operand := range operands[:len(operands)-1] {
		if hostOf(operand) == "" && isPathish(operand) {
			sources = append(sources, operand)
		}
	}
	return sources
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

// expressionCommands take a program or a pattern as their first non-flag
// argument, and it is not a path however much it looks like one. `sed s/a/b/
// notes.md` reads one file; without this, the substitution expression is a
// second target, and `s/a/b/` renders in the panel as a path the package
// touches.
var expressionCommands = map[string]bool{
	"sed": true, "awk": true, "perl": true,
	"grep": true, "egrep": true, "fgrep": true, "rg": true,
}

// pathArgs keeps the arguments that are paths. A flag is not a path, and neither
// is a bare word: `grep TODO src/notes.md` reads one file, not two.
func pathArgs(args []string, skipFirst bool) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		arg = strings.Trim(arg, `"'`)
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		if skipFirst {
			skipFirst = false
			continue
		}
		// A token that names a host is a network target, not a filesystem one.
		// `scp report.txt deploy@files.example.dev:/srv/drop/` writes to a machine,
		// and filing `/srv/drop/` as a local write scope would describe the wrong
		// risk on the wrong panel.
		if hostOf(arg) != "" {
			continue
		}
		if isPathish(arg) {
			out = append(out, arg)
		}
	}
	return out
}

func isPathish(arg string) bool {
	switch {
	case isDynamic(arg):
		return strings.ContainsAny(arg, "/~.")
	case strings.HasPrefix(arg, "/"), strings.HasPrefix(arg, "~"), strings.HasPrefix(arg, "./"),
		strings.HasPrefix(arg, "../"), strings.Contains(arg, "/"):
		return true
	default:
		// A bare `notes.md` is a path; a bare `TODO` is a pattern. The dot is the
		// only signal available, and guessing wider would make every grep pattern a
		// filesystem target.
		return strings.Contains(strings.TrimPrefix(arg, "."), ".")
	}
}

// sensitiveFragments are the paths whose presence is the reason a filesystem
// check exists at all: credentials, keys and the machine's own configuration.
// The design's f2 finding — a SKILL.md instructing the agent to read ~/.pgpass
// and ~/.aws/credentials — is exactly this list doing its job.
var sensitiveFragments = []string{
	"/.ssh", "/.aws", "/.gnupg", "/.kube", "/.docker", "/.netrc", "/.npmrc",
	"/.pypirc", "/.gitconfig", "/.git-credentials", "/.pgpass", "/.env",
	"id_rsa", "id_ed25519", "credentials", "secret", "token", "password",
	"/etc/", "/proc/", "/sys/", "/var/", "/root",
}

func sensitivePath(target string) bool {
	lowered := strings.ToLower(target)
	// A leading ~ and a leading . are the same claim about the same file, so both
	// are normalised to the fragment shape the list is written in.
	if strings.HasPrefix(lowered, ".") && !strings.HasPrefix(lowered, "./") &&
		!strings.HasPrefix(lowered, "../") {
		lowered = "/" + lowered
	}
	lowered = strings.TrimPrefix(lowered, "~")
	for _, fragment := range sensitiveFragments {
		if strings.Contains(lowered, fragment) {
			return true
		}
	}
	return false
}

// overBroad is the design's f4 finding: a write scope of `**` where a report
// directory would do. A recursive glob, or a glob at the root of an absolute
// path, names a set nobody can enumerate by reading the script.
func overBroad(target string) bool {
	if strings.Contains(target, "**") {
		return true
	}
	if !strings.ContainsAny(target, "*?[") {
		return false
	}
	// A glob confined to one directory is still definite enough to grade on its
	// location; a glob that starts the path is not.
	first := strings.SplitN(strings.TrimPrefix(target, "/"), "/", 2)[0]
	return strings.ContainsAny(first, "*?[") || strings.HasPrefix(target, "/")
}

// escapesTree is a relative path that climbs out of the package root. It is
// separated from insideTree so the level can say WHY: a `..` is not merely
// outside, it is outside by way of a route the extractor refuses in an archive
// member (internal/bundle) and that a script should not be taking either.
func escapesTree(target string) bool {
	if strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~") {
		return false
	}
	cleaned := path.Clean(target)
	return cleaned == ".." || strings.HasPrefix(cleaned, "../")
}

// insideTree is a relative path that stays under the package root. It does NOT
// require the file to exist in Artefacts.Files: a script legitimately writes an
// output file the bundle does not ship, and requiring the walk to have seen it
// would grade every generated file as reaching outside the package.
func insideTree(target string) bool {
	if strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~") {
		return false
	}
	return !escapesTree(target)
}

// ---- shell --------------------------------------------------------------------

// inferShell is FR-018's floor, and the reason it reads as a floor rather than
// as a grade: whatever the commands are, a package that runs a shell can run
// anything the shell can, so the level is Review and there is no analysis that
// could lower it. finish applies it a second time, so a future edit here cannot
// quietly drop below Review either.
func inferShell(a Artefacts) (Capability, bool) {
	if len(a.Commands) == 0 && !hasScript(a) {
		return Capability{}, false
	}

	row := Capability{Name: Shell, Source: SourceInferred, Level: LevelReview}
	for i := range a.Commands {
		row.Detail = append(row.Detail, a.Commands[i].Name)
	}
	return row, true
}

// hasScript covers the case the AST cannot: a script the parser produced no
// commands from — because it is empty, or because it failed to parse — is still a
// script, and reporting no shell capability for it would be the analysis grading
// its own blind spot as clean.
func hasScript(a Artefacts) bool {
	for _, file := range a.Files {
		if file.Class == ClassScript {
			return true
		}
	}
	return false
}

// isDynamic reports whether a token carries a shell expansion or a template
// placeholder, and therefore names something only a running shell would know.
func isDynamic(token string) bool {
	return strings.ContainsAny(token, "$`") || strings.Contains(token, "{{")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
