package capability

import (
	"net/url"
	"path"
	"strings"
)

// Infer derives capabilities from the scan artefacts alone; an empty result
// means the package reaches nothing, not that the scan is missing.
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

// transferCommands count as network reach even with no resolvable host.
var transferCommands = map[string]struct{}{
	"curl": {}, "wget": {}, "http": {}, "https": {}, "httpie": {}, "xh": {},
	"nc": {}, "ncat": {}, "netcat": {}, "telnet": {}, "ftp": {}, "sftp": {},
	"ssh": {}, "scp": {}, "rsync": {}, "git": {},
}

// registryCommands reach a default registry with no host written down, so
// they are network reach with an indefinite target.
var registryCommands = map[string]struct{}{
	"npm": {}, "npx": {}, "pnpm": {}, "yarn": {}, "bun": {},
	"pip": {}, "pip3": {}, "pipx": {}, "uv": {}, "poetry": {},
	"gem": {}, "bundle": {}, "cargo": {}, "go": {}, "brew": {},
	"apt": {}, "apt-get": {}, "apk": {}, "dnf": {}, "yum": {},
	"docker": {}, "helm": {}, "kubectl": {}, "terraform": {},
	"aws": {}, "gcloud": {}, "az": {}, "gh": {},
}

// inferNetwork is never Scoped: a host is outside the package by definition.
func inferNetwork(a Artefacts) (Capability, bool) {
	row := Capability{Name: Network, Source: SourceInferred, Level: LevelAllowlisted}
	found := false

	record := func(host string) {
		found = true
		switch {
		case host == "":
			row.Indefinite = true
		case isDynamic(host):
			// Behind an expansion: reaches somewhere this can't name.
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

// commandHosts: args as URLs, `host:port`, or scp's `user@host:path`.
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

// hostOf requires an explicit host (scheme, `user@` or `:port`), since a bare
// dotted word is indistinguishable from a filename. Transfer commands with no
// nameable host still grade Review via an indefinite target.
func hostOf(token string) string {
	token = strings.Trim(token, `"'`)
	if token == "" {
		return ""
	}

	if strings.Contains(token, "://") {
		parsed, err := url.Parse(token)
		if err != nil || parsed.Host == "" {
			// Unparseable but URL-shaped: still names a host, so don't drop it.
			return strings.TrimSpace(strings.SplitN(strings.TrimPrefix(token, "//"), "/", 2)[0])
		}
		return parsed.Hostname()
	}

	if at := strings.LastIndex(token, "@"); at >= 0 { // scp/ssh: user@host[:path]
		rest := token[at+1:]
		rest, _, _ = strings.Cut(rest, ":")
		if looksLikeHost(rest) {
			return rest
		}
		return ""
	}

	if host, port, ok := strings.Cut(token, ":"); ok && isDigits(port) && looksLikeHost(host) {
		return host
	}
	return ""
}

// looksLikeHost validates a token already known by context to be a host.
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
	if isDigits(last) { // all-numeric last label: an IPv4 literal
		return isDigits(strings.Join(labels, ""))
	}
	return true
}

// sensitiveHosts force Review: cloud metadata endpoints (SSRF/credential
// theft) and loopback (a portable package shouldn't expect a local listener).
var sensitiveHosts = map[string]struct{}{
	"169.254.169.254": {}, "metadata.google.internal": {}, "metadata.goog": {},
	"localhost": {}, "127.0.0.1": {}, "0.0.0.0": {}, "::1": {},
}

func sensitiveHost(host string) bool {
	_, sensitive := sensitiveHosts[strings.ToLower(host)]
	return sensitive
}

// ---- filesystem ---------------------------------------------------------------

var readCommands = map[string]struct{}{
	"cat": {}, "head": {}, "tail": {}, "less": {}, "more": {}, "grep": {},
	"egrep": {}, "fgrep": {}, "rg": {}, "awk": {}, "wc": {}, "sort": {},
	"uniq": {}, "diff": {}, "cut": {}, "md5sum": {}, "sha256sum": {},
	"shasum": {}, "source": {}, ".": {}, "jq": {}, "yq": {}, "stat": {},
	"file": {}, "openssl": {},
}

var writeCommands = map[string]struct{}{
	"tee": {}, "rm": {}, "rmdir": {}, "mkdir": {}, "touch": {}, "truncate": {},
	"chmod": {}, "chown": {}, "ln": {}, "unlink": {}, "shred": {}, "dd": {},
}

// transferPairCommands read every path argument but the last and write the last.
var transferPairCommands = map[string]struct{}{
	"cp": {}, "mv": {}, "install": {}, "rsync": {}, "scp": {},
}

// sedInPlace: `sed` reads, `sed -i` writes.
const sedInPlace = "-i"

func inferFilesystemRead(a Artefacts) (Capability, bool) {
	return inferFilesystem(a, FilesystemRead)
}

func inferFilesystemWrite(a Artefacts) (Capability, bool) {
	return inferFilesystem(a, FilesystemWrite)
}

// inferFilesystem grades Scoped (inside the package), Allowlisted (a definite
// set of outside paths) or Review (anything indefinite).
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

// pairTargets splits over argument positions, not the filtered path list,
// because the destination may not be local (`scp file deploy@host:/srv/`).
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

// expressionCommands take a program or pattern as their first non-flag
// argument: never a path, however much it looks like one.
var expressionCommands = map[string]bool{
	"sed": true, "awk": true, "perl": true,
	"grep": true, "egrep": true, "fgrep": true, "rg": true,
}

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
		if hostOf(arg) != "" { // a host is a network target, not a filesystem one
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
		// A dot is the only signal: `notes.md` is a path, `TODO` is a pattern.
		return strings.Contains(strings.TrimPrefix(arg, "."), ".")
	}
}

// sensitiveFragments: credentials, keys and the machine's own configuration.
var sensitiveFragments = []string{
	"/.ssh", "/.aws", "/.gnupg", "/.kube", "/.docker", "/.netrc", "/.npmrc",
	"/.pypirc", "/.gitconfig", "/.git-credentials", "/.pgpass", "/.env",
	"id_rsa", "id_ed25519", "credentials", "secret", "token", "password",
	"/etc/", "/proc/", "/sys/", "/var/", "/root",
}

func sensitivePath(target string) bool {
	lowered := strings.ToLower(target)
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

// overBroad reports a recursive glob or a glob at an absolute root.
func overBroad(target string) bool {
	if strings.Contains(target, "**") {
		return true
	}
	if !strings.ContainsAny(target, "*?[") {
		return false
	}
	first := strings.SplitN(strings.TrimPrefix(target, "/"), "/", 2)[0]
	return strings.ContainsAny(first, "*?[") || strings.HasPrefix(target, "/")
}

func escapesTree(target string) bool {
	if strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~") {
		return false
	}
	cleaned := path.Clean(target)
	return cleaned == ".." || strings.HasPrefix(cleaned, "../")
}

// insideTree does not require the file to exist in Artefacts.Files, since a
// script may write output the bundle doesn't ship.
func insideTree(target string) bool {
	if strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~") {
		return false
	}
	return !escapesTree(target)
}

// ---- shell --------------------------------------------------------------------

// inferShell is always Review: a shell can run anything.
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

// hasScript counts scripts that yielded no commands, so a parse failure is
// not graded clean.
func hasScript(a Artefacts) bool {
	for _, file := range a.Files {
		if file.Class == ClassScript {
			return true
		}
	}
	return false
}

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
