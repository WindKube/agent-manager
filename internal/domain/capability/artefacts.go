package capability

// The scanner's side of the boundary (T056, filled by T066).
//
// Artefacts is SYNTAX. Everything in it is something a parser or a directory
// walk can produce without knowing what any of it means: the files that survived
// the spec-layout filter, the commands a shell AST yielded, the URLs a scan of
// the instruction files found. What a command MEANS — that `curl` reaches the
// network, that `~/.aws/credentials` is sensitive, that `**` is over-broad —
// is this package's job and lives nowhere else.
//
// The split matters because of FR-021 and FR-026. The scanner may never execute
// a bundle, so a command's effect can only ever be read off its shape; and the
// shell audit must parse rather than match text, so the shape has to arrive here
// already parsed. A scanner that decided what a command meant would put the
// judgement in the package that also does the I/O, where it cannot be tested
// without one.

// Artefacts is everything Infer reads. The manifest is deliberately absent: the
// R1 inversion is that capabilities come from the bytes, and a function that
// could see the declaration might come to agree with it.
type Artefacts struct {
	// Files is the tree as the extractor kept it, one entry per file.
	Files []File
	// Commands is every command the shell parser found, in the order it found
	// them. A file with no commands contributes none, and no commands at all means
	// no `shell` capability rather than a `shell` capability at level zero.
	Commands []Command
	// URLs is every absolute URL found in an instruction file — SKILL.md, the
	// files under references/, a plugin's prose. FR-018 names them alongside the
	// shell AST because an instruction telling an agent to fetch something is
	// network reach just as much as a `curl` is.
	URLs []URL
}

// Class is what kind of file the walk decided this is. It is decided by path and
// extension, never by content sniffing.
type Class string

const (
	// ClassManifest is plugin.json, SKILL.md's frontmatter or mcp.json.
	ClassManifest Class = "manifest"
	// ClassInstruction is prose an agent reads: SKILL.md bodies, references/.
	ClassInstruction Class = "instruction"
	// ClassScript is something a shell would run.
	ClassScript Class = "script"
	// ClassOther is everything else the layout kept.
	ClassOther Class = "other"
)

// File is one file the extractor kept, at its path inside the package root.
type File struct {
	Path  string
	Class Class
}

// Command is one command as the shell AST gave it up.
//
// Name is the command word with no path — `curl`, not `/usr/bin/curl` — and Args
// are its arguments with quoting removed but expansions NOT resolved: `$HOST`
// arrives as the four characters, because resolving it would mean evaluating the
// script, which FR-021 forbids outright. An unresolved expansion is what makes a
// target indefinite, and that is information, not a gap.
type Command struct {
	File string
	Line int
	Name string
	Args []string
	// Redirects are the `<`, `>` and `>>` targets attached to this command.
	Redirects []Redirect
}

// Redirect is one redirection target and its direction.
type Redirect struct {
	Path string
	// Write is true for `>` and `>>`, false for `<` and here-strings.
	Write bool
}

// URL is one absolute URL found in an instruction file.
type URL struct {
	File string
	Line int
	Raw  string
}
