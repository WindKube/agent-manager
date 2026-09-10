package capability

// Artefacts is SYNTAX: everything in it is something a parser or directory
// walk can produce without knowing what it means. What a command MEANS —
// that `curl` reaches the network, that `~/.aws/credentials` is sensitive —
// is this package's job and lives nowhere else. This split exists because
// the scanner may never execute a bundle, so a command's effect can only be
// read off its shape.
//
// The manifest is deliberately absent here: capabilities come from the
// bytes, and a function that could see the declaration might agree with it.
type Artefacts struct {
	Files []File
	// Commands: a file with no commands contributes none, and no commands
	// at all means no `shell` capability rather than one at level zero.
	Commands []Command
	// URLs is every absolute URL found in an instruction file: an
	// instruction telling an agent to fetch something is network reach
	// just as much as a `curl` is.
	URLs []URL
}

// Class is decided by path and extension, never by content sniffing.
type Class string

const (
	ClassManifest    Class = "manifest"
	ClassInstruction Class = "instruction"
	ClassScript      Class = "script"
	ClassOther       Class = "other"
)

type File struct {
	Path  string
	Class Class
}

// Command: Name is the command word with no path (`curl`, not
// `/usr/bin/curl`), and Args have quoting removed but expansions NOT
// resolved — `$HOST` arrives as the four characters, since resolving it
// would mean evaluating the script. An unresolved expansion is what makes a
// target indefinite, and that's information, not a gap.
type Command struct {
	File      string
	Line      int
	Name      string
	Args      []string
	Redirects []Redirect
}

type Redirect struct {
	Path string
	// Write is true for `>` and `>>`, false for `<` and here-strings.
	Write bool
}

type URL struct {
	File string
	Line int
	Raw  string
}
