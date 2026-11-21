package capability

// Artefacts is pure syntax a parser can produce; what a command means is
// decided only in this package. The manifest is deliberately absent so
// inference cannot be swayed by the declaration.
type Artefacts struct {
	Files    []File
	Commands []Command
	// URLs found in instruction files count as network reach like `curl`.
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

// Command has Name without a path and Args unquoted but with expansions left
// unresolved; an unresolved expansion is what makes a target indefinite.
type Command struct {
	File      string
	Line      int
	Name      string
	Args      []string
	Redirects []Redirect
}

type Redirect struct {
	Path  string
	Write bool
}

type URL struct {
	File string
	Line int
	Raw  string
}
