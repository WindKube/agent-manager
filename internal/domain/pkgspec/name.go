package pkgspec

import (
	"fmt"
	"regexp"
	"strings"
)

// The published `name` patterns open with a negative lookahead that RE2
// cannot parse, failing the whole schema at load time. So the vendored bytes
// stay byte-identical on disk, the lookahead is stripped from the in-memory
// copy at compile time (embed.go), and the `--`/`..` prohibition it
// expressed is re-applied here by CheckName. The transform fails closed: a
// vendored pattern that is not the string below is a load-time error.

const (
	// lookaheadNamePattern is the published pattern, verbatim.
	lookaheadNamePattern = `^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`
	re2NamePattern       = `^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`
	NameMaxLength        = 64

	// NameSchemaPath is where a validator would have reported a pattern
	// failure, so CheckName's findings can't be told apart from the schema-enforced half.
	NameSchemaPath = "/properties/name/pattern"
)

var nameRE = regexp.MustCompile(re2NamePattern)

// forbiddenNameRuns are the two sequences the lookahead excluded: doubling a
// separator makes a name look like another — `foo--bar`/`foo..bar` read as
// `foo-bar`/`foo.bar` at a glance, and this hub keys identity off the name.
var forbiddenNameRuns = []string{"--", ".."}

func CheckName(name string) []Problem {
	var problems []Problem
	add := func(format string, args ...any) {
		problems = append(problems, Problem{
			SchemaPath:   NameSchemaPath,
			InstancePath: "/name",
			Message:      fmt.Sprintf(format, args...),
		})
	}

	switch {
	case name == "":
		add("name is empty")
		return problems
	case len(name) > NameMaxLength:
		add("name is %d bytes, over the published maxLength of %d", len(name), NameMaxLength)
	}
	if !nameRE.MatchString(name) {
		add("name %q does not match %s", name, re2NamePattern)
	}
	for _, run := range forbiddenNameRuns {
		if strings.Contains(name, run) {
			add("name %q contains %q, which the published pattern's negative lookahead forbids", name, run)
		}
	}
	return problems
}

func ValidName(name string) bool { return len(CheckName(name)) == 0 }
