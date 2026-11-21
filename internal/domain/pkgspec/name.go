package pkgspec

import (
	"fmt"
	"regexp"
	"strings"
)

// The published `name` pattern has a negative lookahead RE2 cannot parse, so
// embed.go strips it from the in-memory schema and CheckName re-applies the
// `--`/`..` prohibition. A vendored pattern that differs fails at load.

const (
	// lookaheadNamePattern is the published pattern, verbatim.
	lookaheadNamePattern = `^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`
	re2NamePattern       = `^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`
	NameMaxLength        = 64

	// NameSchemaPath makes CheckName's findings indistinguishable from the
	// schema-enforced half.
	NameSchemaPath = "/properties/name/pattern"
)

var nameRE = regexp.MustCompile(re2NamePattern)

// forbiddenNameRuns are excluded because `foo--bar` reads as `foo-bar` at a
// glance, and identity is keyed off the name.
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
