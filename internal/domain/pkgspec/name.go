package pkgspec

import (
	"fmt"
	"regexp"
	"strings"
)

// The `name` rule, and the one place in this project where a published schema
// cannot be executed as written.
//
// Both published `name` patterns open with a negative lookahead:
//
//	^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$
//
// MEASURED: github.com/santhosh-tekuri/jsonschema/v6 compiles `pattern` with
// Go's own regexp package (compiler.go:330, `goRegexpCompile`), so RE2's lack of
// lookahead is the validator's lack of lookahead. Compiling the vendored schema
// unchanged fails at metaschema validation, not at instance validation:
//
//	"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json#" is not valid
//	against metaschema: ... at '/properties/name/pattern':
//	'^(?!.*(?:--|\\.\\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$' is not valid regex:
//	error parsing regexp: invalid or unsupported Perl syntax: `(?!`
//
// The whole schema therefore refuses to load, taking the other nine fields and
// `additionalProperties: false` with it. v6 does expose UseRegexpEngine for a
// PCRE-capable engine, but that means a new module, and a second regexp
// implementation to keep in step with the one the rest of this project uses.
//
// So: the vendored bytes stay byte-identical on disk, the lookahead is removed
// from the IN-MEMORY copy at compile time (see embed.go), and the `--`/`..`
// prohibition it expressed is enforced by CheckName below and reported against
// the same schema path a validator would have used. The transform is exact and
// fails closed: a vendored pattern that is not the string below is a load-time
// error rather than a silently dropped rule.

const (
	// lookaheadNamePattern is the published pattern, verbatim, as it appears in
	// both vendored plugin schemas.
	lookaheadNamePattern = `^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`

	// re2NamePattern is what survives once the lookahead is lifted out. It is the
	// same language minus the `--`/`..` prohibition, which CheckName re-applies.
	re2NamePattern = `^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`

	// NameMaxLength is the published maxLength on `name`.
	NameMaxLength = 64

	// NameSchemaPath is where a validator would have reported a failure of the
	// pattern. CheckName's findings are reported here so a caller cannot tell the
	// re-implemented half of the rule from the schema-enforced half.
	NameSchemaPath = "/properties/name/pattern"
)

var nameRE = regexp.MustCompile(re2NamePattern)

// forbiddenNameRuns are the two sequences the lookahead excluded. Doubling a
// separator is how a name is made to look like another one — `foo--bar` and
// `foo..bar` read as `foo-bar` and `foo.bar` at a glance, and this hub keys
// package identity off the name.
var forbiddenNameRuns = []string{"--", ".."}

// CheckName applies the whole published `name` rule, including the half RE2
// cannot express. It returns Problems addressed at NameSchemaPath, so the caller
// merges them with the validator's own output without distinguishing them.
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

// ValidName reports whether name satisfies the whole rule.
func ValidName(name string) bool { return len(CheckName(name)) == 0 }
