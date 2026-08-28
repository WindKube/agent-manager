package web_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tailwind v4's `@source` directives are ADDITIVE to its automatic content
// detection, which walks the whole repository. Left on, the shipped stylesheet
// becomes a function of every file in the module: the word "collapse" in a Go
// comment under internal/domain and "shrink" in one under internal/fetch each
// added a utility rule, which failed `task gen:check` on a branch that had not
// touched internal/web at all. All 31 utilities harvested that way were false
// positives — every class attribute in this design is a hand-written am-* one.
//
// Both halves are asserted, because either alone is defeatable: source(none)
// without scoped @source globs would drop the templ files that legitimately hold
// the class attributes, and scoped globs without source(none) is the bug.
func TestTheStylesheetIsAFunctionOfTheWebTreeAlone(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "assets", "input.css"))
	require.NoError(t, err)
	css := string(raw)

	require.Contains(t, css, `@import "tailwindcss" source(none);`,
		"automatic content detection must be off; see this test's comment for what it costs")

	sources := regexp.MustCompile(`@source\s+(?:not\s+)?"([^"]+)"`).FindAllStringSubmatch(css, -1)
	require.NotEmpty(t, sources, "with source(none) the @source globs are the only content")

	for _, source := range sources {
		require.Truef(t, strings.HasPrefix(source[1], "../internal/web/"),
			"@source %q reaches outside internal/web, so an unrelated file can change the stylesheet", source[1])
	}
}
