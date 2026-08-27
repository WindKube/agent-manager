package web_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
)

// The table is transcribed by hand from the design's fuzzy() semantics
// (docs/design/agent-manager.dc.html line 964), not from this implementation's
// output. The other side of the check is the browser: the R7 measurement asserts
// amFuzzy in app.js against the same cases.
func TestFuzzy(t *testing.T) {
	tests := []struct {
		name     string
		needle   string
		haystack string
		want     bool
	}{
		{name: "an empty needle matches everything", needle: "", haystack: "terraform", want: true},
		{name: "a whitespace-only needle matches everything", needle: "   ", haystack: "terraform", want: true},
		{name: "an exact match matches", needle: "terraform", haystack: "terraform", want: true},
		{name: "a prefix matches", needle: "terra", haystack: "terraform", want: true},
		{name: "a substring matches", needle: "form", haystack: "terraform", want: true},
		{name: "a non-adjacent subsequence matches, which a substring match would reject",
			needle: "tfm", haystack: "terraform-module-review", want: true},
		{name: "a subsequence out of order does not match", needle: "mft", haystack: "terraform-module-review", want: false},
		{name: "matching is case-insensitive on both sides", needle: "AWS", haystack: "aws", want: true},
		{name: "matching is case-insensitive in the haystack", needle: "sec", haystack: "Security & compliance", want: true},
		{name: "whitespace is stripped from the needle", needle: "sec com", haystack: "Security & compliance", want: true},
		{name: "a subsequence spanning the haystack's spaces matches", needle: "y&c", haystack: "Security & compliance", want: true},
		{name: "a needle longer than the haystack does not match", needle: "terraformer", haystack: "terraform", want: false},
		{name: "a character absent from the haystack does not match", needle: "z", haystack: "terraform", want: false},
		{name: "a repeated needle character consumes one haystack occurrence each",
			needle: "rrr", haystack: "terraform", want: true},
		{name: "one repeat too many does not match", needle: "rrrr", haystack: "terraform", want: false},
		{name: "an empty haystack rejects a non-empty needle", needle: "a", haystack: "", want: false},
		{name: "a digit in a generated topic tag matches", needle: "t07", haystack: "topic-07", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, web.Fuzzy(tc.needle, tc.haystack))
		})
	}
}
