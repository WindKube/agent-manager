package web

import (
	"strings"
	"unicode"
)

// Fuzzy is the facet-menu option matcher: a case-insensitive SUBSEQUENCE match,
// not a substring match. The needle's characters must appear in the haystack in
// order but need not be adjacent, so "tfm" matches "terraform-module-review".
// Whitespace is stripped from the needle only, which is what lets a typed
// "sec com" match "Security & compliance".
//
// This is fuzzy() from docs/design/agent-manager.dc.html line 964, and it is
// mirrored character for character by amFuzzy in internal/web/static/app.js —
// the client does the typing-time filtering, this side answers a menu opened
// with a filter already in it.
func Fuzzy(needle, haystack string) bool {
	n := []rune(strings.ToLower(stripSpace(needle)))
	if len(n) == 0 {
		return true
	}

	i := 0
	for _, r := range strings.ToLower(haystack) {
		if r == n[i] {
			i++
			if i == len(n) {
				return true
			}
		}
	}
	return false
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}
