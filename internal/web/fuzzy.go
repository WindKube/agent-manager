package web

import (
	"strings"
	"unicode"
)

// Fuzzy is a case-insensitive subsequence match with whitespace stripped from
// the needle, so "tfm" matches "terraform-module-review". It must stay in sync
// with amFuzzy in internal/web/static/app.js.
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
