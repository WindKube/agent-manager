package plan

import (
	"strconv"
	"strings"
)

// This file is the reporting side and the only place in the CLI where an
// ordering on version strings may exist. Masterminds/semver may be imported
// here and nowhere else.
//
// The distinction that makes that safe, and it is not a wording trick:
//
//   - Comparing two versions the hub ALREADY CHOSE, to decide whether to print
//     "upgrade" or "downgrade", is reporting. Nothing downstream reads the
//     answer. Get it wrong and one word is wrong.
//   - Choosing WHICH version to install is resolving, and it belongs to the
//     hub. A second implementation here is a second answer, and the two
//     eventually disagree — at which point the machine holds a version the
//     hub's audit trail says it does not.
//
// compute.go, on the other side of that line, asks only whether two version
// strings are equal and whether two digests are the same 32 bytes. It never
// asks which is greater. TestTheChangeSetDoesNotDependOnTheVersionComparer
// proves the line is real by inverting the comparer and asserting the change
// set is byte-identical.

// Direction is which way a replacement moved, as a label.
type Direction string

const (
	// DirectionNone: there was no previous version. An add.
	DirectionNone Direction = ""

	// DirectionUp: the locked version is greater than the installed one.
	DirectionUp Direction = "up"

	// DirectionDown: the locked version is LESS than the installed one. A real
	// outcome, not a mistake — a pin can be moved backwards, and a `latest`
	// entry moves backwards on its own when the newest version gets flagged and
	// the gate blocks it. A downgrade is not an upgrade with a minus sign; the
	// report has to say which it was.
	DirectionDown Direction = "down"

	// DirectionSame: the two versions order equal. Either they are the same
	// string and only the digest moved (a republish), or they differ only in
	// build metadata or segment padding.
	DirectionSame Direction = "same"

	// DirectionUnknown: the comparer declined to order them. Reported as such
	// rather than guessed, because a guessed direction is indistinguishable
	// from a measured one once it is printed.
	DirectionUnknown Direction = "unknown"
)

// Comparer orders two version strings. It returns the sign of a-b and whether
// it is willing to stand behind the answer; ok=false means "these are not
// orderable by me", which becomes [DirectionUnknown] rather than a coin flip.
//
// It is a seam so that Masterminds/semver can be dropped in at one call site
// once cli/go.mod carries it:
//
//	plan.Inputs{Compare: func(a, b string) (int, bool) {
//	        va, err := semver.NewVersion(a)
//	        if err != nil { return 0, false }
//	        vb, err := semver.NewVersion(b)
//	        if err != nil { return 0, false }
//	        return va.Compare(vb), true
//	}}
type Comparer func(a, b string) (int, bool)

// DirectionOf labels a replacement. from is the installed version, to is the
// version the hub resolved. A nil comparer uses [CompareVersions].
func DirectionOf(cmp Comparer, from, to string) Direction {
	if from == "" {
		return DirectionNone
	}
	if cmp == nil {
		cmp = CompareVersions
	}
	sign, ok := cmp(from, to)
	switch {
	case !ok:
		return DirectionUnknown
	case sign < 0:
		return DirectionUp
	case sign > 0:
		return DirectionDown
	default:
		return DirectionSame
	}
}

// CompareVersions is the default comparer: Semantic Versioning 2.0.0
// precedence (§11), degrading to numeric-segment comparison for strings that
// are not valid semver.
//
// It is hand-written rather than delegated because cli/go.mod does not carry
// Masterminds/semver and this package must not add a requirement. Two things
// it deliberately does:
//
//   - It compares numeric segments NUMERICALLY. Lexicographic comparison is
//     the trap this whole function exists to avoid: "1.10.0" < "1.9.0" as
//     strings, so the single most common real upgrade would be reported as a
//     downgrade. String inequality can tell you that two versions differ; it
//     cannot tell you which is newer, and nothing in the lockfile can either —
//     `revision` orders revisions, not versions, and `resolution` says how the
//     hub chose, not what it chose over.
//   - It returns ok=false rather than 0 when the two order equal but are not
//     the same string, i.e. when the only difference is build metadata
//     ("1.2.3" vs "1.2.3+build.7") or segment padding ("1.0" vs "1.0.0").
//     Semver says those have equal precedence, so "no direction" is the true
//     answer and 0 would be indistinguishable from "identical".
//
// What it gets wrong, stated so nobody has to rediscover it: it does not
// validate semver, so a version this hub would have rejected still gets an
// ordering, and for genuinely non-semver schemes the ordering is whatever
// numeric-segment comparison says (dates and four-segment versions come out
// right; "2.0-final" against "2.0-beta" comes out right by ASCII accident,
// "10-jan" against "2-feb" comes out right; but "v2" against "2" orders v2
// HIGHER, because §11.4.3 puts every alphanumeric field above every numeric
// one, which is a semver rule applied to something that is not semver). Where
// exactness matters more than the absence of a dependency, replace it via
// [Comparer]; the change set does not move either way.
func CompareVersions(a, b string) (int, bool) {
	if a == "" || b == "" {
		return 0, false
	}
	if a == b {
		return 0, true
	}

	coreA, preA := splitVersion(a)
	coreB, preB := splitVersion(b)

	if sign := compareCore(coreA, coreB); sign != 0 {
		return sign, true
	}

	// Semver §11.3: a version WITH a prerelease has lower precedence than the
	// same version without one. 1.0.0-rc.1 precedes 1.0.0, which lexicographic
	// comparison gets backwards.
	switch {
	case preA == "" && preB != "":
		return 1, true
	case preA != "" && preB == "":
		return -1, true
	case preA != "" && preB != "":
		if sign := comparePrerelease(preA, preB); sign != 0 {
			return sign, true
		}
	}

	return 0, false
}

// splitVersion drops build metadata (§10: it is ignored for precedence) and
// separates the core from the prerelease.
func splitVersion(v string) (core, prerelease string) {
	if plus := strings.IndexByte(v, '+'); plus >= 0 {
		v = v[:plus]
	}
	if dash := strings.IndexByte(v, '-'); dash >= 0 {
		return v[:dash], v[dash+1:]
	}
	return v, ""
}

func compareCore(a, b string) int {
	segA := strings.Split(a, ".")
	segB := strings.Split(b, ".")
	n := max(len(segA), len(segB))
	for i := range n {
		// A missing segment is zero, so 1.2 and 1.2.0 order equal — the same
		// answer semver gives once both are normalised.
		x, y := "0", "0"
		if i < len(segA) {
			x = segA[i]
		}
		if i < len(segB) {
			y = segB[i]
		}
		if sign := compareIdentifier(x, y); sign != 0 {
			return sign
		}
	}
	return 0
}

// comparePrerelease implements §11.4 field by field.
func comparePrerelease(a, b string) int {
	fieldsA := strings.Split(a, ".")
	fieldsB := strings.Split(b, ".")
	n := min(len(fieldsA), len(fieldsB))
	for i := range n {
		if sign := compareIdentifier(fieldsA[i], fieldsB[i]); sign != 0 {
			return sign
		}
	}
	// §11.4.4: a larger set of fields has higher precedence when all preceding
	// fields are equal.
	switch {
	case len(fieldsA) < len(fieldsB):
		return -1
	case len(fieldsA) > len(fieldsB):
		return 1
	default:
		return 0
	}
}

// compareIdentifier compares one dot-separated field. Numeric fields compare
// numerically; a numeric field has lower precedence than an alphanumeric one
// (§11.4.3); two alphanumeric fields compare by ASCII.
func compareIdentifier(a, b string) int {
	na, okA := numeric(a)
	nb, okB := numeric(b)
	switch {
	case okA && okB:
		return cmpUint(na, nb)
	case okA:
		return -1
	case okB:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

// numeric parses a field as an unsigned integer. A value too large for uint64
// is treated as non-numeric rather than truncated: a wrong ordering is worse
// than an unordered pair, and no real version has a 20-digit segment.
func numeric(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
