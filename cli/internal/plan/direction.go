package plan

import (
	"strconv"
	"strings"
)

// This file is the only place in the CLI where an ordering on version
// strings may exist: it reports which way a hub-chosen replacement moved,
// never chooses which version to install (that's the hub's job — a second
// implementation here could disagree with its audit trail). compute.go, on
// the other side of that line, only ever asks whether two strings are equal.

// Direction is which way a replacement moved, as a label.
type Direction string

const (
	DirectionNone Direction = "" // no previous version: an add

	DirectionUp Direction = "up"

	// DirectionDown is a real outcome, not a mistake: a pin can move
	// backwards, and `latest` moves backwards on its own when the newest
	// version gets gated.
	DirectionDown Direction = "down"

	// DirectionSame: same string with only the digest moved (a republish),
	// or differing only in build metadata or segment padding.
	DirectionSame Direction = "same"

	DirectionUnknown Direction = "unknown" // the comparer declined; reported, not guessed
)

// Comparer orders two version strings, returning ok=false rather than a
// coin flip when it can't; it's a seam so Masterminds/semver can be dropped
// in at one call site once cli/go.mod carries it.
type Comparer func(a, b string) (int, bool)

// DirectionOf labels a replacement; a nil comparer uses [CompareVersions].
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

// CompareVersions is the default comparer: SemVer 2.0.0 precedence (§11),
// hand-written since cli/go.mod carries no semver library. It compares
// numeric segments numerically (never "1.10.0" < "1.9.0" as strings), and
// returns ok=false rather than 0 for equal-precedence-but-different strings
// (build metadata, segment padding) since 0 would read as "identical". It
// does not validate semver, so non-semver strings still get an ordering —
// swap in [Comparer] where exactness matters more than a zero-dependency default.
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

	// §11.3: a version WITH a prerelease precedes the same version without one.
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

// splitVersion drops build metadata (§10) and separates core from prerelease.
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
		x, y := "0", "0" // missing segment is zero, so 1.2 and 1.2.0 order equal
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
	switch { // §11.4.4: more fields wins when all preceding fields are equal
	case len(fieldsA) < len(fieldsB):
		return -1
	case len(fieldsA) > len(fieldsB):
		return 1
	default:
		return 0
	}
}

// compareIdentifier: numeric fields compare numerically and rank below alphanumeric ones (§11.4.3).
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

// numeric: overflow is non-numeric rather than truncated (a wrong order is worse than unordered).
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
