// Package plan is a pure function of a lockfile, the record and a comparer:
// no I/O, no clock, no environment — the plan printed by --dry-run is exactly what apply executes.
package plan
