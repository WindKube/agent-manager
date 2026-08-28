// Package capability holds the two halves of the capability model: what a
// version can reach, INFERRED from what the scanner found in the bytes (FR-018),
// and what its publisher said it should reach, read from the manifest (FR-018a).
//
// research.md R1 is why the inference exists at all. Neither Agent Plugins 1.0.0
// nor Agent Skills defines a permissions model, so a conformant manifest cannot
// declare one; the design's `network: {allow: []}` and `filesystem: {read: []}`
// are not fields that exist. The evidence about what a package does is therefore
// the bytes, and a manifest can only carry an expectation to compare them
// against.
//
// Two things this package deliberately does NOT do:
//
//   - It does not grant or deny anything. A level is how much trust a capability
//     demands from a human reading the page, not a permission the hub enforces —
//     there is no enforcement point anywhere in this system, and a UI that reads
//     like there is would be the worst kind of security theatre (FR-018a).
//   - It carries no evidence. A file-and-line citation belongs to a finding
//     (FR-024) and lives in `finding_evidence`; the `capability` table has no
//     column for one, and a second copy here is a fact nothing keeps in step.
//
// It is pure by construction and by internal/archcheck: no database, no blob, no
// HTTP. Nothing here writes a `capability` row either — the scanner writes both
// sources in the transaction that records the scan (T071), because `am_fetcher`
// has no grant on `capability` and deliberately never gets one.
package capability

import (
	"sort"
	"strings"

	"agent-manager/internal/domain/pkgspec"
)

// The capability names, which are pkgspec's closed set. They are re-exported
// rather than re-spelled: the expected set is validated against that set when a
// manifest is ingested, and a second list here would be a second vocabulary that
// silently never matches the first.
const (
	Network         = pkgspec.CapabilityNetwork
	FilesystemRead  = pkgspec.CapabilityFilesystemRead
	FilesystemWrite = pkgspec.CapabilityFilesystemWrite
	Shell           = pkgspec.CapabilityShell
)

// Names is the closed set, in the order a panel lists it.
var Names = []string{Network, FilesystemRead, FilesystemWrite, Shell}

// Level is how much trust a capability demands. It mirrors the
// `capability_level` enum.
type Level string

const (
	// LevelScoped is a definite target set that stays inside the package.
	LevelScoped Level = pkgspec.LevelScoped
	// LevelAllowlisted is a definite target set that reaches outside it, so a
	// human has to decide once whether the list is acceptable.
	LevelAllowlisted Level = pkgspec.LevelAllowlisted
	// LevelReview is anything indefinite, dynamic, over-broad or sensitive. It is
	// also the floor for `shell` (FR-018), whatever the analysis found.
	LevelReview Level = pkgspec.LevelReview
)

// rank orders the levels by how much trust they demand, so two findings about
// the same capability combine to the stricter one rather than to the last one
// written.
func (l Level) rank() int {
	switch l {
	case LevelScoped:
		return 0
	case LevelAllowlisted:
		return 1
	default:
		return 2
	}
}

// Valid reports whether l is one of the three enum values.
func (l Level) Valid() bool {
	return l == LevelScoped || l == LevelAllowlisted || l == LevelReview
}

func stricter(a, b Level) Level {
	if b.rank() > a.rank() {
		return b
	}
	return a
}

// Source is the R1 inversion made explicit: `inferred` is what the bytes say,
// `expected` is what the publisher says. Both live in one table keyed by source
// so FR-027's comparison is between two sets of the same thing.
type Source string

const (
	SourceInferred Source = "inferred"
	SourceExpected Source = "expected"
)

// Capability is one row of the `capability` table before it is a row.
type Capability struct {
	// Name is one of Names.
	Name string
	// Source says which side of the comparison this is.
	Source Source
	// Level is what the panel shows as Scoped / Allowlisted / Review.
	Level Level
	// Detail is the scoping: hosts for network, paths for filesystem, command
	// names for shell. Sorted and deduplicated, so two analyses of the same bundle
	// produce the same row.
	Detail []string
	// Indefinite records that the analysis found targets it could not resolve —
	// a host behind a shell variable, a package manager reaching its default
	// registry. It is the difference between "this reaches these two hosts" and
	// "this reaches these two hosts AND something else", and collapsing the two
	// would turn an unknown into a clean bill of health.
	Indefinite bool
}

// maxDetail bounds a row's target list. The targets come from an untrusted
// bundle (constitution principle III) and land in a jsonb column and on a page,
// so a bundle with ten thousand distinct hosts must not choose the size of
// either. The entries dropped are the ones sorting last, and Indefinite is set so
// the row never reads as a complete list.
const maxDetail = 64

// finish sorts, deduplicates and caps a target list, and applies the FR-018
// floor. Every constructed Capability goes through it, which is what makes the
// shell floor unconditional rather than a rule each call site remembers.
func finish(c Capability) Capability {
	c.Detail = tidy(c.Detail, &c.Indefinite)

	// An indefinite target set cannot be graded below Review, and the rule lives
	// here rather than at each call site because tidy can CREATE indefiniteness by
	// truncating: a list capped at maxDetail is no longer the whole list, and a
	// capped list still reading Allowlisted would invite a reviewer to accept a
	// set they cannot see the end of.
	if c.Indefinite {
		c.Level = stricter(c.Level, LevelReview)
	}

	// FR-018: a shell capability is never below Review. It is applied here, to
	// BOTH sources, because a level is a claim about how much trust the capability
	// demands and not about who wrote it down — and the panel puts the two rows
	// side by side, where `shell: Scoped` under Expected beside `shell: Review`
	// under Inferred would read as a disagreement the scanner found rather than as
	// a publisher writing a level this model does not have.
	if c.Name == Shell {
		c.Level = stricter(c.Level, LevelReview)
	}
	if !c.Level.Valid() {
		c.Level = LevelReview
	}
	return c
}

func tidy(values []string, truncated *bool) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, dup := seen[value]; dup {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) > maxDetail {
		out = out[:maxDetail]
		*truncated = true
	}
	return out
}

// order sorts a set of rows into the order Names gives, so the panel's rows do
// not move between two scans of the same package.
func order(rows []Capability) []Capability {
	rank := make(map[string]int, len(Names))
	for i, name := range Names {
		rank[name] = i
	}
	sort.SliceStable(rows, func(i, j int) bool { return rank[rows[i].Name] < rank[rows[j].Name] })
	return rows
}
