// Package capability holds the two halves of the capability model:
// INFERRED (what the scanner found in the bytes) and EXPECTED (what the
// publisher's manifest declares). A level is how much trust a capability
// demands from a human, not a permission the hub enforces — there is no
// enforcement point anywhere in this system. Pure by construction: no
// database, no blob, no HTTP.
package capability

import (
	"sort"
	"strings"

	"agent-manager/internal/domain/pkgspec"
)

// Re-exported from pkgspec's closed set so there's no second vocabulary.
const (
	Network         = pkgspec.CapabilityNetwork
	FilesystemRead  = pkgspec.CapabilityFilesystemRead
	FilesystemWrite = pkgspec.CapabilityFilesystemWrite
	Shell           = pkgspec.CapabilityShell
)

var Names = []string{Network, FilesystemRead, FilesystemWrite, Shell}

type Level string

const (
	LevelScoped      Level = pkgspec.LevelScoped      // stays inside the package
	LevelAllowlisted Level = pkgspec.LevelAllowlisted // a definite outside set
	LevelReview      Level = pkgspec.LevelReview      // indefinite, dynamic, over-broad or sensitive
)

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

func (l Level) Valid() bool {
	return l == LevelScoped || l == LevelAllowlisted || l == LevelReview
}

func stricter(a, b Level) Level {
	if b.rank() > a.rank() {
		return b
	}
	return a
}

type Source string

const (
	SourceInferred Source = "inferred"
	SourceExpected Source = "expected"
)

type Capability struct {
	Name   string
	Source Source
	Level  Level
	Detail []string
	// Indefinite: collapsing "reaches these hosts" with "AND something
	// else" would turn an unknown into a clean bill of health.
	Indefinite bool
}

// maxDetail bounds a row's target list: an untrusted bundle must not
// choose the size of a jsonb column or a page.
const maxDetail = 64

// finish sorts, deduplicates and caps a target list, and applies the shell
// floor. Every constructed Capability goes through it.
func finish(c Capability) Capability {
	c.Detail = tidy(c.Detail, &c.Indefinite)

	// tidy can CREATE indefiniteness by truncating, so this runs after it.
	if c.Indefinite {
		c.Level = stricter(c.Level, LevelReview)
	}

	// A shell capability is never below Review, applied to BOTH sources so
	// the panel never shows `shell: Scoped` under Expected beside
	// `shell: Review` under Inferred as if the scanner found a disagreement.
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

// order sorts rows into Names' order, so the panel's rows don't move
// between two scans of the same package.
func order(rows []Capability) []Capability {
	rank := make(map[string]int, len(Names))
	for i, name := range Names {
		rank[name] = i
	}
	sort.SliceStable(rows, func(i, j int) bool { return rank[rows[i].Name] < rank[rows[j].Name] })
	return rows
}
