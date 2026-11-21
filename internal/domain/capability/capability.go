// Package capability holds the inferred (scanned) and expected (declared)
// capability sets. A level is how much human trust a capability demands, never
// an enforced permission.
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
	// Indefinite marks that Detail is not the whole set.
	Indefinite bool
}

// maxDetail stops an untrusted bundle choosing the size of a row.
const maxDetail = 64

// finish tidies the target list and applies the level floors. Every
// constructed Capability goes through it.
func finish(c Capability) Capability {
	c.Detail = tidy(c.Detail, &c.Indefinite)

	// tidy can create indefiniteness by truncating, so this runs after it.
	if c.Indefinite {
		c.Level = stricter(c.Level, LevelReview)
	}

	// Shell is never below Review, for both sources, so the panel never shows
	// a false disagreement.
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

// order sorts rows into Names' order so rows are stable between scans.
func order(rows []Capability) []Capability {
	rank := make(map[string]int, len(Names))
	for i, name := range Names {
		rank[name] = i
	}
	sort.SliceStable(rows, func(i, j int) bool { return rank[rows[i].Name] < rank[rows[j].Name] })
	return rows
}
