package checks

import (
	"encoding/json"
	"regexp"
	"strings"

	"agent-manager/internal/worker/scanner/rules"
)

// matchDependencies is the `dep-manifest` matcher: it judges specifiers in
// package.json, requirements.txt and go.mod.
func matchDependencies(b *Bundle, rule rules.Rule) []hit {
	var hits []hit
	for _, file := range b.Artefacts.Files {
		if !rule.Match.InScope(file.Path) {
			continue
		}

		var specs []dependency
		switch {
		case strings.HasSuffix(file.Path, "package.json"):
			specs = npmDependencies(b, file.Path)
		case strings.HasSuffix(file.Path, "requirements.txt"):
			specs = pipDependencies(b, file.Path)
		case strings.HasSuffix(file.Path, "go.mod"):
			specs = goDependencies(b, file.Path)
		default:
			continue
		}

		for _, spec := range specs {
			value := spec.name + "@" + spec.constraint
			if !judge(b, rule, value) {
				continue
			}
			quote := spec.text
			if rule.Evidence.Quote == rules.QuoteMatchedNode {
				quote = value
			}
			hits = append(hits, hit{path: file.Path, line: spec.line, quote: quote, value: value})
		}
	}
	return hits
}

type dependency struct {
	name       string
	constraint string
	line       int
	text       string
}

// npmDependencyFields omits `bundledDependencies`, which ship inside the tarball.
var npmDependencyFields = []string{
	"dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
}

func npmDependencies(b *Bundle, filePath string) []dependency {
	file, ok := b.File(filePath)
	if !ok {
		return nil
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(file.Data, &document); err != nil {
		return nil
	}

	var out []dependency
	for _, field := range npmDependencyFields {
		raw, present := document[field]
		if !present {
			continue
		}
		var block map[string]string
		if err := json.Unmarshal(raw, &block); err != nil {
			continue
		}
		for name, constraint := range block {
			out = append(out, dependency{
				name:       name,
				constraint: constraint,
				line:       lineOf(b, filePath, `"`+name+`"`),
				text:       lineTextOf(b, filePath, `"`+name+`"`),
			})
		}
	}
	return out
}

// pipRequirement splits `package[extra]==1.2.3 ; marker` into its name and the rest.
var pipRequirement = regexp.MustCompile(`^([A-Za-z0-9._-]+)(\[[^\]]*\])?\s*(.*)$`)

func pipDependencies(b *Bundle, filePath string) []dependency {
	var out []dependency
	for number, text := range b.Lines(filePath) {
		line := strings.TrimSpace(text)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		match := pipRequirement.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		out = append(out, dependency{
			name:       match[1],
			constraint: strings.TrimSpace(match[3]),
			line:       number + 1,
			text:       text,
		})
	}
	return out
}

var goRequirement = regexp.MustCompile(`^\s*(?:require\s+)?([^\s()]+)\s+(v\S+)`)

func goDependencies(b *Bundle, filePath string) []dependency {
	var out []dependency
	inBlock := false
	for number, text := range b.Lines(filePath) {
		line := strings.TrimSpace(text)
		switch {
		case strings.HasPrefix(line, "require ("):
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case !inBlock && !strings.HasPrefix(line, "require "):
			continue
		}
		match := goRequirement.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		out = append(out, dependency{name: match[1], constraint: match[2], line: number + 1, text: text})
	}
	return out
}

var rangeOperators = []string{"^", "~", ">", "<", "=>", ">=", "<=", "||", " - ", "*", "x"}

// unpinned treats an unreadable specifier as unpinned.
func unpinned(value string) bool {
	_, constraint, found := strings.Cut(value, "@")
	if !found {
		return true
	}
	constraint = strings.TrimSpace(constraint)

	switch {
	case constraint == "":
		return true
	case strings.HasPrefix(constraint, "=="):
		// pip's exact pin.
		return false
	case strings.HasPrefix(constraint, "v") && !strings.ContainsAny(constraint, "^~<>*|"):
		// go.mod require lines are always exact.
		return false
	}

	// Git, http and file specifiers are flagged even when commit-pinned.
	if strings.Contains(constraint, "://") || strings.HasPrefix(constraint, "git") ||
		strings.HasPrefix(constraint, "github:") || strings.HasPrefix(constraint, "file:") {
		return true
	}

	lowered := strings.ToLower(constraint)
	if lowered == "latest" || lowered == "next" || lowered == "*" {
		return true
	}
	for _, operator := range rangeOperators {
		if strings.Contains(lowered, operator) {
			return true
		}
	}
	return !exactSemver.MatchString(constraint)
}

var exactSemver = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?$`)

func lineOf(b *Bundle, filePath, needle string) int {
	for number, text := range b.Lines(filePath) {
		if strings.Contains(text, needle) {
			return number + 1
		}
	}
	return 0
}

func lineTextOf(b *Bundle, filePath, needle string) string {
	for _, text := range b.Lines(filePath) {
		if strings.Contains(text, needle) {
			return text
		}
	}
	return needle
}
