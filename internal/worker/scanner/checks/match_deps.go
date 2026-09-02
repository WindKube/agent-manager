package checks

import (
	"encoding/json"
	"regexp"
	"strings"

	"agent-manager/internal/worker/scanner/rules"
)

// matchDependencies is the `dep-manifest` matcher: it reads dependency
// declarations out of the three manifests real trees carry, and judges the
// SPECIFIER rather than the text of the file.
//
// The difference matters. `"tar": "^6.0.0"` and `"tar": "6.0.0"` differ by one
// character and only one of them is a supply-chain hole: a caret range resolves to
// whatever the registry serves at install time, so the bytes a reviewer approved
// are not the bytes the next machine gets. A text rule looking for `^` would also
// match every `^` in every string in the file.
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

// npmDependencyFields are the four dependency maps npm resolves at install time.
// `bundledDependencies` is absent on purpose: those ship inside the tarball, so
// they are bytes the scan already read rather than a specifier resolved later.
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
		// A package.json that is not json declares no dependencies this matcher can
		// read. It is not silently clean either: the file is still read as text by
		// any regex rule scoped to it, and a manifest that fails its own schema is
		// the manifest-schema check's business.
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

// pipRequirement splits `package[extra]==1.2.3 ; marker` into its name and the
// rest. Anything not matching is not a requirement line — a `-r other.txt`, a
// `--index-url`, a comment.
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

// rangeOperators are the npm specifiers that resolve to a set rather than to one
// release.
var rangeOperators = []string{"^", "~", ">", "<", "=>", ">=", "<=", "||", " - ", "*", "x"}

// unpinned reports whether a dependency specifier names one exact release.
//
// It is deliberately conservative in the direction of flagging: a specifier this
// function cannot read is unpinned, because the alternative is a supply-chain
// finding suppressed by a notation nobody implemented.
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
		// pip's exact pin, the only pip notation that names one release.
		return false
	case strings.HasPrefix(constraint, "v") && !strings.ContainsAny(constraint, "^~<>*|"):
		// go.mod, whose require lines are always exact.
		return false
	}

	// A git, http or file specifier resolves to whatever that reference holds. A
	// commit-pinned git URL is arguably exact, and it is still flagged: a reviewer
	// deciding that is exactly what a finding is for.
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
	// Anything left with three numeric segments is an exact npm pin.
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
