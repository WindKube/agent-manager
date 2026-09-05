package checks

import (
	"encoding/json"
	"strconv"
	"strings"

	"agent-manager/internal/worker/scanner/rules"
)

// matchSchema is the `schema-path` matcher: it judges the manifest document
// rather than any file's text. A rule quoting `schema-error` asks for the
// manifest to be validated; any other quote judges a JSON pointer's value.
func matchSchema(b *Bundle, rule rules.Rule) []hit {
	manifestPath := b.ManifestObject
	if manifestPath == "" {
		manifestPath = "plugin.json"
	}

	if rule.Evidence.Quote == rules.QuoteSchemaError {
		hits := make([]hit, 0, len(b.ManifestProblems))
		for _, problem := range b.ManifestProblems {
			value := problem.InstancePath
			if value == "" {
				value = "/"
			}
			if !judge(b, rule, problem.String()) {
				continue
			}
			hits = append(hits, hit{path: manifestPath, quote: problem.String(), value: value})
		}
		return hits
	}

	if len(b.Manifest) == 0 || !json.Valid(b.Manifest) {
		return nil
	}
	var document any
	if err := json.Unmarshal(b.Manifest, &document); err != nil {
		return nil
	}

	value, found := resolvePointer(document, rule.Match.Pointer)
	if !found {
		return nil
	}
	rendered := renderValue(value)
	if !judge(b, rule, rendered) {
		return nil
	}
	return []hit{{path: manifestPath, quote: rule.Match.Pointer + ": " + rendered, value: rendered}}
}

// resolvePointer walks an RFC 6901 JSON pointer: `~1` for a slash inside a
// key, `~0` for a tilde.
func resolvePointer(document any, pointer string) (any, bool) {
	if pointer == "" || pointer == "/" {
		return document, true
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}

	current := document
	for _, token := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		token = strings.ReplaceAll(token, "~1", "/")
		token = strings.ReplaceAll(token, "~0", "~")

		switch node := current.(type) {
		case map[string]any:
			next, ok := node[token]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(node) {
				return nil, false
			}
			current = node[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func renderValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case nil:
		return "null"
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(encoded)
	}
}
