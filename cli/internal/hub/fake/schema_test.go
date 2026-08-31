package fake

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A small JSON Schema validator, test-only.
//
// Why hand-written: cli/go.mod carries no schema library and this layer may not
// add one. Why that is acceptable here: the schema being interpreted is FROZEN and
// uses exactly the keywords handled below, and the alternative — asserting against
// a Go struct — is not a check at all, because the struct is generated from the
// same document as the schema and would agree with it by construction.
//
// What it does NOT implement: $ref, allOf/anyOf/oneOf, if/then, dependent schemas,
// numeric multiples, string lengths, uniqueItems, and every format except
// date-time. If lockfile.schema.json ever grows one of those, this validator will
// silently ignore it — so schemaKeywordsAreAllHandled below fails the build when a
// keyword appears that nothing here interprets. A validator that quietly skips the
// rule you were relying on is worse than no validator.
var handledKeywords = map[string]bool{
	// Structural, interpreted below.
	"type": true, "required": true, "properties": true, "additionalProperties": true,
	"items": true, "enum": true, "const": true, "pattern": true, "minimum": true,
	"format": true,
	// Annotations with no validation effect.
	"$schema": true, "$id": true, "title": true, "description": true, "examples": true,
}

type violation struct {
	path string
	msg  string
}

func (v violation) String() string { return v.path + ": " + v.msg }

type validator struct {
	// relaxEnumAt suppresses the enum check at exactly this instance path. It exists
	// for one case and is named after it: FR-011 requires the CLI to report an
	// unrecognised skip reason verbatim, so the fake must serve one, and the frozen
	// enum cannot contain it. Every OTHER rule still applies to that document.
	relaxEnumAt string
	out         []violation
}

func (v *validator) fail(path, format string, args ...any) {
	v.out = append(v.out, violation{path: path, msg: fmt.Sprintf(format, args...)})
}

func (v *validator) check(schema map[string]any, doc any, path string) {
	if t, ok := schema["type"].(string); ok && !typeMatches(t, doc) {
		v.fail(path, "expected type %s, got %s", t, jsonKind(doc))
		return
	}
	if c, ok := schema["const"]; ok && !jsonEqual(c, doc) {
		v.fail(path, "expected const %v, got %v", c, doc)
	}
	if enum, ok := schema["enum"].([]any); ok && path != v.relaxEnumAt {
		found := false
		for _, e := range enum {
			if jsonEqual(e, doc) {
				found = true
				break
			}
		}
		if !found {
			v.fail(path, "value %v is not in the enum", doc)
		}
	}
	if pat, ok := schema["pattern"].(string); ok {
		if s, isStr := doc.(string); isStr && !regexp.MustCompile(pat).MatchString(s) {
			v.fail(path, "value %q does not match %s", s, pat)
		}
	}
	if f, ok := schema["format"].(string); ok && f == "date-time" {
		if s, isStr := doc.(string); isStr {
			if _, err := time.Parse(time.RFC3339, s); err != nil {
				v.fail(path, "value %q is not an RFC 3339 date-time", s)
			}
		}
	}
	if m, ok := schema["minimum"].(float64); ok {
		if n, isNum := doc.(float64); isNum && n < m {
			v.fail(path, "value %v is below the minimum %v", n, m)
		}
	}

	switch typed := doc.(type) {
	case map[string]any:
		props, _ := schema["properties"].(map[string]any)
		for _, r := range asStrings(schema["required"]) {
			if _, present := typed[r]; !present {
				v.fail(path, "required property %q is absent", r)
			}
		}
		if extra, ok := schema["additionalProperties"].(bool); ok && !extra {
			for k := range typed {
				if _, declared := props[k]; !declared {
					v.fail(path, "property %q is not declared and additionalProperties is false", k)
				}
			}
		}
		for k, sub := range props {
			val, present := typed[k]
			if !present {
				continue
			}
			subSchema, ok := sub.(map[string]any)
			if !ok {
				continue
			}
			v.check(subSchema, val, path+"/"+k)
		}
	case []any:
		items, ok := schema["items"].(map[string]any)
		if !ok {
			return
		}
		for i, el := range typed {
			v.check(items, el, fmt.Sprintf("%s/%d", path, i))
		}
	}
}

func typeMatches(t string, doc any) bool {
	switch t {
	case "object":
		_, ok := doc.(map[string]any)
		return ok
	case "array":
		_, ok := doc.([]any)
		return ok
	case "string":
		_, ok := doc.(string)
		return ok
	case "boolean":
		_, ok := doc.(bool)
		return ok
	case "number":
		_, ok := doc.(float64)
		return ok
	case "integer":
		n, ok := doc.(float64)
		return ok && n == math.Trunc(n)
	case "null":
		return doc == nil
	default:
		return true
	}
}

func jsonKind(doc any) string {
	switch doc.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%T", doc)
	}
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}

func asStrings(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func walkKeywords(schema any, seen map[string]bool) {
	switch typed := schema.(type) {
	case map[string]any:
		for k, sub := range typed {
			seen[k] = true
			switch k {
			case "properties":
				if props, ok := sub.(map[string]any); ok {
					for _, s := range props {
						walkKeywords(s, seen)
					}
				}
			case "items":
				walkKeywords(sub, seen)
			case "enum", "examples", "required", "const":
				// Value positions, not schema positions: their contents are data.
			default:
				walkKeywords(sub, seen)
			}
		}
	case []any:
		for _, e := range typed {
			walkKeywords(e, seen)
		}
	}
}

// lockfileSchema reads the FROZEN schema from the repo, not a copy. A copy inside
// this package would drift the day the hub's schema changed and no test would
// notice, which is the exact failure this self-test exists to prevent.
func lockfileSchema(t *testing.T) map[string]any {
	t.Helper()
	const rel = "specs/001-agent-manager-hub/contracts/lockfile.schema.json"
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		candidate := filepath.Join(dir, rel)
		if _, err := os.Stat(candidate); err == nil {
			raw, err := os.ReadFile(candidate)
			require.NoError(t, err)
			var schema map[string]any
			require.NoError(t, json.Unmarshal(raw, &schema))
			return schema
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find %s above the test's working directory; the fake's conformance test cannot run without the frozen schema", rel)
		}
		dir = parent
	}
}

func TestSchemaKeywordsAreAllHandled(t *testing.T) {
	seen := map[string]bool{}
	walkKeywords(lockfileSchema(t), seen)
	// The walker is the load-bearing half; if it returned nothing the sweep below
	// would pass on an empty set and say nothing at all.
	for _, expect := range []string{"type", "required", "properties", "additionalProperties", "enum", "pattern", "const", "minimum", "format", "items"} {
		require.True(t, seen[expect], "the keyword walker did not reach %q, so this sweep is vacuous", expect)
	}
	var unhandled []string
	for k := range seen {
		if !handledKeywords[k] {
			unhandled = append(unhandled, k)
		}
	}
	sort.Strings(unhandled)
	require.Empty(t, unhandled,
		"lockfile.schema.json uses keywords this validator ignores, so the conformance test below is weaker than it looks: %v", unhandled)
}

// A negative control for the validator itself. Every gate needs one: a validator
// that returns no violations for anything would make the conformance test green
// and meaningless.
func TestValidatorRejectsMalformedLockfiles(t *testing.T) {
	schema := lockfileSchema(t)
	valid := `{"schemaVersion":"1.0.0","profile":{"slug":"p","name":"P"},"revision":1,` +
		`"resolvedAt":"2026-04-17T09:12:04Z","gate":"approval","entries":[],"skipped":[],"targets":[]}`

	tests := []struct {
		name string
		body string
		want string
	}{
		{"a conforming lockfile produces no violations", valid, ""},
		{"an absent required property is reported", `{"schemaVersion":"1.0.0"}`, "required property"},
		{"an undeclared top-level property is reported", `{"schemaVersion":"1.0.0","profile":{"slug":"p","name":"P"},"revision":1,"resolvedAt":"2026-04-17T09:12:04Z","gate":"approval","entries":[],"skipped":[],"targets":[],"surprise":1}`, "not declared"},
		{"a wrong schemaVersion const is reported", `{"schemaVersion":"2.0.0","profile":{"slug":"p","name":"P"},"revision":1,"resolvedAt":"2026-04-17T09:12:04Z","gate":"approval","entries":[],"skipped":[],"targets":[]}`, "const"},
		{"a gate outside the enum is reported", `{"schemaVersion":"1.0.0","profile":{"slug":"p","name":"P"},"revision":1,"resolvedAt":"2026-04-17T09:12:04Z","gate":"whatever","entries":[],"skipped":[],"targets":[]}`, "not in the enum"},
		{"a null array where one is required is reported", `{"schemaVersion":"1.0.0","profile":{"slug":"p","name":"P"},"revision":1,"resolvedAt":"2026-04-17T09:12:04Z","gate":"approval","entries":null,"skipped":[],"targets":[]}`, "expected type array"},
		{"revision 0 is below the minimum", `{"schemaVersion":"1.0.0","profile":{"slug":"p","name":"P"},"revision":0,"resolvedAt":"2026-04-17T09:12:04Z","gate":"approval","entries":[],"skipped":[],"targets":[]}`, "below the minimum"},
		{"a digest that is not sha256:<64 hex> is reported", `{"schemaVersion":"1.0.0","profile":{"slug":"p","name":"P"},"revision":1,"resolvedAt":"2026-04-17T09:12:04Z","gate":"approval","entries":[{"id":"a/b","kind":"skill","version":"1","digest":"sha256:ABC","objectKey":"k","resolution":"pinned","verdict":"clean"}],"skipped":[],"targets":[]}`, "does not match"},
		{"a resolvedAt that is not a date-time is reported", `{"schemaVersion":"1.0.0","profile":{"slug":"p","name":"P"},"revision":1,"resolvedAt":"yesterday","gate":"approval","entries":[],"skipped":[],"targets":[]}`, "date-time"},
		{"a skip reason outside the six is reported", `{"schemaVersion":"1.0.0","profile":{"slug":"p","name":"P"},"revision":1,"resolvedAt":"2026-04-17T09:12:04Z","gate":"approval","entries":[],"skipped":[{"id":"a/b","reason":"made-up"}],"targets":[]}`, "not in the enum"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			require.NoError(t, json.Unmarshal([]byte(tc.body), &doc))
			v := &validator{}
			v.check(schema, doc, "")
			if tc.want == "" {
				require.Empty(t, v.out)
				return
			}
			require.NotEmpty(t, v.out, "expected a violation mentioning %q", tc.want)
			require.Contains(t, fmt.Sprint(v.out), tc.want)
		})
	}
}
