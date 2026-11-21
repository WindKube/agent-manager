// The emitted document must stay a superset of the frozen contract, because the CLI
// ships separately and cannot be redeployed in step with the hub.
//
// Additions (operations, properties, keywords like format or description) are allowed;
// a frozen operation changing shape is a CLI release event, not a commit.
package api_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"agent-manager/internal/api"
	"agent-manager/internal/domain/resolve"
)

const frozenContract = "../../specs/001-agent-manager-hub/contracts/openapi.yaml"

func TestEmittedDocumentIsOpenAPI31(t *testing.T) {
	emitted := emittedDocument(t)
	require.Equal(t, "3.1.0", emitted.root["openapi"],
		"the served document must be OpenAPI 3.1")
}

func TestEmittedDocumentIsASupersetOfTheFrozenContract(t *testing.T) {
	frozen := frozenDocument(t)
	emitted := emittedDocument(t)

	frozenPaths, ok := frozen.root["paths"].(map[string]any)
	require.True(t, ok, "the frozen contract declares no paths — the gate would pass vacuously")
	require.NotEmpty(t, frozenPaths)

	emittedPaths, ok := emitted.root["paths"].(map[string]any)
	require.True(t, ok, "the emitted document declares no paths")

	seen := 0
	for path, rawItem := range frozenPaths {
		item, ok := rawItem.(map[string]any)
		require.Truef(t, ok, "frozen path %s is not an object", path)

		emittedItem, ok := emittedPaths[path].(map[string]any)
		require.Truef(t, ok, "the emitted document has no path %s", path)

		for _, method := range []string{"get", "put", "post", "delete", "patch"} {
			frozenOp, ok := item[method].(map[string]any)
			if !ok {
				continue
			}
			seen++
			emittedOp, ok := emittedItem[method].(map[string]any)
			require.Truef(t, ok, "the emitted document has no %s %s", strings.ToUpper(method), path)

			name := fmt.Sprintf("%s %s (%v)", strings.ToUpper(method), path, frozenOp["operationId"])
			t.Run(name, func(t *testing.T) {
				requireOperationSuperset(t, frozen, emitted, name, frozenOp, emittedOp)
			})
		}
	}

	// A check that extracted nothing has silently stopped testing anything.
	require.GreaterOrEqual(t, seen, 7,
		"expected at least the seven frozen operations, walked %d", seen)
}

func TestEmittedDocumentKeepsTheFrozenSecurityScheme(t *testing.T) {
	frozen := frozenDocument(t)
	emitted := emittedDocument(t)

	frozenSchemes := dig(frozen.root, "components", "securitySchemes")
	require.NotNil(t, frozenSchemes, "the frozen contract declares no security schemes")

	for name, rawScheme := range frozenSchemes.(map[string]any) {
		scheme := rawScheme.(map[string]any)
		emittedScheme := dig(emitted.root, "components", "securitySchemes", name)
		require.NotNilf(t, emittedScheme, "the emitted document has no %s security scheme", name)

		for _, field := range []string{"type", "scheme", "bearerFormat", "name", "in"} {
			want, present := scheme[field]
			if !present {
				continue
			}
			require.Equalf(t, want, emittedScheme.(map[string]any)[field],
				"security scheme %s changed its %s", name, field)
		}
	}
}

func requireOperationSuperset(t *testing.T, frozen, emitted document, name string, frozenOp, emittedOp map[string]any) {
	t.Helper()

	require.Equal(t, frozenOp["operationId"], emittedOp["operationId"], "%s changed operationId", name)

	// `security: []` removes the root requirement; public and guarded operations must stay so.
	frozenSecurity, frozenHasSecurity := frozenOp["security"]
	emittedSecurity, emittedHasSecurity := emittedOp["security"]
	if frozenHasSecurity && isEmptyList(frozenSecurity) {
		require.Truef(t, emittedHasSecurity && isEmptyList(emittedSecurity),
			"%s is unauthenticated in the frozen contract and must stay so", name)
	} else {
		require.Falsef(t, emittedHasSecurity && isEmptyList(emittedSecurity),
			"%s is authenticated in the frozen contract and must not become public", name)
	}

	requireParametersSuperset(t, frozen, emitted, name, frozenOp, emittedOp)
	requireRequestBodySuperset(t, frozen, emitted, name, frozenOp, emittedOp)
	requireResponsesSuperset(t, frozen, emitted, name, frozenOp, emittedOp)
}

func requireParametersSuperset(t *testing.T, frozen, emitted document, name string, frozenOp, emittedOp map[string]any) {
	t.Helper()

	frozenParams, _ := frozenOp["parameters"].([]any)
	emittedParams, _ := emittedOp["parameters"].([]any)

	for _, raw := range frozenParams {
		want := frozen.resolve(raw).(map[string]any)
		var got map[string]any
		for _, candidate := range emittedParams {
			c := emitted.resolve(candidate).(map[string]any)
			if c["name"] == want["name"] && c["in"] == want["in"] {
				got = c
				break
			}
		}
		require.NotNilf(t, got, "%s lost parameter %v in %v", name, want["name"], want["in"])
		require.Equalf(t, want["required"], got["required"],
			"%s parameter %v changed whether it is required", name, want["name"])
		requireSchemaSuperset(t, frozen, emitted,
			fmt.Sprintf("%s parameter %v", name, want["name"]), want["schema"], got["schema"])
	}
}

func requireRequestBodySuperset(t *testing.T, frozen, emitted document, name string, frozenOp, emittedOp map[string]any) {
	t.Helper()

	frozenBody, ok := frozen.resolve(frozenOp["requestBody"]).(map[string]any)
	if !ok {
		return
	}
	emittedBody, ok := emitted.resolve(emittedOp["requestBody"]).(map[string]any)
	require.Truef(t, ok, "%s lost its request body", name)
	require.Equalf(t, frozenBody["required"], emittedBody["required"],
		"%s changed whether its request body is required", name)

	frozenContent, _ := frozenBody["content"].(map[string]any)
	emittedContent, _ := emittedBody["content"].(map[string]any)
	for mediaType, raw := range frozenContent {
		got, ok := emittedContent[mediaType].(map[string]any)
		require.Truef(t, ok, "%s request body lost media type %s (has %s)",
			name, mediaType, keys(emittedContent))
		requireSchemaSuperset(t, frozen, emitted,
			fmt.Sprintf("%s request body (%s)", name, mediaType),
			raw.(map[string]any)["schema"], got["schema"])
	}
}

func requireResponsesSuperset(t *testing.T, frozen, emitted document, name string, frozenOp, emittedOp map[string]any) {
	t.Helper()

	frozenResponses, _ := frozenOp["responses"].(map[string]any)
	emittedResponses, _ := emittedOp["responses"].(map[string]any)
	require.NotEmptyf(t, frozenResponses, "%s declares no responses in the frozen contract", name)

	for status, raw := range frozenResponses {
		want := frozen.resolve(raw).(map[string]any)
		gotRaw, present := emittedResponses[status]
		require.Truef(t, present, "%s lost its %s response (has %s)", name, status, keys(emittedResponses))
		got := emitted.resolve(gotRaw).(map[string]any)

		// Headers are matched case-insensitively: HTTP header names are.
		frozenHeaders, _ := want["headers"].(map[string]any)
		emittedHeaders := lowerKeys(got["headers"])
		for header, rawHeader := range frozenHeaders {
			gotHeader, ok := emittedHeaders[strings.ToLower(header)]
			require.Truef(t, ok, "%s %s lost response header %s", name, status, header)
			requireSchemaSuperset(t, frozen, emitted,
				fmt.Sprintf("%s %s header %s", name, status, header),
				frozen.resolve(rawHeader).(map[string]any)["schema"],
				emitted.resolve(gotHeader).(map[string]any)["schema"])
		}

		frozenContent, _ := want["content"].(map[string]any)
		emittedContent, _ := got["content"].(map[string]any)
		for mediaType, rawMedia := range frozenContent {
			gotMedia, ok := emittedContent[mediaType].(map[string]any)
			require.Truef(t, ok, "%s %s lost media type %s (has %s)",
				name, status, mediaType, keys(emittedContent))
			requireSchemaSuperset(t, frozen, emitted,
				fmt.Sprintf("%s %s (%s)", name, status, mediaType),
				rawMedia.(map[string]any)["schema"], gotMedia["schema"])
		}
	}
}

// requireSchemaSuperset compares keyword by keyword: the emitted schema may say more but
// nothing different. Enums must match exactly, since widening breaks a client's switch too.
func requireSchemaSuperset(t *testing.T, frozen, emitted document, where string, frozenSchema, emittedSchema any) {
	t.Helper()

	want, ok := frozen.resolve(frozenSchema).(map[string]any)
	if !ok {
		return
	}
	got, ok := emitted.resolve(emittedSchema).(map[string]any)
	require.Truef(t, ok, "%s: the emitted document has no schema here", where)

	for _, keyword := range []string{"type", "format", "pattern", "const", "minimum", "maximum"} {
		wantValue, present := want[keyword]
		if !present {
			continue
		}
		require.Equalf(t, wantValue, got[keyword], "%s: %s changed", where, keyword)
	}

	if wantEnum, present := want["enum"]; present {
		require.ElementsMatchf(t, wantEnum, got["enum"], "%s: enum changed", where)
	}

	if wantRequired, present := want["required"].([]any); present {
		gotRequired, _ := got["required"].([]any)
		for _, field := range wantRequired {
			require.Containsf(t, gotRequired, field, "%s: %v is no longer required", where, field)
		}
	}

	if wantProps, present := want["properties"].(map[string]any); present {
		gotProps, _ := got["properties"].(map[string]any)
		for prop, schema := range wantProps {
			gotProp, ok := gotProps[prop]
			require.Truef(t, ok, "%s: lost property %s (has %s)", where, prop, keys(gotProps))
			requireSchemaSuperset(t, frozen, emitted, where+"."+prop, schema, gotProp)
		}
	}

	if wantItems, present := want["items"]; present {
		requireSchemaSuperset(t, frozen, emitted, where+"[]", wantItems, got["items"])
	}
}

// document is a parsed OpenAPI document plus the directory its relative $refs
// resolve against.
type document struct {
	root map[string]any
	dir  string
}

// resolve follows a $ref, loading relative file refs (./lockfile.schema.json) from disk.
func (d document) resolve(v any) any {
	for range 8 {
		node, ok := v.(map[string]any)
		if !ok {
			return v
		}
		ref, ok := node["$ref"].(string)
		if !ok {
			return v
		}
		switch {
		case strings.HasPrefix(ref, "#/"):
			target := d.root
			var next any = target
			for _, segment := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
				m, ok := next.(map[string]any)
				if !ok {
					return nil
				}
				next = m[segment]
			}
			v = next
		default:
			raw, err := os.ReadFile(filepath.Join(d.dir, ref))
			if err != nil {
				return nil
			}
			var loaded map[string]any
			if err := json.Unmarshal(raw, &loaded); err != nil {
				return nil
			}
			v = loaded
		}
	}
	return v
}

func frozenDocument(t *testing.T) document {
	t.Helper()

	raw, err := os.ReadFile(frozenContract)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &parsed))

	// Round-tripped through JSON so both sides hold float64 numbers and string keys.
	return document{root: normalise(t, parsed), dir: filepath.Dir(frozenContract)}
}

func emittedDocument(t *testing.T) document {
	t.Helper()
	return document{root: normalise(t, api.Document(api.Options{})), dir: filepath.Dir(frozenContract)}
}

func normalise(t *testing.T, v any) map[string]any {
	t.Helper()

	encoded, err := json.Marshal(v)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(encoded, &out))
	return out
}

func isEmptyList(v any) bool {
	list, ok := v.([]any)
	return ok && len(list) == 0
}

func keys(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return "nothing"
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func lowerKeys(v any) map[string]any {
	m, _ := v.(map[string]any)
	out := make(map[string]any, len(m))
	for k, value := range m {
		out[strings.ToLower(k)] = value
	}
	return out
}

func dig(root map[string]any, path ...string) any {
	var next any = root
	for _, segment := range path {
		m, ok := next.(map[string]any)
		if !ok {
			return nil
		}
		next = m[segment]
	}
	return next
}

// The resolver is the only source of lockfile skip reasons, and the separately shipped
// CLI would show a new one as an untranslated slug.
func TestTheResolverProducesExactlyTheSkipReasonsTheFrozenSchemaAdmits(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(frozenContract), "lockfile.schema.json"))
	require.NoError(t, err)

	var schema struct {
		Properties struct {
			Skipped struct {
				Items struct {
					Properties struct {
						Reason struct {
							Enum []string `json:"enum"`
						} `json:"reason"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"skipped"`
		} `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(raw, &schema))

	frozen := schema.Properties.Skipped.Items.Properties.Reason.Enum
	require.NotEmpty(t, frozen, "the skip reason enum was not found where this test looks for it")

	produced := make([]string, 0, len(resolve.Reasons()))
	for _, reason := range resolve.Reasons() {
		produced = append(produced, string(reason))
	}
	require.Equal(t, frozen, produced)
}
