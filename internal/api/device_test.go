package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
)

// userCodePattern is copied from the frozen contract rather than derived from the
// struct tag, so the generator is checked against an independent source.
var userCodePattern = regexp.MustCompile(`^[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}$`)

// formRequest posts an RFC 8628 form body; the shared `request` helper always sends JSON.
func formRequest(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUserCodeMatchesTheFrozenPatternAndNeverCarriesAnAmbiguousGlyph(t *testing.T) {
	const samples = 20000
	const glyphs = 8

	// Counted per position: a generator that biases one position looks fine in aggregate.
	seen := make([]map[rune]int, glyphs)
	for i := range seen {
		seen[i] = map[rune]int{}
	}

	for range samples {
		code, err := commands.NewUserCode()
		require.NoError(t, err)
		require.Regexp(t, userCodePattern, code)
		require.Equal(t, "-", string(code[4]), "the separator is part of the shape")

		// The Crockford excludes; the pattern alone already rejects all but L.
		require.NotContains(t, code, "I")
		require.NotContains(t, code, "L")
		require.NotContains(t, code, "O")
		require.NotContains(t, code, "U")

		stripped := strings.ReplaceAll(code, "-", "")
		require.Len(t, stripped, glyphs)
		for i, glyph := range stripped {
			seen[i][glyph]++
		}
	}

	// 625 expected per glyph per position; catches a glyph that can never be emitted
	// (modulo bias, substitution tables) with a threshold no fair generator trips.
	const alphabetSize = 32
	for position, counts := range seen {
		require.Lenf(t, counts, alphabetSize,
			"position %d emitted %d distinct glyphs, want the whole 32-glyph alphabet", position, len(counts))
		for glyph, count := range counts {
			require.Greaterf(t, count, 300,
				"position %d emitted %q only %d times in %d draws", position, string(glyph), count, samples)
		}
	}

	t.Run("the pattern is not vacuous", func(t *testing.T) {
		for _, bad := range []string{"HKQ2-9FTI", "HIQ2-9FTL", "HKQ2-9FTO", "HKQ2-9FTU", "HKQ29FTL", "hkq2-9ftl", ""} {
			require.NotRegexp(t, userCodePattern, bad)
		}
	})
}

func TestDeviceCodeHashBindsTheClientIDAndYieldsNoUsableCredential(t *testing.T) {
	const code = "a-high-entropy-device-code"

	same := commands.DeviceCodeHash("agent-manager-cli", code)
	require.Len(t, same, 32, "sha256 is 32 bytes")
	require.Equal(t, same, commands.DeviceCodeHash("agent-manager-cli", code),
		"the same pair must hash to the same row key, or no poll would ever find its row")

	// No column carries client_id, so it is hashed in: a different client matches no row.
	require.NotEqual(t, same, commands.DeviceCodeHash("some-other-client", code))

	// The separator: without it ("ab","c") and ("a","bc") would be one authorisation.
	require.NotEqual(t,
		commands.DeviceCodeHash("ab", "c"),
		commands.DeviceCodeHash("a", "bc"))

	require.NotContains(t, string(same), code, "the plaintext must not survive in the stored key")
}

func TestDeviceAuthorizeRefusesAHostItWouldOtherwiseBindAndRender(t *testing.T) {
	// No database: validation must refuse before any statement is issued.
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"an empty host", `{"client_id":"agent-manager-cli","host":""}`, http.StatusUnprocessableEntity},
		{"a whitespace-only host", `{"client_id":"agent-manager-cli","host":"   "}`, http.StatusUnprocessableEntity},
		{
			"a host carrying a newline, which would forge an audit line",
			`{"client_id":"agent-manager-cli","host":"dev-laptop-01\nlogin approved"}`,
			http.StatusUnprocessableEntity,
		},
		{
			"a host carrying markup, which the approval page has to escape",
			`{"client_id":"agent-manager-cli","host":"<script>alert(1)</script>"}`,
			http.StatusUnprocessableEntity,
		},
		{
			"a host longer than any DNS name",
			`{"client_id":"agent-manager-cli","host":"` + strings.Repeat("a", 254) + `"}`,
			http.StatusUnprocessableEntity,
		},
		{"an empty client_id", `{"client_id":"","host":"dev-laptop-01"}`, http.StatusUnprocessableEntity},
		{"a missing client_id", `{"host":"dev-laptop-01"}`, http.StatusUnprocessableEntity},
		{
			// Negative control: with no database a valid host gets as far as needing one.
			"a plausible host is not refused by validation",
			`{"client_id":"agent-manager-cli","host":"dev-laptop-01.corp.example"}`,
			http.StatusInternalServerError,
		},
		{
			"an IPv6 literal is a host too",
			`{"client_id":"agent-manager-cli","host":"fe80::1"}`,
			http.StatusInternalServerError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, handler(t, api.Deps{}), http.MethodPost, "/v1/device/authorize", "", tc.body)
			require.Equal(t, tc.want, rec.Code, rec.Body.String())
		})
	}
}

func TestDeviceAuthorizeIsRateLimitedWithAnEmptyBodyAndARetryAfter(t *testing.T) {
	h := handler(t, api.Deps{})
	const body = `{"client_id":"agent-manager-cli","host":"dev-laptop-01"}`

	// 40 bits of user code is only enough while live codes stay few, so the cap is part
	// of the entropy argument. Poll rather than hard-code the burst.
	var limited *httptest.ResponseRecorder
	for range 200 {
		rec := request(t, h, http.MethodPost, "/v1/device/authorize", "", body)
		if rec.Code == http.StatusTooManyRequests {
			limited = rec
			break
		}
		require.Equal(t, http.StatusInternalServerError, rec.Code,
			"before the cap bites, the only other outcome here is the missing database")
	}
	require.NotNil(t, limited, "the issuance cap never fired: the 429 is declared but not implemented")

	require.Zero(t, limited.Body.Len(), "the 429 is declared with no body schema")
	seconds, err := strconv.Atoi(limited.Header().Get("Retry-After"))
	require.NoError(t, err, "Retry-After must be an integer number of seconds")
	require.Positive(t, seconds)
}

func TestDeviceTokenRefusesAMalformedRequestWithTheRFCEnvelope(t *testing.T) {
	const grant = "urn:ietf:params:oauth:grant-type:device_code"

	// invalid_grant, not invalid_request: the frozen enum has no invalid_request, and
	// invalid_grant is the terminal one.
	for _, tc := range []struct{ name, body string }{
		{"no grant type", "device_code=abc&client_id=agent-manager-cli"},
		{"the authorization_code grant", "grant_type=authorization_code&device_code=abc&client_id=x"},
		{"no device code", "grant_type=" + grant + "&client_id=agent-manager-cli"},
		{"an empty device code", "grant_type=" + grant + "&device_code=&client_id=agent-manager-cli"},
		{"no client id", "grant_type=" + grant + "&device_code=abc"},
		{"an unparsable body", "grant_type=%zz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := formRequest(t, handler(t, api.Deps{}), "/v1/device/token", tc.body)
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

			var envelope contract.DeviceTokenError
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
			require.Equal(t, "invalid_grant", envelope.Error)
		})
	}

	t.Run("a request with no body never enters the flow", func(t *testing.T) {
		// The framework refuses a missing required body before the handler runs, so this
		// is the project's error shape, not the RFC envelope.
		rec := formRequest(t, handler(t, api.Deps{}), "/v1/device/token", "")
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Equal(t, "application/problem+json",
			strings.Split(rec.Header().Get("Content-Type"), ";")[0])

		var shape contract.Error
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &shape))
		require.Equal(t, http.StatusBadRequest, shape.Status)
	})

	t.Run("a well-formed request is not refused by parsing", func(t *testing.T) {
		rec := formRequest(t, handler(t, api.Deps{}), "/v1/device/token",
			"grant_type="+grant+"&device_code=abc&client_id=agent-manager-cli")
		require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	})
}

func TestDeviceOperationsStayPublicAndDeclareNo501(t *testing.T) {
	doc := api.Document(api.Options{})

	for _, path := range []string{"/v1/device/authorize", "/v1/device/token"} {
		item := doc.Paths[path]
		require.NotNil(t, item)
		require.NotNil(t, item.Post)

		// `security: []`, not absent: an absent block inherits the root bearer requirement.
		require.NotNil(t, item.Post.Security, path)
		require.Empty(t, item.Post.Security, path)

		require.NotContains(t, item.Post.Responses, "501",
			"%s still advertises 501: a client would treat the flow as unavailable", path)
		require.Contains(t, item.Post.Responses, "200", path)
	}

	require.Contains(t, doc.Paths["/v1/device/authorize"].Post.Responses, "429",
		"the issuance cap the entropy argument depends on must stay declared")
}

// A middleware change requiring a principal would break the only way a machine gets a credential.
func TestDeviceAuthorizeRunsWithNoPrincipal(t *testing.T) {
	h := handler(t, api.Deps{Sessions: resolver{err: context.Canceled}})
	rec := request(t, h, http.MethodPost, "/v1/device/authorize", "",
		`{"client_id":"agent-manager-cli","host":""}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
}

func TestDeviceOperationsDeclareEveryStatusAMalformedRequestCanProduce(t *testing.T) {
	// oapi-codegen leaves typed response fields nil for an undeclared status, so a client
	// would read an undeclared framework refusal as a successful empty response.
	doc := api.Document(api.Options{})
	h := handler(t, api.Deps{})

	for _, tc := range []struct {
		name, path, contentType, body string
	}{
		{"authorize with no body", "/v1/device/authorize", "application/json", ""},
		{"authorize with a body that is not JSON", "/v1/device/authorize", "application/json", "not-json"},
		{"authorize under the token endpoint's media type", "/v1/device/authorize",
			"application/x-www-form-urlencoded", "client_id=agent-manager-cli&host=dev-laptop-01"},
		{"token with no body", "/v1/device/token", "application/x-www-form-urlencoded", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			require.GreaterOrEqual(t, rec.Code, 400, "this request is meant to be refused")
			status := strconv.Itoa(rec.Code)
			require.Containsf(t, doc.Paths[tc.path].Post.Responses, status,
				"POST %s answered %s and the document does not declare it (declares %v)",
				tc.path, status, slices.Sorted(maps.Keys(doc.Paths[tc.path].Post.Responses)))

			sent := strings.Split(rec.Header().Get("Content-Type"), ";")[0]
			require.Contains(t, doc.Paths[tc.path].Post.Responses[status].Content, sent,
				"POST %s answered %s as %s, which the document's %s does not describe",
				tc.path, status, sent, status)
		})
	}

	t.Run("the check is not vacuous", func(t *testing.T) {
		require.NotContains(t, doc.Paths["/v1/device/authorize"].Post.Responses, "418")
	})
}

func TestTheIssuedTokenIsOpaqueAndTheDocumentSaysSo(t *testing.T) {
	// What the token is and what the document says it is, asserted together so neither drifts alone.
	for range 64 {
		token, err := auth.NewToken()
		require.NoError(t, err)
		require.NotContains(t, token, ".",
			"a JWT is three dot-separated segments; this token has one and carries no claims")
		raw, err := base64.RawURLEncoding.DecodeString(token)
		require.NoError(t, err, "the token is base64url of random bytes and nothing more")
		require.Len(t, raw, 32)
	}

	scheme := api.Document(api.Options{}).Components.SecuritySchemes[api.BearerScheme]
	require.NotNil(t, scheme)
	require.Equal(t, "opaque", scheme.BearerFormat,
		"bearerFormat is a hint to a client author and nothing else, so a wrong one is "+
			"worse than none: `JWT` here is what makes someone write jwt.Parse")
	require.Contains(t, scheme.Description, "OPAQUE",
		"the machine-readable hint is one word; the description is where a client author "+
			"is told not to read an expiry out of the token")
}
