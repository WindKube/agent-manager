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

// The device flow's container-free half (T088, T089). Everything here is either a
// pure function or a refusal the surface makes before it needs a database; the
// grant, the transitions and the concurrency are in device_integration_test.go.

// userCodePattern is copied from the FROZEN contract
// (specs/001-agent-manager-hub/contracts/openapi.yaml), not from the Go struct
// tag. Deriving it from the tag would compare the generator against the same
// string the generator's schema was built from, and the whole point is that the
// two sides are independent.
var userCodePattern = regexp.MustCompile(`^[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}$`)

// formRequest posts an RFC 8628 form body. The shared `request` helper labels
// every body application/json, and this endpoint's is form-encoded per §3.4.
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

	// One counter per position per glyph. Uniformity is asserted per POSITION
	// rather than over the whole string, because a generator that biases one
	// position looks fine in an aggregate count.
	seen := make([]map[rune]int, glyphs)
	for i := range seen {
		seen[i] = map[rune]int{}
	}

	for range samples {
		code, err := commands.NewUserCode()
		require.NoError(t, err)
		require.Regexp(t, userCodePattern, code)
		require.Equal(t, "-", string(code[4]), "the separator is part of the shape")

		// I, L, O and U: the four Crockford excludes. The frozen pattern rejects
		// three of them on its own, so L is the one only the generator can get
		// wrong — and the one a "generate base32 then substitute" implementation
		// leaves in.
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

	// 32 glyphs over 20000 draws is 625 expected per glyph per position. A glyph
	// the generator can never emit at some position is the failure this catches —
	// exactly what a modulo over a non-power-of-two alphabet, or a substitution
	// table, produces — and the threshold is loose enough that no fair generator
	// trips it.
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
		// The negative control. Without it a broken regexp that matches everything
		// would make every assertion above pass.
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

	// The frozen contract says client_id "must be the same client_id that opened
	// the authorisation". No column carries it, so it is hashed in: a different
	// client_id computes a different key and matches no row.
	require.NotEqual(t, same, commands.DeviceCodeHash("some-other-client", code))

	// The NUL separator, asserted rather than assumed: without it ("ab","c") and
	// ("a","bc") would be one authorisation.
	require.NotEqual(t,
		commands.DeviceCodeHash("ab", "c"),
		commands.DeviceCodeHash("a", "bc"))

	require.NotContains(t, string(same), code, "the plaintext must not survive in the stored key")
}

func TestDeviceAuthorizeRefusesAHostItWouldOtherwiseBindAndRender(t *testing.T) {
	// No database: every case below is refused before the handler needs one, which
	// is itself the assertion — validation happens before a statement is issued.
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
			"a host carrying markup, which FR-055 would have to escape on the approval page",
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
			// The negative control: a host this hub accepts must NOT be refused, or
			// every row above would pass against a handler that rejects everything.
			// With no database configured it gets as far as asking for one.
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
	// One handler, so one limiter: every other test builds its own and cannot
	// exhaust this one.
	h := handler(t, api.Deps{})
	const body = `{"client_id":"agent-manager-cli","host":"dev-laptop-01"}`

	// 40 bits of user code is only enough while the number of LIVE codes stays
	// small, so the cap on how many a caller may open is part of the entropy
	// argument and not a nicety. Poll until it bites rather than hard-coding the
	// burst, which would make the test a copy of the constant.
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

	// Every case is invalid_grant and not invalid_request: the frozen enum has no
	// invalid_request value, and of the five it does have, invalid_grant is the
	// terminal one — right for a request that will not become well-formed by being
	// repeated.
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
		// The frozen contract makes the request body required, so an absent body is
		// refused by the framework's own validation before this handler runs. It is
		// therefore the project's error shape and not the RFC envelope, and the
		// document says so on the 400 rather than describing only one of the two.
		rec := formRequest(t, handler(t, api.Deps{}), "/v1/device/token", "")
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Equal(t, "application/problem+json",
			strings.Split(rec.Header().Get("Content-Type"), ";")[0])

		var shape contract.Error
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &shape))
		require.Equal(t, http.StatusBadRequest, shape.Status)
	})

	t.Run("a well-formed request is not refused by parsing", func(t *testing.T) {
		// The negative control: with no database the well-formed request reaches the
		// point of needing one, which proves the rows above failed on their content
		// and not on the shape of the request.
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

		// `security: []` and not an absent security block: an absent one inherits
		// the document's root bearer requirement, which would make the login flow
		// require a login.
		require.NotNil(t, item.Post.Security, path)
		require.Empty(t, item.Post.Security, path)

		require.NotContains(t, item.Post.Responses, "501",
			"%s still advertises 501: a client would treat the flow as unavailable", path)
		require.Contains(t, item.Post.Responses, "200", path)
	}

	require.Contains(t, doc.Paths["/v1/device/authorize"].Post.Responses, "429",
		"the issuance cap the entropy argument depends on must stay declared")
}

// The handler is reached with no principal at all, which is what the device flow
// is for. Asserted here because a middleware change that started requiring one
// would break the only way a machine can ever get a credential.
func TestDeviceAuthorizeRunsWithNoPrincipal(t *testing.T) {
	h := handler(t, api.Deps{Sessions: resolver{err: context.Canceled}})
	rec := request(t, h, http.MethodPost, "/v1/device/authorize", "",
		`{"client_id":"agent-manager-cli","host":""}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
}

func TestDeviceOperationsDeclareEveryStatusAMalformedRequestCanProduce(t *testing.T) {
	// The document is the contract a generated client is built from, and
	// oapi-codegen leaves every typed response field nil for a status the document
	// does not declare — returning no error — so a caller that switches on those
	// fields rather than on HTTPResponse.StatusCode reads an undeclared refusal as
	// a successful empty response. These four requests are the ones the framework
	// refuses before either handler runs, and each one's status must be in the
	// document.
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

			// And the declared media type has to be the one on the wire, or a client
			// generated from the document parses the body into the wrong shape.
			sent := strings.Split(rec.Header().Get("Content-Type"), ";")[0]
			require.Contains(t, doc.Paths[tc.path].Post.Responses[status].Content, sent,
				"POST %s answered %s as %s, which the document's %s does not describe",
				tc.path, status, sent, status)
		})
	}

	t.Run("the check is not vacuous", func(t *testing.T) {
		// The negative control: a status no operation declares must fail the same
		// lookup, or the assertions above would pass against an empty response map.
		require.NotContains(t, doc.Paths["/v1/device/authorize"].Post.Responses, "418")
	})
}

func TestTheIssuedTokenIsOpaqueAndTheDocumentSaysSo(t *testing.T) {
	// Two sides of one claim, asserted together so they cannot drift apart: what the
	// token IS, and what the document SAYS it is. Both said JWT until this layer
	// landed and made the claim reachable — no client could obtain such a token
	// while /v1/device/token returned 501, so nothing had ever checked it. If tokens
	// ever do become JWTs the first half fails; if the document goes back to
	// claiming they are while they are not, the second half fails. Asserting only
	// one side would let either change land alone.
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
