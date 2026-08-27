package api

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"agent-manager/internal/auth"
	"agent-manager/internal/logging"
)

// CorrelationHeader is the request and response header carrying the id that ties
// a client's report, the server's logs and any job the request enqueues together
// (FR-059).
const CorrelationHeader = "X-Correlation-ID"

type correlationKey struct{}

type principalKey struct{}

// correlationIDPattern is what an inbound id may contain.
//
// An id supplied by a client lands in structured log lines and in a response
// header, so an unbounded value is a log-injection and header-splitting vector.
// Anything that does not match is replaced rather than sanitised, for the same
// reason the extractor rejects rather than fixes hostile archive entries.
var correlationIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// correlation installs the request's correlation id and logger, echoes the id
// back, and logs the request's outcome.
func correlation(base zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := inboundCorrelationID(c.Request)

		ctx := logging.Into(c.Request.Context(), base)
		ctx, log := logging.WithCorrelation(ctx, id)
		ctx = context.WithValue(ctx, correlationKey{}, id)
		c.Request = c.Request.WithContext(ctx)
		c.Header(CorrelationHeader, id)

		started := time.Now()
		c.Next()

		log.Info().
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Int("status", c.Writer.Status()).
			Dur("duration", time.Since(started)).
			Msg("request")
	}
}

func inboundCorrelationID(r *http.Request) string {
	for _, header := range []string{CorrelationHeader, "X-Request-ID"} {
		if id := strings.TrimSpace(r.Header.Get(header)); correlationIDPattern.MatchString(id) {
			return id
		}
	}
	return uuid.NewString()
}

// CorrelationFrom returns the request's correlation id, or "" outside a request.
func CorrelationFrom(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey{}).(string)
	return id
}

// PrincipalFrom returns the authenticated caller. The second result is false on a
// public operation, which is the only place a handler may run without one.
func PrincipalFrom(ctx context.Context) (auth.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(auth.Principal)
	return p, ok
}

// authenticate resolves the bearer token for every operation that declares
// security, and refuses the request when it cannot.
//
// public() is the OpenAPI rule and not a convention: a root `security` applies to
// every operation, and only an explicit empty array on the operation removes it.
// So an operation that forgot to say anything is authenticated, which is the safe
// direction for a mistake to fall in.
func (s *Server) authenticate(ctx huma.Context, next func(huma.Context)) {
	if public(ctx.Operation()) {
		next(ctx)
		return
	}

	token, ok := bearerToken(ctx.Header("Authorization"))
	if !ok {
		_ = huma.WriteErr(s.api, ctx, http.StatusUnauthorized, "missing bearer token")
		return
	}
	if s.deps.Sessions == nil {
		_ = huma.WriteErr(s.api, ctx, http.StatusServiceUnavailable, "authentication is not configured")
		return
	}

	principal, err := s.deps.Sessions.Resolve(ctx.Context(), token)
	if err != nil {
		// One message for unknown, expired and malformed alike: which one it was
		// tells an attacker whether a token ever existed.
		log := logging.From(ctx.Context())
		log.Debug().Err(err).Msg("bearer token rejected")
		_ = huma.WriteErr(s.api, ctx, http.StatusUnauthorized, "missing, expired or invalid token")
		return
	}

	next(huma.WithValue(ctx, principalKey{}, principal))
}

func public(op *huma.Operation) bool {
	return op != nil && op.Security != nil && len(op.Security) == 0
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	return token, token != ""
}
