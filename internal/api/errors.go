package api

import (
	"errors"
	"net/http"
	"runtime/debug"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/logging"
)

// newHumaError replaces huma's default ErrorModel with contract.Error, so every
// failure has one shape, including huma's own validation 422s.
func newHumaError(status int, msg string, errs ...error) huma.StatusError {
	out := contract.NewError(status, msg)
	for _, err := range errs {
		if err == nil {
			continue
		}
		var detailer huma.ErrorDetailer
		if errors.As(err, &detailer) {
			detail := detailer.ErrorDetail()
			out.Add(detail.Message, detail.Location, detail.Value)
			continue
		}
		out.Add(err.Error(), "", nil)
	}
	return out
}

// stampCorrelation puts the correlation id into error bodies; huma.NewError has no
// context to read it from.
func stampCorrelation(ctx huma.Context, _ string, v any) (any, error) {
	if err, ok := v.(*contract.Error); ok && err.CorrelationID == "" {
		err.CorrelationID = CorrelationFrom(ctx.Context())
	}
	return v, nil
}

// fail maps a domain error onto the wire. The 500 branch does not echo err, which
// may name tables or hosts; it is logged with the correlation id instead.
func fail(log zerolog.Logger, err error) error {
	switch {
	case errors.Is(err, queries.ErrNotFound):
		return huma.Error404NotFound("no such resource, or it is not readable by this identity")
	case errors.Is(err, auth.ErrUnauthenticated):
		return huma.Error401Unauthorized("missing, expired or invalid token")
	default:
		log.Error().Err(err).Msg("request failed")
		return huma.Error500InternalServerError("the request could not be completed")
	}
}

// notFound and methodNotAllowed keep gin's own misses in the same error shape as huma's.
func notFound(c *gin.Context) {
	writeGinError(c, http.StatusNotFound, "no operation at "+c.Request.URL.Path)
}

func methodNotAllowed(c *gin.Context) {
	writeGinError(c, http.StatusMethodNotAllowed, c.Request.Method+" is not allowed on "+c.Request.URL.Path)
}

func writeGinError(c *gin.Context, status int, detail string) {
	body := contract.NewError(status, detail)
	body.CorrelationID = CorrelationFrom(c.Request.Context())
	c.Header("Content-Type", "application/problem+json")
	c.AbortWithStatusJSON(status, body)
}

// recovery turns a panic into the same error shape, logged with the stack. It runs
// after correlation, so the context already carries the request's logger.
func recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				log := logging.From(c.Request.Context())
				log.Error().
					Interface("panic", r).
					Bytes("stack", debug.Stack()).
					Msg("handler panicked")
				if !c.Writer.Written() {
					writeGinError(c, http.StatusInternalServerError, "the request could not be completed")
					return
				}
				c.Abort()
			}
		}()
		c.Next()
	}
}
