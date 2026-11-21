package api

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"agent-manager/internal/auth"
	"agent-manager/internal/logging"
)

// CorrelationHeader carries the id tying a client's report, the server's logs and
// any enqueued job together.
const CorrelationHeader = "X-Correlation-ID"

type correlationKey struct{}

type principalKey struct{}

// sessionTokenKey carries the raw bearer token so sign-out can expire the session
// actually used. It is a credential on a context, so it stays unexported with one reader.
type sessionTokenKey struct{}

// correlationIDPattern bounds inbound ids, which land in logs and response headers
// (log injection, header splitting). Non-matching ids are replaced, not sanitised.
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
			Str("path", logSafePath(c)).
			Int("status", c.Writer.Status()).
			Dur("duration", time.Since(started)).
			Msg("request")
	}
}

// logSafePath logs the route template for device approval routes, whose path
// carries a bearer-equivalent user code.
func logSafePath(c *gin.Context) string {
	if full := c.FullPath(); full != "" && strings.Contains(full, ":user_code") {
		return full
	}
	return c.Request.URL.Path
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

// PrincipalFrom returns the authenticated caller. The second result is false only
// on a public operation.
func PrincipalFrom(ctx context.Context) (auth.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(auth.Principal)
	return p, ok
}

func sessionTokenFrom(ctx context.Context) string {
	token, _ := ctx.Value(sessionTokenKey{}).(string)
	return token
}

// authenticate resolves the bearer token for every operation that declares bearer
// security. An operation that declares nothing inherits the root requirement, so a
// forgotten declaration fails safe.
func (s *Server) authenticate(ctx huma.Context, next func(huma.Context)) {
	if !bearerRequired(ctx.Operation()) {
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
		// One message for unknown, expired and malformed alike, so an attacker cannot
		// tell whether a token ever existed.
		log := logging.From(ctx.Context())
		log.Debug().Err(err).Msg("bearer token rejected")
		_ = huma.WriteErr(s.api, ctx, http.StatusUnauthorized, "missing, expired or invalid token")
		return
	}

	if op := ctx.Operation(); principal.IsServiceToken() && !serviceTokenMayCall(op, principal.ServiceToken) {
		name := "this operation"
		if op != nil {
			name = op.OperationID
		}
		log := logging.From(ctx.Context())
		log.Info().Str("serviceTokenId", principal.ServiceToken.ID.String()).Str("operation", name).
			Msg("refused a service token outside its scopes")
		_ = huma.WriteErr(s.api, ctx, http.StatusForbidden, "a service token may not call "+name+" with its scopes")
		return
	}

	next(huma.WithValue(huma.WithValue(ctx, principalKey{}, principal), sessionTokenKey{}, token))
}

// bearerRequired reports whether an operation is authenticated by a session token.
// It checks for the bearer scheme specifically because the session mint is
// authenticated by a shared secret instead. nil security inherits the root (bearer).
func bearerRequired(op *huma.Operation) bool {
	if op == nil || op.Security == nil {
		return true
	}
	for _, requirement := range op.Security {
		if _, ok := requirement[BearerScheme]; ok {
			return true
		}
	}
	return false
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	return token, token != ""
}

// rateLimiter is a fixed-window counter per key. It is in-process, so the effective
// cap is the burst times the replica count; acceptable because it bounds a population
// by orders of magnitude rather than metering a quota.
type rateLimiter struct {
	mu     sync.Mutex
	burst  int
	window time.Duration
	max    int
	seen   map[string]*rateWindow
}

type rateWindow struct {
	started time.Time
	count   int
}

func newRateLimiter(burst int, window time.Duration, maxKeys int) *rateLimiter {
	return &rateLimiter{burst: burst, window: window, max: maxKeys, seen: map[string]*rateWindow{}}
}

// allow reports whether one more request from key fits, and the wait when not. It
// fails closed when the key table is full of live entries, so flooding fresh keys
// cannot evict the limiter.
func (r *rateLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if window, ok := r.seen[key]; ok {
		if now.Sub(window.started) >= r.window {
			window.started, window.count = now, 1
			return true, 0
		}
		if window.count >= r.burst {
			return false, r.window - now.Sub(window.started)
		}
		window.count++
		return true, 0
	}

	if len(r.seen) >= r.max {
		for k, window := range r.seen {
			if now.Sub(window.started) >= r.window {
				delete(r.seen, k)
			}
		}
		if len(r.seen) >= r.max {
			return false, r.window
		}
	}
	r.seen[key] = &rateWindow{started: now, count: 1}
	return true, 0
}

// blocked reports whether key has spent its burst, without spending any. Used with
// record by limiters that count outcomes rather than attempts.
func (r *rateLimiter) blocked(key string, now time.Time) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	window, ok := r.seen[key]
	if !ok || now.Sub(window.started) >= r.window {
		return false, 0
	}
	if window.count < r.burst {
		return false, 0
	}
	return true, r.window - now.Sub(window.started)
}

// record counts one event against key. A full key table drops the record rather
// than evicting a live key, which is what an attacker with many addresses wants.
func (r *rateLimiter) record(key string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if window, ok := r.seen[key]; ok {
		if now.Sub(window.started) >= r.window {
			window.started, window.count = now, 1
			return
		}
		window.count++
		return
	}

	if len(r.seen) >= r.max {
		for k, window := range r.seen {
			if now.Sub(window.started) >= r.window {
				delete(r.seen, k)
			}
		}
		if len(r.seen) >= r.max {
			return
		}
	}
	r.seen[key] = &rateWindow{started: now, count: 1}
}

// peerAddress strips the port, so a client's many connections share one key.
func peerAddress(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}

const (
	// Refused mints, not attempts: legitimate sign-ins succeed, and behind one proxy
	// they share a key, so capping attempts would throttle a busy morning.
	sessionMintFailureBurst  = 5
	sessionMintFailureWindow = time.Minute
	// Smaller than the device flow's: legitimate callers are the web role's replicas.
	sessionMintFailureMaxKeys = 1024
)

// limitSessionMint caps guessing at the shared secret, which can mint a session for
// any subject. Keyed on the peer address, not X-Forwarded-For. Address rotation
// defeats it; it exists so a short or reused secret is not brute-forceable.
func (s *Server) limitSessionMint(ctx huma.Context, next func(huma.Context)) {
	key := peerAddress(ctx.RemoteAddr())

	if blocked, retryAfter := s.mintLimiter.blocked(key, time.Now()); blocked {
		seconds := int(retryAfter.Round(time.Second).Seconds())
		if seconds < 1 {
			seconds = 1
		}
		ctx.SetHeader("Retry-After", strconv.Itoa(seconds))
		_ = huma.WriteErr(s.api, ctx, http.StatusTooManyRequests, "too many refused session mints")
		return
	}

	next(ctx)

	// Only 401 counts: a 503 (no secret configured) is a misconfiguration, not a
	// guess, and a 422 means the secret was already accepted.
	if ctx.Status() == http.StatusUnauthorized {
		s.mintLimiter.record(key, time.Now())
	}
}
