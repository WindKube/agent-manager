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

// CorrelationHeader is the request and response header carrying the id that ties
// a client's report, the server's logs and any job the request enqueues together
// (FR-059).
const CorrelationHeader = "X-Correlation-ID"

type correlationKey struct{}

type principalKey struct{}

// sessionTokenKey carries the raw bearer token the request presented.
//
// Only sign-out reads it, and only because it must expire the session that was
// actually used: the principal names the identity, not which of its sessions this
// request is, and expiring all of them would be a remote sign-out nobody asked
// for. The plaintext is already in the request's own Authorization header for the
// whole of the request, so this widens nothing — but it is a credential on a
// context, so it stays unexported and there is exactly one reader.
type sessionTokenKey struct{}

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
			Str("path", logSafePath(c)).
			Int("status", c.Writer.Status()).
			Dur("duration", time.Since(started)).
			Msg("request")
	}
}

// logSafePath is what a request log line names as the path.
//
// The device approval routes carry a bearer-equivalent user code in the path.
// gin's c.FullPath() returns the route template, never the value a caller
// sent, so using it for those two routes avoids logging the secret.
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

// PrincipalFrom returns the authenticated caller. The second result is false on a
// public operation, which is the only place a handler may run without one — the
// catalog is not one of them: public anonymous browsing is out of scope (spec.md).
func PrincipalFrom(ctx context.Context) (auth.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(auth.Principal)
	return p, ok
}

// sessionTokenFrom returns the raw bearer token the request presented, or "" when
// it presented none.
func sessionTokenFrom(ctx context.Context) string {
	token, _ := ctx.Value(sessionTokenKey{}).(string)
	return token
}

// authenticate resolves the bearer token for every operation that declares
// security, and refuses the request when it cannot.
//
// bearerRequired() is the OpenAPI rule and not a convention: a root `security`
// applies to every operation, and only what the operation itself declares can
// displace it. So an operation that forgot to say anything is authenticated,
// which is the safe direction for a mistake to fall in.
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
		// One message for unknown, expired and malformed alike: which one it was
		// tells an attacker whether a token ever existed.
		log := logging.From(ctx.Context())
		log.Debug().Err(err).Msg("bearer token rejected")
		_ = huma.WriteErr(s.api, ctx, http.StatusUnauthorized, "missing, expired or invalid token")
		return
	}

	next(huma.WithValue(huma.WithValue(ctx, principalKey{}, principal), sessionTokenKey{}, token))
}

// bearerRequired reports whether an operation is authenticated by a session
// token.
//
// It asks whether the bearer scheme is among the operation's requirements rather
// than whether the operation declared any, because one operation is authenticated
// by something else entirely: the session mint's caller is a role holding a
// shared secret, not a person holding a session (contracts/auth.md). Declaring
// that operation `security: []` would have kept this function shorter and made the
// document say the mint is unauthenticated, which it is not.
//
// nil means "inherit the root", and the root is the bearer scheme.
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

// ---- rate limiting -----------------------------------------------------------

// rateLimiter is a fixed-window counter per key.
//
// In-process, and therefore per replica: two api replicas each allow the burst,
// so the effective cap is the burst times the replica count. That is stated
// rather than hidden, and it is acceptable here because the limit exists to bound
// a population by orders of magnitude, not to meter a quota. A shared limiter
// would be a Redis this project does not run or a table this layer would have to
// migrate.
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

// allow reports whether one more request from key fits, and how long the caller
// should be told to wait when it does not.
//
// It fails CLOSED when the key table is full of live entries: an unauthenticated
// endpoint whose limiter can be evicted by flooding it with fresh keys is a
// limiter with an off switch.
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

// blocked reports whether key has already spent its burst in the current window,
// without spending any of it.
//
// It is the read half of a limiter that counts OUTCOMES rather than attempts: a
// caller checks before doing the work and records only when the work failed. A key
// it has never seen is not blocked, which is the one direction this cannot fail
// closed in — see limitSessionMint for why that is the right trade there.
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

// record counts one event against key. Unlike allow it never refuses: the caller
// has already decided the event happened, and there is nothing left to permit.
//
// A full key table drops the record rather than evicting a live one, because
// evicting is what an attacker with many addresses would be aiming for. Dropping
// costs one uncounted failure; evicting costs another key its whole budget.
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
	// sessionMintFailureBurst is how many REFUSED session mints one address may
	// collect in a window before it is answered 429 with no comparison performed
	// at all.
	//
	// Refusals and not attempts, which is the whole design: a legitimate sign-in
	// authenticates successfully every time, so a cap on attempts would be a cap on
	// how many people may sign in per minute — and behind one reverse proxy, or from
	// one web replica, every sign-in shares a key. That cap would be reached by a
	// busy morning rather than by an attack. Counting only failures cannot be
	// reached by a working deployment at all.
	sessionMintFailureBurst = 5
	// sessionMintFailureWindow is the fixed window those failures are counted in.
	sessionMintFailureWindow = time.Minute
	// sessionMintFailureMaxKeys bounds the limiter's memory. Smaller than the
	// device flow's: the legitimate caller set here is the web role's replicas,
	// not every machine that ever ran the CLI.
	sessionMintFailureMaxKeys = 1024
)

// limitSessionMint caps guessing at the shared secret. contracts/auth.md requires
// it in as many words, and the reason is the operation: a caller who finds the
// secret can mint a session for any subject, so unlimited guesses is the one thing
// this endpoint must not offer.
//
// The key is the peer address and NOT X-Forwarded-For, for the same reason
// limitDeviceAuthorize gives: a client-settable header as a rate-limit key is a
// rate limit with a bypass switch.
//
// What this does not stop is an attacker who can rotate source addresses — five
// guesses per address, and a fresh address resets the budget. That is inherent to
// any address-keyed limit and it does not matter here: the secret is a
// high-entropy value an operator generated, so the population being searched is
// not one a rate limit is the last defence against. The limit exists so that a
// SHORT or reused secret, which is the realistic operator mistake, is not
// brute-forceable in an afternoon.
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

	// After the fact, because the outcome is what is being counted and only the
	// handler knows it.
	//
	// 401 and nothing else. A 503 — this hub holds no secret at all — is not a
	// guess, and counting it would turn a misconfiguration into a 429 after five
	// legitimate attempts, replacing the one answer that tells an operator what is
	// wrong with one that does not. A 422 is a token that did not verify, which
	// means the secret was already accepted.
	if ctx.Status() == http.StatusUnauthorized {
		s.mintLimiter.record(key, time.Now())
	}
}
