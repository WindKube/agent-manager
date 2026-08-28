package hub

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Class is what went wrong with a hub call, at the granularity a person can
// act on. FR-040 names four that must never be confused — unreachable,
// unauthorised, forbidden, not-found — and this is that list plus the answers
// the hub actually gives that are none of the four.
//
// The two additions that matter, because folding either into ClassUnreachable
// would print "check your network" while the hub is answering perfectly:
//
//   - 501 is ClassUnimplemented. The hub returns it for an operation this
//     deployment does not implement — internal/api/api_test.go asserts that as
//     intended behaviour, so it is a version skew between CLI and hub, and the
//     fix is to upgrade the hub or stop using the feature.
//   - 5xx is ClassServer (503 is ClassUnavailable). The hub is there, reached
//     the CLI's request, and failed on its own side; the correlation id is the
//     thing to quote, not the network.
//
// Class 0 is not a class: it is what ClassOf returns for an error that did not
// come from here, so a caller cannot mistake "unclassified" for "unreachable".
type Class int

// The classes. Grouped by where the diagnosis comes from: the transport
// (nothing answered), the status line, or the body.
const (
	// ClassUnreachable — nothing answered. DNS, dial, connection reset, or the
	// context expiring. A cancelled context lands here too; errors.Is still
	// reaches context.Canceled through OpError.Unwrap, so a caller that cares
	// can tell.
	ClassUnreachable Class = iota + 1
	// ClassTLS — something answered but the TLS handshake or certificate chain
	// was not acceptable. Separate from unreachable because the remedy is a
	// trust store or a URL, never a network. FR-041 is the reason this is not
	// silently downgraded.
	ClassTLS
	// ClassUnauthorised — 401. No credential, or one the hub will not accept.
	ClassUnauthorised
	// ClassForbidden — 403. Authenticated and refused: no access to the
	// profile, or a version the gate will not distribute.
	ClassForbidden
	// ClassNotFound — 404. No such profile, revision or version.
	ClassNotFound
	// ClassRateLimited — 429. Retry after the interval the hub named.
	ClassRateLimited
	// ClassRequest — any other 4xx (400, 409, 415, 422). The CLI sent
	// something the hub would not take, which is a bug here or a bad argument.
	ClassRequest
	// ClassUnimplemented — 501. See the type comment.
	ClassUnimplemented
	// ClassUnavailable — 503. The hub is up and a dependency it needs is not;
	// /v1/health says which. Retryable.
	ClassUnavailable
	// ClassServer — any other 5xx. The hub failed internally.
	ClassServer
	// ClassProtocol — something answered and it was not a hub: an
	// unparseable body, a missing body on a documented 200, or a status the
	// contract does not declare for the operation. This is what a URL pointing
	// at a load balancer's error page looks like, and calling that
	// "unreachable" sends the user hunting a network fault that is not there.
	ClassProtocol
)

// Sentinels, one per Class, so a caller may use errors.Is instead of switching
// on a Class. Both work on the same value; see OpError.Is.
var (
	ErrUnreachable   = errors.New("hub unreachable")
	ErrTLS           = errors.New("hub TLS verification failed")
	ErrUnauthorised  = errors.New("hub rejected the credential")
	ErrForbidden     = errors.New("hub refused access")
	ErrNotFound      = errors.New("hub has no such resource")
	ErrRateLimited   = errors.New("hub is rate limiting this client")
	ErrRequest       = errors.New("hub rejected the request")
	ErrUnimplemented = errors.New("hub does not implement this operation")
	ErrUnavailable   = errors.New("hub is not ready")
	ErrServer        = errors.New("hub failed internally")
	ErrProtocol      = errors.New("response did not come from a hub")

	// ErrInsecureHub is returned by New for an http:// hub without
	// Config.AllowPlaintext (FR-041). It is not a Class: no request was made.
	ErrInsecureHub = errors.New("hub URL is not https")
	// ErrHubURL is returned by New for a URL it cannot use at all.
	ErrHubURL = errors.New("unusable hub URL")
)

// classSentinel is the only mapping between the two. A new Class with no
// sentinel makes classInfo's completeness test fail rather than producing an
// error that quietly matches nothing.
var classSentinel = map[Class]error{
	ClassUnreachable:   ErrUnreachable,
	ClassTLS:           ErrTLS,
	ClassUnauthorised:  ErrUnauthorised,
	ClassForbidden:     ErrForbidden,
	ClassNotFound:      ErrNotFound,
	ClassRateLimited:   ErrRateLimited,
	ClassRequest:       ErrRequest,
	ClassUnimplemented: ErrUnimplemented,
	ClassUnavailable:   ErrUnavailable,
	ClassServer:        ErrServer,
	ClassProtocol:      ErrProtocol,
}

// classSlug is the stable machine-facing token for a Class — what
// --output json prints and what a script may switch on. The human sentence is
// classSentinel's text; these are deliberately two different strings because
// one is a contract and the other is prose.
var classSlug = map[Class]string{
	ClassUnreachable:   "unreachable",
	ClassTLS:           "tls",
	ClassUnauthorised:  "unauthorised",
	ClassForbidden:     "forbidden",
	ClassNotFound:      "not-found",
	ClassRateLimited:   "rate-limited",
	ClassRequest:       "invalid-request",
	ClassUnimplemented: "unimplemented",
	ClassUnavailable:   "unavailable",
	ClassServer:        "server-error",
	ClassProtocol:      "not-a-hub",
}

// String implements fmt.Stringer with the machine-facing slug.
func (c Class) String() string {
	if s, ok := classSlug[c]; ok {
		return s
	}
	return "unclassified"
}

// Classes lists every Class, in declaration order. The tests walk it, so a
// twelfth class cannot be added without a sentinel and a slug.
func Classes() []Class {
	return []Class{
		ClassUnreachable, ClassTLS, ClassUnauthorised, ClassForbidden,
		ClassNotFound, ClassRateLimited, ClassRequest, ClassUnimplemented,
		ClassUnavailable, ClassServer, ClassProtocol,
	}
}

// Retryable reports whether waiting and trying again could plausibly succeed
// without anything else changing. It is advice for a caller writing a retry
// loop, not permission to loop forever.
func (c Class) Retryable() bool {
	switch c {
	case ClassUnreachable, ClassRateLimited, ClassUnavailable, ClassServer:
		return true
	case ClassTLS, ClassUnauthorised, ClassForbidden, ClassNotFound,
		ClassRequest, ClassUnimplemented, ClassProtocol:
		return false
	default:
		return false
	}
}

// OpError is every error this package produces for a call that reached the
// network layer. It is named OpError rather than Error because the generated
// client already owns `Error` — that is the hub's problem+json body.
//
// WHAT THIS STRUCT DELIBERATELY DOES NOT HOLD, and must never hold: the
// *http.Request, the *http.Response, any http.Header, and the bearer token
// (FR-007). Wrapping the request "for context" is the natural thing to reach
// for and it stringifies the Authorization header into every log line that
// formats the error with %+v. The fields below are the whole of what a
// diagnosis needs, and hub_test.go formats each of them with %v and %+v and
// greps for the token.
type OpError struct {
	// Class is the diagnosis.
	Class Class
	// Op is the operationId that failed: "getRevision", "health", …
	Op string
	// URL is the request target with userinfo, query and fragment removed —
	// see safeURL for why the query in particular must go.
	URL string
	// Status is the HTTP status, or 0 when nothing answered.
	Status int
	// Title and Detail come from the hub's problem+json body when it sent one.
	Title  string
	Detail string
	// CorrelationID is the hub's own request id, which is the only useful
	// thing to quote at whoever runs the hub.
	CorrelationID string
	// RetryAfter is the Retry-After header's seconds, when the hub sent one.
	RetryAfter int
	// Err is the underlying transport error, if any. Nil for a status-derived
	// classification, because there is no cause below the status line.
	Err error
}

// Error implements error. Reads as a sentence, no capitals, and never contains
// a credential.
func (e *OpError) Error() string {
	var b strings.Builder
	b.WriteString(e.Op)
	b.WriteString(": ")
	if s, ok := classSentinel[e.Class]; ok {
		b.WriteString(s.Error())
	} else {
		b.WriteString("hub call failed")
	}
	if e.Status != 0 {
		b.WriteString(" (")
		b.WriteString(strconv.Itoa(e.Status))
		b.WriteString(")")
	}
	if e.URL != "" {
		b.WriteString(" at ")
		b.WriteString(e.URL)
	}
	if d := e.message(); d != "" {
		b.WriteString(": ")
		b.WriteString(d)
	}
	if e.RetryAfter > 0 {
		fmt.Fprintf(&b, " (retry after %ds)", e.RetryAfter)
	}
	if e.CorrelationID != "" {
		b.WriteString(" (correlation ")
		b.WriteString(e.CorrelationID)
		b.WriteString(")")
	}
	return b.String()
}

// message is the most specific explanation available: the hub's detail, else
// its title, else the transport error. Title is skipped when it merely repeats
// the status ("Not Found" on a 404), which is noise rather than diagnosis.
func (e *OpError) message() string {
	switch {
	case e.Detail != "":
		return e.Detail
	case e.Title != "" && !strings.EqualFold(strings.ReplaceAll(e.Title, " ", ""), strings.ReplaceAll(http.StatusText(e.Status), " ", "")):
		return e.Title
	case e.Err != nil:
		return e.Err.Error()
	default:
		return ""
	}
}

// Unwrap exposes the transport cause, so errors.Is(err, context.Canceled) and
// errors.As(err, &tlsErr) keep working through this type.
func (e *OpError) Unwrap() error { return e.Err }

// Is makes errors.Is(err, ErrUnauthorised) equivalent to
// ClassOf(err) == ClassUnauthorised, so a caller may pick either idiom.
func (e *OpError) Is(target error) bool {
	s, ok := classSentinel[e.Class]
	return ok && errors.Is(target, s)
}

// ClassOf reports the Class of err, or 0 if err did not come from this
// package. It walks the wrap chain, so a caller that has added its own context
// with %w still gets the diagnosis.
func ClassOf(err error) Class {
	var oe *OpError
	if errors.As(err, &oe) {
		return oe.Class
	}
	return 0
}

// classifyTransport turns a failure with no response into an OpError. url
// carries the sanitised target because a transport error is exactly the case
// where the caller has no other record of what was attempted.
func classifyTransport(op, target string, err error) *OpError {
	class := ClassUnreachable

	// A TLS failure is not a network failure, and telling someone to check
	// their connection when their corporate CA is missing wastes an afternoon.
	//
	// http.ErrSchemeMismatch is checked because net/http REPLACES the
	// tls.RecordHeaderError with it rather than wrapping it — client.go:270
	// converts, and errors.As on the tls type therefore never matches. That is
	// the exact error for pointing an https:// URL at a plaintext dev hub, i.e.
	// the mistake FR-041's flag exists to make explicit, so misclassifying it
	// as "unreachable" would hide the one case with an obvious fix.
	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	var recordErr tls.RecordHeaderError
	if errors.As(err, &certErr) ||
		errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidCert) ||
		errors.As(err, &recordErr) ||
		errors.Is(err, http.ErrSchemeMismatch) {
		class = ClassTLS
	}

	return &OpError{Class: class, Op: op, URL: target, Err: redactURLError(err)}
}

// classifyStatus turns a response the operation did not want into an OpError.
// want lists the statuses that are success for this operation; anything else
// is classified, including an undeclared 2xx, which is ClassProtocol rather
// than a silent success.
func classifyStatus(op string, resp *http.Response, body []byte, want ...int) *OpError {
	if resp == nil {
		return &OpError{Class: ClassProtocol, Op: op, Detail: "no response"}
	}
	for _, w := range want {
		if resp.StatusCode == w {
			return nil
		}
	}

	e := &OpError{
		Class:      statusClass(resp.StatusCode),
		Op:         op,
		Status:     resp.StatusCode,
		RetryAfter: retryAfterSeconds(resp),
	}
	if resp.Request != nil {
		e.URL = safeURL(resp.Request.URL)
	}
	// The correlation id is on the header as well as in the body, and the
	// header survives a body this code cannot parse — which is precisely the
	// case where it is most wanted.
	e.CorrelationID = resp.Header.Get("X-Correlation-ID")

	var problem Error
	if len(body) > 0 && json.Unmarshal(body, &problem) == nil {
		e.Title = problem.Title
		if problem.Detail != nil {
			e.Detail = *problem.Detail
		}
		if problem.CorrelationId != nil && *problem.CorrelationId != "" {
			e.CorrelationID = *problem.CorrelationId
		}
		if e.Detail == "" && problem.Errors != nil {
			e.Detail = joinDetails(*problem.Errors)
		}
	}
	return e
}

// joinDetails flattens problem+json's per-field errors into one clause, so a
// 422 says which field rather than only "Unprocessable Entity". The offending
// Value is deliberately NOT echoed: it is caller-supplied and this string ends
// up in logs.
func joinDetails(details []ErrorDetail) string {
	parts := make([]string, 0, len(details))
	for _, d := range details {
		if d.Location != nil && *d.Location != "" {
			parts = append(parts, *d.Location+": "+d.Message)
			continue
		}
		parts = append(parts, d.Message)
	}
	return strings.Join(parts, "; ")
}

// statusClass is the whole status-to-Class table. Hand-derived from the frozen
// contract's declared responses, not from observing a running hub.
func statusClass(code int) Class {
	switch code {
	case http.StatusUnauthorized:
		return ClassUnauthorised
	case http.StatusForbidden:
		return ClassForbidden
	case http.StatusNotFound:
		return ClassNotFound
	case http.StatusTooManyRequests:
		return ClassRateLimited
	case http.StatusNotImplemented:
		return ClassUnimplemented
	case http.StatusServiceUnavailable:
		return ClassUnavailable
	}
	switch {
	case code >= 500:
		return ClassServer
	case code >= 400:
		return ClassRequest
	default:
		// A 1xx, 2xx or 3xx that the operation did not declare. Something is
		// answering that is not this hub, or is a proxy in front of it.
		return ClassProtocol
	}
}

func retryAfterSeconds(resp *http.Response) int {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	// Only the delta-seconds form is read. The HTTP-date form is legal and the
	// hub does not send it; guessing at a clock skew is worse than ignoring it.
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// safeURL renders a URL for a message with everything credential-shaped
// removed: userinfo, query and fragment.
//
// The query is not paranoia. getBundle answers 307 with a pre-signed
// object-store URL whose SIGNATURE IS IN THE QUERY STRING, so a failure
// against that URL formatted as u.String() writes a working download
// credential into the log — the same defect FR-007 forbids for the bearer
// token, one layer down.
func safeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.User = nil
	c.RawQuery = ""
	c.ForceQuery = false
	c.Fragment = ""
	c.RawFragment = ""
	return c.String()
}

// redactURLError rebuilds a *url.Error with its URL sanitised. net/http puts
// the full request URL, query and all, into the error text; safeURL's reason
// applies to that text too, and this is the only place it can be applied
// because the URL is a plain string by the time it reaches us.
func redactURLError(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	target := ue.URL
	if u, perr := url.Parse(ue.URL); perr == nil {
		target = safeURL(u)
	} else {
		// Unparseable: drop everything from the first '?' rather than keep a
		// string that might carry a signature.
		if i := strings.IndexByte(target, '?'); i >= 0 {
			target = target[:i]
		}
	}
	if target == ue.URL {
		return err
	}
	return &url.Error{Op: ue.Op, URL: target, Err: ue.Err}
}

// ClassifyStatus is classifyStatus for callers outside this file — bundles.go
// classifies getBundle's streamed response itself, and must land on the same
// Class table rather than a second one. It returns a nil error interface, not
// a typed nil, when the status is wanted.
func ClassifyStatus(op string, resp *http.Response, body []byte, want ...int) error {
	if e := classifyStatus(op, resp, body, want...); e != nil {
		return e
	}
	return nil
}

// ClassifyTransport is classifyTransport for the same callers.
func ClassifyTransport(op, target string, err error) error {
	if err == nil {
		return nil
	}
	return classifyTransport(op, target, err)
}

// SafeURL is safeURL for the same callers: it is the only sanctioned way to
// put a URL that may be a pre-signed object-store URL into a message.
func SafeURL(u *url.URL) string { return safeURL(u) }
