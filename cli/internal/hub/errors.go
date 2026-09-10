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

// Class is what went wrong with a hub call, at a granularity a person can
// act on. Class 0 is what ClassOf returns for an error that didn't come
// from here.
type Class int

const (
	ClassUnreachable   Class = iota + 1 // nothing answered: DNS, dial, reset, or context expiry
	ClassTLS                            // handshake/cert not acceptable; remedy is a trust store, not a network
	ClassUnauthorised                   // 401: no credential, or one the hub won't accept
	ClassForbidden                      // 403: authenticated and refused
	ClassNotFound                       // 404: no such profile, revision or version
	ClassRateLimited                    // 429: retry after the interval the hub named
	ClassRequest                        // other 4xx: the CLI sent something the hub wouldn't take
	ClassUnimplemented                  // 501: version skew between CLI and hub
	ClassUnavailable                    // 503: hub up, a dependency isn't; /v1/health says which. Retryable
	ClassServer                         // other 5xx: hub failed internally
	ClassProtocol                       // answered, but not a hub: unparseable body, or an undeclared status
	ClassOffload                        // the OBJECT STORE refused a followed 307, not the hub; never ClassForbidden
)

var ( // sentinels, one per Class, so a caller may use errors.Is; see OpError.Is
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
	ErrOffload       = errors.New("the object store the hub redirected to refused the bundle")

	ErrInsecureHub = errors.New("hub URL is not https") // returned by New; no request was made
	ErrHubURL      = errors.New("unusable hub URL")     // returned by New for an unusable URL
)

var classSentinel = map[Class]error{ // the only mapping; a new Class with no sentinel fails a completeness test
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
	ClassOffload:       ErrOffload,
}

var classSlug = map[Class]string{ // the machine-facing token --output json prints
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
	ClassOffload:       "offload-refused",
}

func (c Class) String() string {
	if s, ok := classSlug[c]; ok {
		return s
	}
	return "unclassified"
}

// Classes: the tests walk it, so a new class can't be added without a sentinel and a slug.
func Classes() []Class {
	return []Class{
		ClassUnreachable, ClassTLS, ClassUnauthorised, ClassForbidden,
		ClassNotFound, ClassRateLimited, ClassRequest, ClassUnimplemented,
		ClassUnavailable, ClassServer, ClassProtocol, ClassOffload,
	}
}

// Retryable is advice for a caller's retry loop, not permission to loop forever.
func (c Class) Retryable() bool {
	switch c {
	case ClassUnreachable, ClassRateLimited, ClassUnavailable, ClassServer:
		return true
	case ClassOffload: // a pre-signed URL's commonest failure is gone by the next run's fresh URL
		return true
	case ClassTLS, ClassUnauthorised, ClassForbidden, ClassNotFound,
		ClassRequest, ClassUnimplemented, ClassProtocol:
		return false
	default:
		return false
	}
}

// OpError is every error this package produces for a call that reached the
// network layer (named OpError since the generated client owns `Error`). It
// deliberately holds no *http.Request/*http.Response/http.Header or bearer
// token: wrapping the request "for context" would stringify Authorization
// into every %+v log line; hub_test.go greps every field to enforce this.
type OpError struct {
	Class         Class
	Op            string // the operationId that failed: "getRevision", "health", ...
	URL           string // request target with userinfo/query/fragment removed; see safeURL
	Status        int    // HTTP status, or 0 when nothing answered
	Title         string
	Detail        string
	CorrelationID string // the hub's own request id
	RetryAfter    int    // Retry-After header's seconds, when sent
	Err           error  // underlying transport error, if any
}

// Error reads as a sentence, no capitals, and never contains a credential.
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

// message: detail, else title (skipped if it just repeats the status), else the transport error.
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

func (e *OpError) Unwrap() error { return e.Err }

func (e *OpError) Is(target error) bool {
	s, ok := classSentinel[e.Class]
	return ok && errors.Is(target, s)
}

// ClassOf walks the wrap chain, so added %w context doesn't hide the Class.
func ClassOf(err error) Class {
	var oe *OpError
	if errors.As(err, &oe) {
		return oe.Class
	}
	return 0
}

func classifyTransport(op, target string, err error) *OpError {
	class := ClassUnreachable

	// http.ErrSchemeMismatch: net/http replaces tls.RecordHeaderError with it
	// rather than wrapping it, so errors.As on the TLS type alone would miss
	// the https-at-a-plaintext-hub case --allow-plaintext-hub exists for.
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

// classifyStatus: want lists success statuses, so an undeclared 2xx is ClassProtocol, not a silent success.
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
	e.CorrelationID = resp.Header.Get("X-Correlation-ID") // survives a body this code can't parse

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

// joinDetails: the offending Value is deliberately NOT echoed; it's caller-supplied and this ends up in logs.
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

// statusClass is hand-derived from the frozen contract, not from observing a running hub.
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
		return ClassProtocol // a 1xx/2xx/3xx the operation didn't declare
	}
}

func retryAfterSeconds(resp *http.Response) int {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v) // only delta-seconds; the hub never sends the HTTP-date form
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// safeURL strips userinfo, query and fragment: getBundle's 307 carries a
// pre-signed URL whose signature is in the query string.
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

// redactURLError: net/http puts the full request URL, query included, into the error text.
func redactURLError(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	target := ue.URL
	if u, perr := url.Parse(ue.URL); perr == nil {
		target = safeURL(u)
	} else {
		if i := strings.IndexByte(target, '?'); i >= 0 {
			target = target[:i] // unparseable: drop from '?' rather than risk keeping a signature
		}
	}
	if target == ue.URL {
		return err
	}
	return &url.Error{Op: ue.Op, URL: target, Err: ue.Err}
}

// ClassifyStatus is classifyStatus for callers outside this file (bundles.go must land on the same Class table).
func ClassifyStatus(op string, resp *http.Response, body []byte, want ...int) error {
	if e := classifyStatus(op, resp, body, want...); e != nil {
		return e
	}
	return nil
}

func ClassifyTransport(op, target string, err error) error {
	if err == nil {
		return nil
	}
	return classifyTransport(op, target, err)
}

// SafeURL is the only sanctioned way to put a possibly-pre-signed URL into a message.
func SafeURL(u *url.URL) string { return safeURL(u) }
