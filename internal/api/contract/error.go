package contract

import "net/http"

// Error is the one error shape every operation in this API returns, replacing
// huma's default ErrorModel. It is RFC 9457 problem details plus the correlation
// id, so an operator can join a client's error report to the server's logs
// without asking the client to reproduce it (FR-059).
//
// Exactly one exception exists and it is in the frozen contract:
// /v1/device/token's 400 is the RFC 8628 envelope (DeviceTokenError), because a
// polling client parses those field names.
type Error struct {
	Type          string        `json:"type,omitempty" format:"uri" doc:"A URI reference to documentation for this error type."`
	Title         string        `json:"title" doc:"Short, static summary of the problem type." example:"Not Found"`
	Status        int           `json:"status" doc:"HTTP status code, repeated for client convenience." example:"404"`
	Detail        string        `json:"detail,omitempty" doc:"Explanation specific to this occurrence."`
	CorrelationID string        `json:"correlation_id,omitempty" doc:"The request's correlation id, as also returned in the X-Correlation-ID header."`
	Errors        []ErrorDetail `json:"errors,omitempty" doc:"Per-field detail, when the failure was a validation failure."`
}

// ErrorDetail locates one validation failure.
type ErrorDetail struct {
	Message  string `json:"message" doc:"What is wrong."`
	Location string `json:"location,omitempty" doc:"Where it is wrong, e.g. body.targets[0] or path.revision."`
	Value    any    `json:"value,omitempty" doc:"The offending value, echoed back."`
}

// NewError builds the shape for a status and detail. Title is derived from the
// status so it is stable across occurrences, as RFC 9457 requires.
func NewError(status int, detail string) *Error {
	return &Error{Title: http.StatusText(status), Status: status, Detail: detail}
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Title
}

// GetStatus satisfies huma.StatusError, which is how the status reaches the wire.
func (e *Error) GetStatus() int { return e.Status }

// ContentType satisfies huma.ContentTypeFilter: RFC 9457 bodies are served as
// application/problem+json, not application/json.
func (e *Error) ContentType(ct string) string {
	if ct == "application/json" {
		return "application/problem+json"
	}
	return ct
}

// Add appends a detail. It accepts huma's own ErrorDetail through the narrow
// interface huma uses, so validation failures keep their location and value.
func (e *Error) Add(message, location string, value any) {
	e.Errors = append(e.Errors, ErrorDetail{Message: message, Location: location, Value: value})
}
