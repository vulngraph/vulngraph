// Package errs provides typed application errors with HTTP status mapping,
// RFC 9457 Problem Details response writing, and server-side error logging.
//
// Use the sentinel errors for Is checks:
//
//	if errors.Is(err, errs.ErrNotFound) { ... }
//
// Use the constructors to add context:
//
//	return errs.NotFound("connector " + id)
//	return errs.Wrap(err, "fetchConnector")
//
// HTTP handlers write errors with:
//
//	errs.WriteHTTPErrorMsg(w, "id required", http.StatusBadRequest)
//	errs.WriteHTTPErrorCtx(r.Context(), w, "query failed", http.StatusInternalServerError)
package errs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/vulngraph/vulngraph/pkg/log"
	"go.opentelemetry.io/otel/trace"
)

// Code classifies an error for mapping to an HTTP status.
type Code int

const (
	CodeUnknown      Code = 0
	CodeNotFound     Code = 1
	CodeForbidden    Code = 2
	CodeInvalidInput Code = 3
	CodeConflict     Code = 4
	CodeTimeout      Code = 5
	CodeInternal     Code = 6
	CodeUnavailable  Code = 7
)

func (c Code) String() string {
	switch c {
	case CodeNotFound:
		return "NOT_FOUND"
	case CodeForbidden:
		return "FORBIDDEN"
	case CodeInvalidInput:
		return "INVALID_INPUT"
	case CodeConflict:
		return "CONFLICT"
	case CodeTimeout:
		return "TIMEOUT"
	case CodeInternal:
		return "INTERNAL"
	case CodeUnavailable:
		return "UNAVAILABLE"
	default:
		return "UNKNOWN"
	}
}

// Error is a typed application error with an optional wrapped cause.
type Error struct {
	code  Code
	msg   string
	cause error
}

// Sentinel errors for use with errors.Is.
var (
	ErrNotFound     = &Error{code: CodeNotFound, msg: "not found"}
	ErrForbidden    = &Error{code: CodeForbidden, msg: "forbidden"}
	ErrInvalidInput = &Error{code: CodeInvalidInput, msg: "invalid input"}
	ErrConflict     = &Error{code: CodeConflict, msg: "conflict"}
	ErrTimeout      = &Error{code: CodeTimeout, msg: "timeout"}
	ErrInternal     = &Error{code: CodeInternal, msg: "internal error"}
	ErrUnavailable  = &Error{code: CodeUnavailable, msg: "unavailable"}
)

func (e *Error) Error() string {
	if e.cause != nil {
		return e.msg + ": " + e.cause.Error()
	}
	return e.msg
}

func (e *Error) Unwrap() error { return e.cause }

// Is matches by code so errors.Is(err, ErrNotFound) works for any
// *Error with CodeNotFound, not just the sentinel pointer.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.code == t.code
}

// Code returns the error's classification code.
func (e *Error) Code() Code { return e.code }

// HTTPStatus maps the error's code to an HTTP status code.
func (e *Error) HTTPStatus() int {
	switch e.code {
	case CodeNotFound:
		return http.StatusNotFound
	case CodeForbidden:
		return http.StatusForbidden
	case CodeInvalidInput:
		return http.StatusBadRequest
	case CodeConflict:
		return http.StatusConflict
	case CodeTimeout:
		return http.StatusGatewayTimeout
	case CodeUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// Constructors

// NotFound creates a not-found error with the given message.
func NotFound(msg string) error { return &Error{code: CodeNotFound, msg: msg} }

// Forbidden creates a forbidden error.
func Forbidden(msg string) error { return &Error{code: CodeForbidden, msg: msg} }

// InvalidInput creates a bad-input error.
func InvalidInput(msg string) error { return &Error{code: CodeInvalidInput, msg: msg} }

// Conflict creates a conflict error.
func Conflict(msg string) error { return &Error{code: CodeConflict, msg: msg} }

// Internal creates an internal error.
func Internal(msg string) error { return &Error{code: CodeInternal, msg: msg} }

// Unavailable creates a service-unavailable error (503) — e.g. a readiness
// check while a backing store is still warming up.
func Unavailable(msg string) error { return &Error{code: CodeUnavailable, msg: msg} }

// Timeout creates a gateway-timeout error (504) — an upstream engine or
// service did not answer within its deadline.
func Timeout(msg string) error { return &Error{code: CodeTimeout, msg: msg} }

// Wrap wraps an error with a context message, preserving the error chain.
func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", msg, err)
}

// New creates a new internal error. Prefer typed constructors when the
// error kind is known.
func New(msg string) error { return &Error{code: CodeInternal, msg: msg} }

// HTTPStatus extracts the HTTP status from err, defaulting to 500.
func HTTPStatus(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.HTTPStatus()
	}
	return http.StatusInternalServerError
}

// ── Validation Errors ─────────────────────────────────────────────────────────

// FieldViolation describes a single field that failed validation.
type FieldViolation struct {
	Field       string `json:"field"`
	Description string `json:"description"`
}

// ValidationErrors holds one or more field-level validation failures.
// Serialised as an RFC 9457 extension field on ErrorResponse.
type ValidationErrors struct {
	Violations []FieldViolation `json:"violations"`
}

// AddViolation appends a field-level validation error.
func (v *ValidationErrors) AddViolation(field, description string) {
	v.Violations = append(v.Violations, FieldViolation{Field: field, Description: description})
}

// ── RFC 9457 Problem Details ──────────────────────────────────────────────────

// ErrorResponse is an RFC 9457 Problem Details response body.
// Serialised as application/problem+json.
type ErrorResponse struct {
	Type       string `json:"type,omitempty"`                // URI identifying the problem type
	Title      string `json:"title"`                         // Short human-readable summary
	Status     int    `json:"status"`                        // HTTP status code
	Detail     string `json:"detail,omitempty"`              // Human-readable explanation
	Instance   string `json:"instance,omitempty"`            // URI identifying the specific occurrence (trace_id)
	ErrCode    string `json:"err_code,omitempty"`            // Application-specific error code (e.g. "RATE_LIMITED")
	RetryAfter int    `json:"retry_after_seconds,omitempty"` // Retry delay for 429 responses

	// ValidationErrors carries field-level validation failures.
	// Populated when Status is 400 and multiple fields are invalid.
	*ValidationErrors `json:",omitempty"`
}

// traceIDFromCtx extracts the OTel trace ID from context, if any.
// This is the primary correlation identifier — it links the error response
// to the distributed trace in the configured OTLP trace backend.
func traceIDFromCtx(ctx context.Context) string {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if sc.HasTraceID() {
		return sc.TraceID().String()
	}
	return ""
}

// requestIDFromCtx extracts the request ID that httpsrv.withRequestID injects.
// Used as a fallback correlation identifier when OTel tracing is unavailable.
func requestIDFromCtx(ctx context.Context) string {
	return log.RequestIDFromContext(ctx)
}

// problemType returns the "type" URI for a given HTTP status.
// In production, these should point to documentation pages.
func problemType(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "/errors/bad-request"
	case http.StatusUnauthorized:
		return "/errors/unauthorized"
	case http.StatusForbidden:
		return "/errors/forbidden"
	case http.StatusNotFound:
		return "/errors/not-found"
	case http.StatusConflict:
		return "/errors/conflict"
	case http.StatusRequestEntityTooLarge:
		return "/errors/payload-too-large"
	case http.StatusTooManyRequests:
		return "/errors/rate-limited"
	case http.StatusServiceUnavailable:
		return "/errors/unavailable"
	case http.StatusGatewayTimeout:
		return "/errors/timeout"
	default:
		return "/errors/internal"
	}
}

// problemTitle returns a short title for a given HTTP status.
func problemTitle(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "Bad Request"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusNotFound:
		return "Not Found"
	case http.StatusConflict:
		return "Conflict"
	case http.StatusRequestEntityTooLarge:
		return "Payload Too Large"
	case http.StatusTooManyRequests:
		return "Too Many Requests"
	case http.StatusServiceUnavailable:
		return "Service Unavailable"
	case http.StatusInternalServerError:
		return "Internal Server Error"
	case http.StatusGatewayTimeout:
		return "Gateway Timeout"
	case http.StatusMethodNotAllowed:
		return "Method Not Allowed"
	default:
		return "Error"
	}
}

// WriteHTTPErrorMsg writes a simple RFC 9457 Problem Details error response.
// Use for quick error returns where no structured errs.Error is needed.
func WriteHTTPErrorMsg(w http.ResponseWriter, detail string, status int) {
	resp := ErrorResponse{
		Type:   problemType(status),
		Title:  problemTitle(status),
		Status: status,
		Detail: detail,
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// WriteHTTPError writes an RFC 9457 Problem Details response from any error.
// If the error is an *errs.Error, the HTTP status and err_code are derived from it.
func WriteHTTPError(w http.ResponseWriter, err error) {
	status := HTTPStatus(err)
	resp := ErrorResponse{
		Type:   problemType(status),
		Title:  problemTitle(status),
		Status: status,
		Detail: err.Error(),
	}
	var e *Error
	if errors.As(err, &e) {
		resp.ErrCode = e.code.String()
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// WriteHTTPErrorCtx writes an RFC 9457 Problem Details response and logs the
// error server-side via pkg/log. The Instance field is populated with the
// trace_id from the request's OpenTelemetry span context (or X-Request-ID if set).
//
// Use this in request-scoped handlers that have access to context.Context.
func WriteHTTPErrorCtx(ctx context.Context, w http.ResponseWriter, detail string, status int) {
	resp := ErrorResponse{
		Type:   problemType(status),
		Title:  problemTitle(status),
		Status: status,
		Detail: detail,
	}
	if instance := traceIDFromCtx(ctx); instance != "" {
		resp.Instance = "trace:" + instance
	} else if reqID := requestIDFromCtx(ctx); reqID != "" {
		resp.Instance = "req:" + reqID
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
	if status >= 500 {
		log.FromContext(ctx).Error().Int("status", status).Str("detail", detail).
			Str("instance", resp.Instance).Msg("http: server error")
	} else {
		log.FromContext(ctx).Warn().Int("status", status).Str("detail", detail).
			Str("instance", resp.Instance).Msg("http: client error")
	}
}

// WriteHTTPValidationError writes a 400 Bad Request with field-level validation
// errors in RFC 9457 format. The violations are serialised as an extension field.
func WriteHTTPValidationError(ctx context.Context, w http.ResponseWriter, ve *ValidationErrors) {
	resp := ErrorResponse{
		Type:             problemType(http.StatusBadRequest),
		Title:            "Validation Error",
		Status:           http.StatusBadRequest,
		Detail:           "One or more fields failed validation",
		ValidationErrors: ve,
	}
	if instance := traceIDFromCtx(ctx); instance != "" {
		resp.Instance = "trace:" + instance
	} else if reqID := requestIDFromCtx(ctx); reqID != "" {
		resp.Instance = "req:" + reqID
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(resp)
	log.FromContext(ctx).Warn().Int("count", len(ve.Violations)).
		Interface("violations", ve.Violations).Msg("http: validation error")
}

// WriteHTTPRateLimitError writes a 429 Too Many Requests response with the
// Retry-After header and retry_after_seconds field per RFC 9457.
// Use this for all rate-limited responses so clients know when to retry.
func WriteHTTPRateLimitError(ctx context.Context, w http.ResponseWriter, retryAfter int) {
	resp := ErrorResponse{
		Type:       problemType(http.StatusTooManyRequests),
		Title:      "Too Many Requests",
		Status:     http.StatusTooManyRequests,
		Detail:     fmt.Sprintf("rate limit exceeded, retry after %d seconds", retryAfter),
		ErrCode:    "RATE_LIMITED",
		RetryAfter: retryAfter,
	}
	if instance := traceIDFromCtx(ctx); instance != "" {
		resp.Instance = "trace:" + instance
	} else if reqID := requestIDFromCtx(ctx); reqID != "" {
		resp.Instance = "req:" + reqID
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(resp)
	log.FromContext(ctx).Warn().Int("retry_after", retryAfter).Msg("http: rate limited")
}
