package errs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCode_String(t *testing.T) {
	cases := map[Code]string{
		CodeNotFound: "NOT_FOUND", CodeForbidden: "FORBIDDEN", CodeInvalidInput: "INVALID_INPUT",
		CodeConflict: "CONFLICT", CodeTimeout: "TIMEOUT", CodeInternal: "INTERNAL", CodeUnknown: "UNKNOWN",
	}
	for code, want := range cases {
		require.Equal(t, want, code.String())
	}
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

func TestWriteHTTPError_FromTypedError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTPError(rec, NotFound("widget not found"))

	require.Equal(t, http.StatusNotFound, rec.Code)
	resp := decode(t, rec)
	require.Equal(t, http.StatusNotFound, resp.Status)
	require.Equal(t, "widget not found", resp.Detail)
	require.Equal(t, "/errors/not-found", resp.Type)
	require.Equal(t, "NOT_FOUND", resp.ErrCode)
}

func TestWriteHTTPError_Timeout(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTPError(rec, Timeout("graph query timed out"))

	require.Equal(t, http.StatusGatewayTimeout, rec.Code)
	resp := decode(t, rec)
	require.Equal(t, "graph query timed out", resp.Detail)
	require.Equal(t, "/errors/timeout", resp.Type)
	require.Equal(t, "TIMEOUT", resp.ErrCode)
}

func TestWriteHTTPError_FromPlainError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTPError(rec, context.Canceled)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Equal(t, http.StatusInternalServerError, decode(t, rec).Status)
}

func TestWriteHTTPErrorMsg(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTPErrorMsg(rec, "bad thing", http.StatusBadRequest)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	resp := decode(t, rec)
	require.Equal(t, "bad thing", resp.Detail)
	require.Equal(t, "/errors/bad-request", resp.Type)
}

func TestWriteHTTPErrorCtx(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTPErrorCtx(context.Background(), rec, "nope", http.StatusForbidden)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, "/errors/forbidden", decode(t, rec).Type)
}

func TestWriteHTTPValidationError(t *testing.T) {
	ve := &ValidationErrors{}
	ve.AddViolation("email", "must be valid")
	ve.AddViolation("role", "unknown role")

	rec := httptest.NewRecorder()
	WriteHTTPValidationError(context.Background(), rec, ve)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	resp := decode(t, rec)
	require.NotNil(t, resp.ValidationErrors)
	require.Len(t, resp.Violations, 2)
	require.Equal(t, "email", resp.Violations[0].Field)
}

func TestWriteHTTPRateLimitError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTPRateLimitError(context.Background(), rec, 42)

	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	resp := decode(t, rec)
	require.Equal(t, 42, resp.RetryAfter)
	require.Equal(t, "/errors/rate-limited", resp.Type)
}
