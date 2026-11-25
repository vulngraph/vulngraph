package httpsrv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/scan"
)

// scopedKeys authenticates "gph_<scope>" as an API key of that scope, owned by
// an admin, so the effective role is the scope's.
type scopedKeys struct{}

func (scopedKeys) Verify(_ context.Context, plaintext string) (auth.APIKeyRecord, error) {
	return auth.APIKeyRecord{ID: "k", UserID: "u", Scope: strings.TrimPrefix(plaintext, "gph_"), OwnerRole: auth.RoleAdmin}, nil
}

type countingValidator struct{ calls int }

func (v *countingValidator) Validate(context.Context, string) scan.TemplateValidation {
	v.calls++
	return scan.TemplateValidation{Valid: true}
}

// Validating a template builds a nuclei engine per call, so it is admin-only
// like test and generate.
func TestValidateTemplate_NonAdmin_403(t *testing.T) {
	v := &countingValidator{}
	srv := New(":0", Handlers{
		Auth:         auth.NewHandler(nil).WithAPIKeys(scopedKeys{}),
		Explore:      &explore.Handler{},
		ScanTemplate: scan.NewTemplateHandler(v, nil, nil),
	})
	post := func(scope string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/scans/templates/validate", strings.NewReader(`{"yaml":"id: x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer gph_"+scope)
		rec := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, req)
		return rec.Code
	}
	require.Equal(t, http.StatusForbidden, post("read"))
	require.Equal(t, http.StatusForbidden, post("write"))
	require.Zero(t, v.calls, "a non-admin must not reach the validator")
	require.Equal(t, http.StatusOK, post("admin"))
	require.Equal(t, 1, v.calls)
}
