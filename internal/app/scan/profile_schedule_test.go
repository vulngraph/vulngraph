package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfileSchedule_Validated(t *testing.T) {
	tests := []struct {
		name     string
		schedule string
		ok       bool
	}{
		{"manual only", "", true},
		{"blank is manual only", "  ", true},
		{"nightly", "0 2 * * *", true},
		{"bad list item", "0 2,x * * *", false},
		{"day name", "0 2 * * 1,MON", false},
		{"four fields", "0 2 * *", false},
		{"impossible date", "0 0 31 2 *", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The repo is never reached on a rejected schedule; a nil embedded
			// ProfileRepo would panic if it were.
			svc := &ProfileService{profiles: &stubProfileRepo{}}
			if tc.ok {
				require.NoError(t, ScheduleError(tc.schedule))
				assert.Empty(t, toProfileResponse(ScanProfile{Schedule: tc.schedule}).ScheduleError)
				return
			}
			require.ErrorIs(t, ScheduleError(tc.schedule), ErrInvalidSchedule)
			_, err := svc.CreateProfile(context.Background(), "n", "", nil, true, "", false, tc.schedule, "nuclei", "all")
			require.ErrorIs(t, err, ErrInvalidSchedule)
			_, err = svc.UpdateProfile(context.Background(), "id", "n", "", nil, true, "", false, tc.schedule, "nuclei", "all")
			require.ErrorIs(t, err, ErrInvalidSchedule)
			assert.Contains(t, toProfileResponse(ScanProfile{Schedule: tc.schedule}).ScheduleError, "invalid schedule",
				"a stored invalid schedule is visibly not running")
		})
	}
}

func TestProfileHandler_InvalidSchedule400(t *testing.T) {
	h := NewProfileHandler(&ProfileService{profiles: &stubProfileRepo{}})
	body := `{"name":"n","scanner_type":"nuclei","template_strategy":"all","schedule":"0 2,x * * *"}`
	for _, tc := range []struct {
		method string
		call   func(http.ResponseWriter, *http.Request)
	}{
		{http.MethodPost, h.CreateProfile},
		{http.MethodPut, h.UpdateProfile},
	} {
		rec := httptest.NewRecorder()
		tc.call(rec, httptest.NewRequest(tc.method, "/api/scan-profiles", strings.NewReader(body)))
		require.Equal(t, http.StatusBadRequest, rec.Code, tc.method)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/problem+json", tc.method)
		assert.Contains(t, rec.Body.String(), "hour", tc.method)
	}
}

func TestProfileHandler_UnavailableStrategy400(t *testing.T) {
	h := NewProfileHandler(&ProfileService{profiles: &stubProfileRepo{}})
	body := `{"name":"n","scanner_type":"nuclei","template_strategy":"ai_contextual"}`
	for _, tc := range []struct {
		method string
		call   func(http.ResponseWriter, *http.Request)
	}{
		{http.MethodPost, h.CreateProfile},
		{http.MethodPut, h.UpdateProfile},
	} {
		rec := httptest.NewRecorder()
		tc.call(rec, httptest.NewRequest(tc.method, "/api/scan-profiles", strings.NewReader(body)))
		require.Equal(t, http.StatusBadRequest, rec.Code, tc.method)
		assert.Contains(t, rec.Body.String(), "not available", tc.method)
	}
}

func TestPresetSchedulesValidate(t *testing.T) {
	for _, p := range TriggerPresets {
		require.NoError(t, ScheduleError(p.Schedule), p.Schedule)
	}
}
