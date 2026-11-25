package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTemplateService struct {
	testedTarget string
	validateCtx  context.Context
}

func (f *fakeTemplateService) Validate(ctx context.Context, _ string) TemplateValidation {
	f.validateCtx = ctx
	return TemplateValidation{Valid: true}
}

func (f *fakeTemplateService) Test(_ context.Context, _, targetURL string) ([]Result, error) {
	f.testedTarget = targetURL
	return nil, nil
}

func postTemplateTest(h *TemplateHandler, target string) *httptest.ResponseRecorder {
	body := `{"yaml":"id: x","target":"` + target + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/scans/templates/test", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Test(rec, req)
	return rec
}

func TestTemplateTest_BlocksInternalTargetsByDefault(t *testing.T) {
	t.Setenv(AllowInternalTargetsEnv, "")
	targets := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:8080/",
		"http://localhost/",
		"https://10.0.0.5/",
		"http://[::1]/",
		"http://[fd00::1]/",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			svc := &fakeTemplateService{}
			rec := postTemplateTest(NewTemplateHandler(svc, svc, nil), target)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), AllowInternalTargetsEnv)
			assert.Empty(t, svc.testedTarget, "tester must not run against a blocked target")
		})
	}
}

func TestTemplateTest_RejectsNonHTTPTargets(t *testing.T) {
	for _, target := range []string{"file:///etc/passwd", "gopher://example.com/", "http://", "example.com"} {
		t.Run(target, func(t *testing.T) {
			svc := &fakeTemplateService{}
			rec := postTemplateTest(NewTemplateHandler(svc, svc, nil), target)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Empty(t, svc.testedTarget)
		})
	}
}

func TestTemplateTest_AllowsPublicTarget(t *testing.T) {
	t.Setenv(AllowInternalTargetsEnv, "")
	svc := &fakeTemplateService{}
	rec := postTemplateTest(NewTemplateHandler(svc, svc, nil), "http://8.8.8.8/")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "http://8.8.8.8/", svc.testedTarget)
}

func TestTemplateTest_OptInStillBlocksMetadata(t *testing.T) {
	t.Setenv(AllowInternalTargetsEnv, "true")
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://[fd00:ec2::254]/",
		"http://100.100.100.200/",
		"http://metadata.google.internal/",
	} {
		t.Run(target, func(t *testing.T) {
			svc := &fakeTemplateService{}
			rec := postTemplateTest(NewTemplateHandler(svc, svc, nil), target)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Empty(t, svc.testedTarget)
		})
	}
}

func TestTemplateTest_OptInAllowsInternalTarget(t *testing.T) {
	t.Setenv(AllowInternalTargetsEnv, "true")
	svc := &fakeTemplateService{}
	rec := postTemplateTest(NewTemplateHandler(svc, svc, nil), "http://10.0.0.5/")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "http://10.0.0.5/", svc.testedTarget)
}

func TestAllowInternalTargets_RequiresExactTrue(t *testing.T) {
	for val, want := range map[string]bool{"": false, "1": false, "yes": false, "TRUE": false, "true": true} {
		t.Setenv(AllowInternalTargetsEnv, val)
		assert.Equal(t, want, AllowInternalTargets(), "value %q", val)
	}
}

func TestCaptureHTTP_BlocksLoopbackByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := CaptureHTTP(t.Context(), srv.URL, 0, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SSRF blocked")

	snap, err := CaptureHTTP(t.Context(), srv.URL, 0, true)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, snap.StatusCode)
}

type slowTemplateService struct{ fakeTemplateService }

func (s *slowTemplateService) Test(ctx context.Context, yaml, targetURL string) ([]Result, error) {
	time.Sleep(400 * time.Millisecond)
	return s.fakeTemplateService.Test(ctx, yaml, targetURL)
}

// A template test outlasting the server WriteTimeout must still get its
// response written: the handler lifts the write deadline for the test run.
func TestTemplateTest_OutlivesServerWriteTimeout(t *testing.T) {
	t.Setenv(AllowInternalTargetsEnv, "true")
	svc := &slowTemplateService{}
	h := NewTemplateHandler(svc, svc, nil)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(h.Test))
	srv.Config.WriteTimeout = 200 * time.Millisecond
	srv.Start()
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"yaml":"id: x","target":"http://10.0.0.5/"}`)) //nolint:noctx // test
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "http://10.0.0.5/", svc.testedTarget)
}

type validateCtxKey struct{}

// Validation runs on the request path, so it gets the request's context: a
// client that disconnects cancels the nuclei engine build.
func TestTemplateValidate_PassesTheRequestContext(t *testing.T) {
	t.Setenv(AllowInternalTargetsEnv, "")
	svc := &fakeTemplateService{}
	h := NewTemplateHandler(svc, svc, nil)
	for _, route := range []struct {
		path string
		call func(http.ResponseWriter, *http.Request)
		body string
	}{
		{"/api/scans/templates/validate", h.Validate, `{"yaml":"id: x"}`},
		{"/api/scans/templates/test", h.Test, `{"yaml":"id: x","target":"http://8.8.8.8/"}`},
	} {
		svc.validateCtx = nil
		ctx := context.WithValue(t.Context(), validateCtxKey{}, route.path)
		req := httptest.NewRequest(http.MethodPost, route.path, strings.NewReader(route.body)).WithContext(ctx)
		route.call(httptest.NewRecorder(), req)
		require.NotNil(t, svc.validateCtx, route.path)
		assert.Equal(t, route.path, svc.validateCtx.Value(validateCtxKey{}), route.path)
	}
}
