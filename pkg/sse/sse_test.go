package sse

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// slowStream sends a text event every 50ms for 600ms, then done — twice the
// server timeouts used below. ctxErr receives the request context's state at
// the end.
func slowStream(extend bool, ctxErr chan<- error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if extend {
			ExtendWriteDeadline(r.Context(), w, 5*time.Second)
		}
		s := NewWriter(w)
		for i := 0; i < 12; i++ {
			s.Text("x")
			time.Sleep(50 * time.Millisecond)
		}
		ctxErr <- r.Context().Err()
		s.Done()
	})
}

// startServer runs h behind otelhttp (the production outermost wrapper) with
// 300ms server Read/WriteTimeouts.
func startServer(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(otelhttp.NewHandler(h, "test"))
	srv.Config.ReadTimeout = 300 * time.Millisecond
	srv.Config.WriteTimeout = 300 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL
}

func post(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(`{}`)) //nolint:noctx // test
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func TestExtendWriteDeadline_StreamOutlivesServerTimeouts(t *testing.T) {
	ctxErr := make(chan error, 1)
	body := post(t, startServer(t, slowStream(true, ctxErr)))
	require.Contains(t, body, `{"type":"done"}`)
	require.Equal(t, 12, strings.Count(body, `"type":"text"`))
	require.NoError(t, <-ctxErr, "the server ReadTimeout must not cancel the request context")
}

// Control: the same stream without ExtendWriteDeadline is cut by WriteTimeout,
// which is what makes the test above meaningful.
func TestExtendWriteDeadline_ControlWithoutExtensionIsCut(t *testing.T) {
	ctxErr := make(chan error, 1)
	body := post(t, startServer(t, slowStream(false, ctxErr)))
	require.NotContains(t, body, `{"type":"done"}`)
}

// The controller must reach the real connection through otelhttp's wrapper.
func TestExtendWriteDeadline_SupportedThroughOtelWrapper(t *testing.T) {
	errc := make(chan error, 1)
	url := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		errc <- http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute))
	}))
	post(t, url)
	require.NoError(t, <-errc)
}

func TestWriter_HeadersGoOutWithFirstEvent(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewWriter(rec)
	require.False(t, s.Started())
	require.False(t, rec.Flushed)

	s.Text("hi")
	s.Error("boom")
	require.True(t, s.Started())
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	require.Equal(t,
		"data: {\"text\":\"hi\",\"type\":\"text\"}\n\ndata: {\"message\":\"boom\",\"type\":\"error\"}\n\n",
		rec.Body.String())
}
