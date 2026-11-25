package safenet_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

func TestValidateWebhookURL(t *testing.T) {
	t.Parallel()

	ok := []string{
		"https://hooks.slack.com/services/abc/def/ghi",
		"https://events.pagerduty.com/v2/enqueue",
		"http://my-webhook.example.com/hook",
		"https://api.example.com/webhook?token=abc",
	}
	for _, u := range ok {
		if err := safenet.ValidateWebhookURL(u); err != nil {
			t.Errorf("expected %q to be valid, got: %v", u, err)
		}
	}

	bad := []struct {
		url string
		why string
	}{
		{"ftp://example.com/hook", "non-http scheme"},
		{"file:///etc/passwd", "file scheme"},
		{"/relative/path", "relative URL — no scheme"},
		{"://bad", "malformed URL"},
		{"https://", "missing host"},
		{"", "empty"},
	}
	for _, tc := range bad {
		if err := safenet.ValidateWebhookURL(tc.url); err == nil {
			t.Errorf("expected %q (%s) to fail validation, got nil", tc.url, tc.why)
		}
	}
}

func TestNew_blocksSwitchLoopback(t *testing.T) {
	t.Parallel()
	client := safenet.New(10 * time.Second)

	// These should all be blocked by the SSRF transport.
	blocked := []string{
		"http://127.0.0.1/",
		"http://localhost/",
		"http://169.254.169.254/latest/meta-data/", // AWS IMDS
		"http://10.0.0.1/",
		"http://192.168.1.1/",
		"http://172.16.0.1/",
	}
	for _, u := range blocked {
		resp, err := client.Get(u) //nolint:noctx
		if err == nil {
			resp.Body.Close()
			t.Errorf("expected %q to be SSRF-blocked but request succeeded", u)
		}
	}
}

func TestNew_noTimeout(t *testing.T) {
	t.Parallel()
	// Ensure New always returns a client with a timeout set.
	client := safenet.New(10 * time.Second)
	if client.Timeout == 0 {
		t.Error("safenet.New returned client with zero timeout")
	}
}

func TestNewInternal_ReturnsClient(t *testing.T) {
	t.Parallel()
	client := safenet.NewInternal(5 * time.Second)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", client.Timeout)
	}
}

func TestNewInternal_AllowsPrivateIPs(t *testing.T) {
	t.Parallel()
	// NewInternal should NOT block private IPs (it's for internal services).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := safenet.NewInternal(5 * time.Second)
	resp, err := client.Get(ts.URL) //nolint:noctx
	if err != nil {
		t.Fatalf("expected internal client to reach local server, got: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestNew_AllowsPublicHTTPServers(t *testing.T) {
	t.Parallel()
	// A local httptest server binds to 127.0.0.1 which is blocked by SSRF.
	// So we test that the client struct is properly configured.
	client := safenet.New(3 * time.Second)
	if client.Timeout != 3*time.Second {
		t.Errorf("expected 3s timeout, got %v", client.Timeout)
	}
	if client.Transport == nil {
		t.Error("expected non-nil transport")
	}
	if client.CheckRedirect == nil {
		t.Error("expected non-nil CheckRedirect for redirect SSRF protection")
	}
}

func TestNew_TooManyRedirects(t *testing.T) {
	t.Parallel()
	// Create a server that always redirects to itself.
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ts.URL, http.StatusFound)
	}))
	defer ts.Close()

	// NewInternal doesn't block private IPs so we can test redirect limiting.
	client := safenet.NewInternal(5 * time.Second)
	// Go's default is 10 redirects; NewInternal doesn't override CheckRedirect.
	_, err := client.Get(ts.URL) //nolint:noctx
	if err == nil {
		t.Error("expected error from redirect loop")
	}
}

func TestValidateWebhookURL_AcceptsPrivateIPFormat(t *testing.T) {
	t.Parallel()
	// ValidateWebhookURL only checks URL format (scheme, host presence).
	// Private IP blocking is done at the transport/dial level, not URL validation.
	privateURLs := []string{
		"http://127.0.0.1/hook",
		"http://10.0.0.1/hook",
		"http://192.168.1.1/hook",
	}
	for _, u := range privateURLs {
		err := safenet.ValidateWebhookURL(u)
		if err != nil {
			t.Errorf("ValidateWebhookURL should accept %q (blocking is at transport level), got: %v", u, err)
		}
	}
}
