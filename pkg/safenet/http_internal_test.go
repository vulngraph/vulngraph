package safenet

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPrivate_TableDriven(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback 127.0.0.1", "127.0.0.1", true},
		{"loopback 127.0.0.254", "127.0.0.254", true},
		{"RFC1918 10.x", "10.0.0.1", true},
		{"RFC1918 10.255.255.255", "10.255.255.255", true},
		{"RFC1918 172.16.0.1", "172.16.0.1", true},
		{"RFC1918 172.31.255.255", "172.31.255.255", true},
		{"RFC1918 192.168.0.1", "192.168.0.1", true},
		{"RFC1918 192.168.255.255", "192.168.255.255", true},
		{"CGNAT 100.64.0.1", "100.64.0.1", true},
		{"CGNAT 100.127.255.255", "100.127.255.255", true},
		{"link-local 169.254.0.1", "169.254.0.1", true},
		{"AWS IMDS 169.254.169.254", "169.254.169.254", true},
		{"current-network 0.0.0.1", "0.0.0.1", true},
		{"reserved 240.0.0.1", "240.0.0.1", true},
		{"doc TEST-NET-2 198.51.100.1", "198.51.100.1", true},
		{"doc TEST-NET-3 203.0.113.1", "203.0.113.1", true},
		{"IPv6 loopback", "::1", true},
		{"IPv6 unique-local fd00::1", "fd00::1", true},
		{"IPv6 link-local fe80::1", "fe80::1", true},
		{"unspecified ::", "::", true},
		{"unspecified 0.0.0.0", "0.0.0.0", true},
		{"IPv4-compatible ::127.0.0.1", "::127.0.0.1", true},
		{"IPv4-mapped loopback", "::ffff:127.0.0.1", true},
		{"IPv4-mapped IMDS", "::ffff:169.254.169.254", true},
		{"IPv4-mapped RFC1918", "::ffff:10.0.0.1", true},
		{"NAT64 well-known", "64:ff9b::7f00:1", true},
		{"NAT64 local-use", "64:ff9b:1::1", true},
		{"6to4 embedding 127.0.0.1", "2002:7f00:1::1", true},
		{"Teredo", "2001:0:4136:e378::1", true},
		{"benchmarking 198.18.0.1", "198.18.0.1", true},
		{"benchmarking 198.19.255.255", "198.19.255.255", true},
		{"IETF 192.0.0.192", "192.0.0.192", true},
		{"doc TEST-NET-1 192.0.2.1", "192.0.2.1", true},
		{"multicast 224.0.0.1", "224.0.0.1", true},
		{"multicast 239.255.255.250", "239.255.255.250", true},
		{"broadcast", "255.255.255.255", true},
		{"IPv6 multicast", "ff02::1", true},
		{"IPv6 site-local", "fec0::1", true},
		{"public 8.8.8.8", "8.8.8.8", false},
		{"IPv4-mapped public", "::ffff:8.8.8.8", false},
		{"not benchmarking 198.20.0.1", "198.20.0.1", false},
		{"public IPv6 2606:4700::1111", "2606:4700::1111", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 203.0.114.1", "203.0.114.1", false},
		{"public IPv6 2001:db8::1", "2001:db8::1", false},
		{"not in CGNAT 100.128.0.1", "100.128.0.1", false},
		{"not RFC1918 172.32.0.1", "172.32.0.1", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tc.ip)
			require.NotNil(t, ip, "failed to parse IP %s", tc.ip)
			got := isPrivate(ip)
			assert.Equal(t, tc.want, got, "isPrivate(%s)", tc.ip)
		})
	}
}

func TestIsPrivate_NilIP(t *testing.T) {
	t.Parallel()

	// Fail closed: an address that cannot be interpreted is not "public".
	assert.True(t, isPrivate(nil))
	assert.True(t, isPrivate(net.IP{1, 2, 3}))
}

func TestPrivateRanges_NotEmpty(t *testing.T) {
	t.Parallel()
	assert.NotEmpty(t, privateRanges, "privateRanges must be populated")
	assert.GreaterOrEqual(t, len(privateRanges), 10, "should have at least 10 private CIDR ranges")
}

func TestValidateWebhookURL_PortRestrictions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"port 80 allowed", "http://example.com:80/hook", false},
		{"port 443 allowed", "https://example.com:443/hook", false},
		{"no port (default)", "https://example.com/hook", false},
		{"port 8080 blocked", "https://example.com:8080/hook", true},
		{"port 3306 blocked", "https://example.com:3306/hook", true},
		{"port 22 blocked", "https://example.com:22/hook", true},
		{"port 9090 blocked", "https://example.com:9090/hook", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateWebhookURL(tc.url)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNew_CheckRedirectValidatesURL(t *testing.T) {
	t.Parallel()
	client := New(5 * time.Second)
	require.NotNil(t, client.CheckRedirect)

	req, _ := http.NewRequest("GET", "ftp://evil.com/payload", nil)
	err := client.CheckRedirect(req, make([]*http.Request, 0))
	assert.Error(t, err, "redirect to ftp:// should be blocked")

	via := make([]*http.Request, 5)
	for i := range via {
		via[i], _ = http.NewRequest("GET", "https://example.com", nil)
	}
	reqOK, _ := http.NewRequest("GET", "https://example.com/final", nil)
	err = client.CheckRedirect(reqOK, via)
	assert.Error(t, err, "more than 5 redirects should be blocked")
	assert.Contains(t, err.Error(), "too many redirects")
}

func TestNew_CheckRedirectAllowsValidHTTPS(t *testing.T) {
	t.Parallel()
	client := New(5 * time.Second)
	req, _ := http.NewRequest("GET", "https://example.com/redirect", nil)
	err := client.CheckRedirect(req, make([]*http.Request, 2))
	assert.NoError(t, err)
}

func TestNew_TransportConfig(t *testing.T) {
	t.Parallel()
	client := New(7 * time.Second)
	assert.Equal(t, 7*time.Second, client.Timeout)

	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "expected *http.Transport")
	assert.Equal(t, 7*time.Second, tr.ResponseHeaderTimeout)
	assert.Equal(t, 10*time.Second, tr.TLSHandshakeTimeout)
	assert.Equal(t, 10, tr.MaxIdleConns)
	assert.Equal(t, 60*time.Second, tr.IdleConnTimeout)
	assert.NotNil(t, tr.DialContext)
}

func TestNewInternal_TransportConfig(t *testing.T) {
	t.Parallel()
	for name, mk := range map[string]func(time.Duration) *http.Client{
		"NewInternal": NewInternal, "NewInternalEgress": NewInternalEgress,
		"NewInternalVia": func(d time.Duration) *http.Client { return NewInternalVia(d, nil) },
	} {
		client := mk(12 * time.Second)
		assert.Equal(t, 12*time.Second, client.Timeout, name)

		tr, ok := client.Transport.(*http.Transport)
		require.True(t, ok, "%s: expected *http.Transport", name)
		assert.Equal(t, 12*time.Second, tr.ResponseHeaderTimeout, name)
		assert.Nil(t, client.CheckRedirect, "%s should not set CheckRedirect", name)
		assert.True(t, tr.ForceAttemptHTTP2, "%s: a custom DialContext must not silently disable HTTP/2", name)
		assert.NotNil(t, tr.DialContext, name)
	}
}

// In-cluster calls (the Ladybug RPC and its shared secret) must never be
// routed through a chart-wide HTTP_PROXY.
func TestNewInternal_IgnoresProxyEnvironment(t *testing.T) {
	t.Parallel()
	tr, ok := NewInternal(0).Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, tr.Proxy, "NewInternal must not honour HTTPS_PROXY/HTTP_PROXY")
}

// An egress call goes through the env-configured proxy.
func TestNewInternalEgress_ProxyFromEnvironment(t *testing.T) {
	t.Parallel()
	tr, ok := NewInternalEgress(0).Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, tr.Proxy, "NewInternalEgress must honour HTTPS_PROXY/HTTP_PROXY")
	req, err := http.NewRequest(http.MethodGet, "https://llm.example.com/v1/chat", nil)
	require.NoError(t, err)
	want, err := http.ProxyFromEnvironment(req)
	require.NoError(t, err)
	got, err := tr.Proxy(req)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// NewInternalVia goes through the proxy it is given and no other, whatever
// the environment says, and directly without one.
func TestNewInternalVia_NamedProxyOnly(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://env-proxy.invalid:3128")
	t.Setenv("HTTP_PROXY", "http://env-proxy.invalid:3128")
	req, err := http.NewRequest(http.MethodGet, "https://codeload.github.com/x", nil)
	require.NoError(t, err)

	tr, ok := NewInternalVia(0, nil).Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, tr.Proxy, "no proxy given: direct")

	named, err := url.Parse("http://named-proxy.invalid:8080")
	require.NoError(t, err)
	tr, ok = NewInternalVia(0, named).Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, tr.Proxy)
	got, err := tr.Proxy(req)
	require.NoError(t, err)
	assert.Equal(t, named, got)
}

func TestInternalDialTimeout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		timeout, want time.Duration
	}{
		{0, maxInternalDialTimeout},
		{5 * time.Second, 5 * time.Second},
		{time.Minute, maxInternalDialTimeout},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, internalDialTimeout(tc.timeout), "timeout %s", tc.timeout)
	}
}

func TestNewInternal_ReachesLocalHTTPTestServer(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	client := NewInternal(5 * time.Second)
	resp, err := client.Get(ts.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestValidateWebhookURL_EmptyHost(t *testing.T) {
	t.Parallel()
	err := ValidateWebhookURL("https:///path")

	assert.Error(t, err)
}

func TestValidateWebhookURL_SchemeCase(t *testing.T) {
	t.Parallel()

	err := ValidateWebhookURL("HTTP://example.com/hook")

	assert.NoError(t, err)
}

func TestSSRFDialer_BadAddress(t *testing.T) {
	t.Parallel()
	d := &ssrfDialer{inner: &net.Dialer{Timeout: time.Second}}
	_, err := d.DialContext(t.Context(), "tcp", "no-port")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad address")
}

func TestSSRFDialer_DNSFailure(t *testing.T) {
	t.Parallel()
	d := &ssrfDialer{inner: &net.Dialer{Timeout: time.Second}}
	_, err := d.DialContext(t.Context(), "tcp", "this-domain-does-not-exist-vg.invalid:80")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DNS lookup failed")
}

func TestSSRFDialer_BlocksPrivateIP(t *testing.T) {
	t.Parallel()
	d := &ssrfDialer{inner: &net.Dialer{Timeout: time.Second}}
	_, err := d.DialContext(t.Context(), "tcp", "127.0.0.1:80")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SSRF blocked")
}

// The reported bypass: http://[::]:PORT reaches a listener bound to
// 127.0.0.1. The client must refuse to dial it, as it does 127.0.0.1 itself.
func TestNew_BlocksUnspecifiedAndMappedLoopback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	client := New(2 * time.Second)
	for _, host := range []string{"127.0.0.1", "[::]", "0.0.0.0", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+host+":"+port+"/", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		require.Error(t, err, host)
		assert.Contains(t, err.Error(), "SSRF blocked", host)
	}
}

func TestCheckPublicHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		host        string
		wantPrivate bool
		wantErr     bool
	}{
		{"metadata IP", "169.254.169.254", true, true},
		{"loopback IP", "127.0.0.1", true, true},
		{"RFC1918 IP", "10.1.2.3", true, true},
		{"IPv6 loopback", "::1", true, true},
		{"IPv4-mapped loopback", "::ffff:127.0.0.1", true, true},
		{"localhost name", "localhost", true, true},
		{"public IP", "8.8.8.8", false, false},
		{"empty", "", false, true},
		{"unresolvable", "this-domain-does-not-exist-vg.invalid", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := CheckPublicHost(t.Context(), tc.host)
			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.wantPrivate, errors.Is(err, ErrPrivateAddress), "err=%v", err)
		})
	}
}
