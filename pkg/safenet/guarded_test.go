package safenet

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func get(t *testing.T, rt http.RoundTripper, url string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := NewWithTransport(2*time.Second, rt).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

// The guarded transport blocks private destinations by default and admits
// exactly the prefixes the operator allowed — and a redirect from an allowed
// host to a blocked one still fails, because the guard is on every dial.
func TestNewGuardedTransport_AllowListAndRedirects(t *testing.T) {
	t.Parallel()
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ok.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	err := get(t, NewGuardedTransport(time.Second, nil), ok.URL)
	require.Error(t, err, "loopback must be blocked with no allow list")
	assert.Contains(t, err.Error(), "SSRF blocked")

	loop := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	require.NoError(t, get(t, NewGuardedTransport(time.Second, loop), ok.URL))

	err = get(t, NewGuardedTransport(time.Second, loop), redirect.URL)
	require.Error(t, err, "a redirect to the metadata endpoint must fail at dial time")
	assert.Contains(t, err.Error(), "SSRF blocked")
}

// Metadata endpoints that sit inside ordinary private space stay blocked even
// when an allow list covers that space: allowing fd00::/8 or 100.64.0.0/10 for
// a registry must not open AWS IPv6 IMDS or Alibaba's metadata service.
func TestSSRFDialer_MetadataAddressesIgnoreTheAllowList(t *testing.T) {
	t.Parallel()
	d := &ssrfDialer{allow: []netip.Prefix{
		netip.MustParsePrefix("fd00::/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
	}}
	for _, ip := range []string{"fd00:ec2::254", "100.100.100.200", "192.0.0.192", "168.63.129.16", "::ffff:100.100.100.200"} {
		assert.True(t, d.blocked(net.ParseIP(ip)), ip)
	}
	for _, ip := range []string{"fd00:ec2::253", "100.64.0.10", "192.0.0.10"} {
		assert.False(t, d.blocked(net.ParseIP(ip)), "%s is inside the allow list and no metadata endpoint", ip)
	}
}

// IPv6 translation addresses carry an IPv4 destination: through NAT64,
// 64:ff9b::a9fe:a9fe IS 169.254.169.254. Allow lists may not cover those
// prefixes, and the dial guard re-checks the embedded address even if one did.
func TestTranslationAddressesCannotReachMetadata(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"64:ff9b::/96", "64:ff9b::a9fe:a9fe", "64:ff9b:1::/64", "2002::/16", "2002:a9fe:a9fe::/48", "2001::/32", "2001:0:a9fe::/48"} {
		_, err := ParseAllowPrefixes(bad)
		require.Error(t, err, bad)
	}

	// Even with an allow list that (by construction elsewhere) covered them.
	d := &ssrfDialer{allow: []netip.Prefix{netip.MustParsePrefix("::/0")}}
	for _, ip := range []string{
		"64:ff9b::a9fe:a9fe",                   // NAT64 → 169.254.169.254
		"64:ff9b::6464:64c8",                   // NAT64 → 100.100.100.200
		"2002:a9fe:a9fe::1",                    // 6to4 → 169.254.169.254
		"2002:6464:64c8::1",                    // 6to4 → 100.100.100.200 (a wrong offset decodes elsewhere)
		"2001:0:a9fe:a9fe::1",                  // Teredo server → 169.254.169.254
		"2001:0:4136:e378:8000:63bf:5601:5601", // Teredo client, XOR-obfuscated → 169.254.169.254
	} {
		assert.True(t, d.blocked(net.ParseIP(ip)), ip)
	}
	assert.False(t, d.blocked(net.ParseIP("64:ff9b::a00:1")), "NAT64 to 10.0.0.1 is only private, and allowed by ::/0")
}

func TestParseAllowPrefixes(t *testing.T) {
	t.Parallel()
	got, err := ParseAllowPrefixes(" 10.20.0.0/16, 192.168.1.7 ,,fd12::/48")
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("192.168.1.7/32"),
		netip.MustParsePrefix("fd12::/48"),
	}, got)

	empty, err := ParseAllowPrefixes("")
	require.NoError(t, err)
	require.Empty(t, empty)

	for _, bad := range []string{"169.254.169.254", "169.254.0.0/16", "0.0.0.0/0", "128.0.0.0/1", "::/0", "fe80::1", "not-an-ip"} {
		_, err := ParseAllowPrefixes(bad)
		require.Error(t, err, bad)
	}
}
