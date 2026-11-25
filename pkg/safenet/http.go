// Package safenet is the factory for every outbound HTTP client Vulngraph builds
// itself; never use http.DefaultClient (the linter bans it) or construct an
// http.Client outside this package (TestNoHTTPClientConstructedOutsideSafenet
// bans it). Of the client and transport factories, only New and
// NewGuardedTransport guard the dial against private addresses (SSRF), and
// NewGuardedTransport still admits the private prefixes an operator allowlists:
// use them for any user- or connector-supplied URL. CheckPublicHost rejects a
// private host up front, as a pre-check only (DNS can change before the dial);
// ValidateWebhookURL checks scheme, host and port, not addresses. NewInternal,
// NewInternalEgress and NewInternalVia apply no SSRF guard and are only for
// trusted URLs an operator configures.
// Third-party SDKs such as Anthropic and the cloud providers use their own
// transports unless they are given a safenet client explicitly.
//
// # SSRF protection
//
// The guarded transport resolves the destination hostname before dialing and
// rejects any address that falls into a private or reserved IP range:
//
//   - loopback, unspecified (0.0.0.0/8, ::) and RFC-1918 ranges
//   - 169.254.0.0/16 — link-local / AWS IMDS  ← the important one
//   - carrier-grade NAT, benchmarking, documentation and IETF-reserved ranges
//   - multicast and reserved space
//   - IPv6 loopback, unique-local, link-local and multicast
//   - IPv6 prefixes that embed an IPv4 address (NAT64, 6to4, Teredo);
//     IPv4-mapped addresses (::ffff:a.b.c.d) are checked as their IPv4 form
//
// The authoritative list is privateRanges.
//
// # Usage
//
//	// One-liner for webhook dispatch:
//	client := safenet.New(10 * time.Second)
//
//	// Validate a user-supplied URL before storing it:
//	if err := safenet.ValidateWebhookURL(rawURL); err != nil {
//	    return fmt.Errorf("SetWebhook: %w", err)
//	}
package safenet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// privateRanges is the list of CIDR blocks that must never be reached via
// a user-supplied URL. Checked at dial time after DNS resolution so DNS
// rebinding attacks are also blocked. Addresses are unmapped before matching,
// so an IPv4-mapped IPv6 address (::ffff:127.0.0.1) is checked as its IPv4 form.
var privateRanges = func() []netip.Prefix {
	raw := []string{
		"0.0.0.0/8",       // current network; 0.0.0.0 reaches local listeners
		"10.0.0.0/8",      // RFC-1918 class A
		"100.64.0.0/10",   // carrier-grade NAT
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local (AWS IMDS at 169.254.169.254)
		"172.16.0.0/12",   // RFC-1918 class B
		"192.0.0.0/24",    // IETF protocol assignments (incl. 192.0.0.192 Oracle IMDS)
		"192.0.2.0/24",    // documentation TEST-NET-1
		"192.168.0.0/16",  // RFC-1918 class C
		"198.18.0.0/15",   // benchmarking; used as a private range in practice
		"198.51.100.0/24", // documentation TEST-NET-2
		"203.0.113.0/24",  // documentation TEST-NET-3
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved, incl. 255.255.255.255 broadcast
		"::/96",           // unspecified (::, reaches local listeners) and deprecated IPv4-compatible
		"::1/128",         // IPv6 loopback
		"64:ff9b::/96",    // NAT64 well-known prefix: embeds an IPv4 address the gateway reaches
		"64:ff9b:1::/48",  // NAT64 local-use prefix
		"100::/64",        // discard-only
		"2001::/32",       // Teredo: embeds an arbitrary IPv4 address
		"2002::/16",       // 6to4: embeds an arbitrary IPv4 address (2002:7f00:1:: = 127.0.0.1)
		"fc00::/7",        // IPv6 unique-local
		"fe80::/10",       // IPv6 link-local
		"fec0::/10",       // deprecated IPv6 site-local
		"ff00::/8",        // IPv6 multicast
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, cidr := range raw {
		out = append(out, netip.MustParsePrefix(cidr))
	}
	return out
}()

// isPrivate reports whether ip falls into any private/reserved range. An
// address that cannot be interpreted (nil, wrong length) counts as private:
// the check must fail closed.
func isPrivate(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	for _, r := range privateRanges {
		if r.Contains(addr) {
			return true
		}
	}
	return false
}

// ValidateWebhookURL checks that rawURL is safe to use as a webhook destination:
//   - Must parse as a valid URL
//   - Scheme must be "http" or "https"
//   - Host must be non-empty
//   - Port (if explicit) must be 80 or 443 — rejects attempts to probe internal
//     services on non-standard ports (e.g. :3306 MySQL, :22 SSH)
//
// Note: IP range checks happen at dial time inside the transport so that DNS
// rebinding is also covered. Call this function before persisting the URL to
// give users early feedback.
func ValidateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid scheme %q — webhook URLs must use http or https", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("URL is missing a host")
	}
	if port := u.Port(); port != "" && port != "80" && port != "443" {
		return fmt.Errorf("invalid port %q — webhook URLs may only use port 80 or 443", port)
	}
	return nil
}

// ssrfDialer wraps net.Dialer and rejects connections to private IPs, except
// those inside an operator-declared allow list.
type ssrfDialer struct {
	inner *net.Dialer
	allow []netip.Prefix
}

// blocked reports whether ip may not be dialed: private or reserved, and not
// inside one of the allowed prefixes.
func (d *ssrfDialer) blocked(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if ok {
		if _, metadata := metadataAddrs[addr.Unmap()]; metadata {
			return true // whatever the allow list says, and even when the address is public
		}
	}
	if !isPrivate(ip) {
		return false
	}
	if !ok {
		return true
	}
	addr = addr.Unmap()
	for _, v4 := range embeddedIPv4(addr) {
		if isMetadataOrLinkLocal(v4) {
			return true // a translated address reaching the metadata endpoint
		}
	}
	for _, p := range d.allow {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

func (d *ssrfDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("safenet: bad address %q: %w", addr, err)
	}

	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("safenet: DNS lookup failed for %q: %w", host, err)
	}
	for _, ipStr := range ips {
		if d.blocked(net.ParseIP(ipStr)) {
			return nil, fmt.Errorf("safenet: SSRF blocked — %s resolves to private address %s", host, ipStr)
		}
	}

	return d.inner.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
}

// New returns an *http.Client configured with:
//   - The given timeout
//   - An SSRF-blocking transport that rejects private IPs at dial time
//   - No redirect following to private IPs (redirect chain is also checked)
//
// Call this once per component and store the result; the client is safe for
// concurrent use.
func New(timeout time.Duration) *http.Client {
	dialer := &ssrfDialer{
		inner: &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		},
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       60 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Intercept redirects so we can re-check the destination after each hop.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("safenet: too many redirects")
			}
			return ValidateWebhookURL(req.URL.String())
		},
	}
}

// NewGuardedTransport returns an SSRF-blocking transport for a client library
// that builds its own http.Clients around a caller-supplied RoundTripper — a
// container-registry client, which follows a server-chosen redirect for every
// blob and fetches tokens from whatever realm the registry's WWW-Authenticate
// header names. Guarding the DIAL rather than the URL is what covers those: a
// hostile registry pointing its token realm or a redirect at 169.254.169.254
// fails at connect time however the request was built.
//
// allow lists private prefixes the operator has declared reachable (a registry
// on RFC-1918 space); nil allows none. Build it with ParseAllowPrefixes, which
// refuses link-local ranges. No proxy is consulted: through a proxy the dial
// check would see the proxy's address, not the destination's.
func NewGuardedTransport(timeout time.Duration, allow []netip.Prefix) http.RoundTripper {
	dialer := &ssrfDialer{
		inner: &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second},
		allow: allow,
	}
	return &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       60 * time.Second,
	}
}

// metadataAddrs are cloud instance-metadata endpoints OUTSIDE link-local, so
// an allow list covering ordinary private space would otherwise open them: an
// operator allowing fd00::/8 for an IPv6 registry would hand out AWS
// credentials. The dial guard refuses them regardless of the allow list.
var metadataAddrs = map[netip.Addr]struct{}{
	netip.MustParseAddr("fd00:ec2::254"):   {}, // AWS IMDS over IPv6 (inside fc00::/7)
	netip.MustParseAddr("100.100.100.200"): {}, // Alibaba Cloud metadata (inside 100.64.0.0/10)
	netip.MustParseAddr("192.0.0.192"):     {}, // Oracle Cloud metadata (inside 192.0.0.0/24)
	netip.MustParseAddr("168.63.129.16"):   {}, // Azure WireServer (public address space)
}

// translationRanges are IPv6 prefixes that carry an IPv4 destination (NAT64,
// 6to4, Teredo). Allowing one would allow every IPv4 address it can embed —
// 64:ff9b::a9fe:a9fe is 169.254.169.254 through a NAT64 gateway — so
// ParseAllowPrefixes refuses them, and the dial guard re-checks the embedded
// address (embeddedIPv4).
var translationRanges = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
}

// embeddedIPv4 returns the IPv4 destinations an IPv6 translation address
// carries: NAT64 well-known prefix (last 32 bits), 6to4 (bits 16-47), Teredo
// (the server at bits 32-63 and the obfuscated client in the last 32 bits).
// The local-use NAT64 prefix 64:ff9b:1::/48 embeds at an operator-chosen
// length, so it has no fixed reading; it is private and never allowable.
func embeddedIPv4(addr netip.Addr) []netip.Addr {
	if !addr.Is6() {
		return nil
	}
	b := addr.As16()
	v4 := func(x [4]byte) netip.Addr { return netip.AddrFrom4(x) }
	switch {
	case translationRanges[0].Contains(addr):
		return []netip.Addr{v4([4]byte{b[12], b[13], b[14], b[15]})}
	case translationRanges[2].Contains(addr):
		return []netip.Addr{v4([4]byte{b[2], b[3], b[4], b[5]})}
	case translationRanges[3].Contains(addr):
		return []netip.Addr{
			v4([4]byte{b[4], b[5], b[6], b[7]}),
			v4([4]byte{b[12] ^ 0xff, b[13] ^ 0xff, b[14] ^ 0xff, b[15] ^ 0xff}),
		}
	}
	return nil
}

// isMetadataOrLinkLocal reports whether addr is a metadata endpoint or in a
// link-local range.
func isMetadataOrLinkLocal(addr netip.Addr) bool {
	if _, ok := metadataAddrs[addr]; ok {
		return true
	}
	for _, ll := range linkLocalRanges {
		if ll.Contains(addr) {
			return true
		}
	}
	return false
}

// linkLocalRanges can never be allowed by ParseAllowPrefixes: the cloud
// instance metadata endpoints live there, and no registry does.
var linkLocalRanges = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
}

// ParseAllowPrefixes parses a comma-separated list of CIDR prefixes or single
// IPs into an allow list for NewGuardedTransport. A prefix overlapping a
// link-local range — including any catch-all such as 0.0.0.0/0 — is an error,
// so an allow list can open a private registry subnet but never the metadata
// endpoint.
func ParseAllowPrefixes(csv string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range strings.Split(csv, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			addr, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				return nil, fmt.Errorf("safenet: %q is neither a CIDR prefix nor an IP address", raw)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		p = p.Masked()
		for _, ll := range linkLocalRanges {
			if p.Overlaps(ll) {
				return nil, fmt.Errorf("safenet: %s overlaps the link-local metadata range %s", p, ll)
			}
		}
		for _, t := range translationRanges {
			if p.Overlaps(t) {
				return nil, fmt.Errorf("safenet: %s overlaps %s, which embeds an IPv4 address (NAT64, 6to4, Teredo)", p, t)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// NewInternal returns a client suitable for trusted internal service calls
// (the serve→worker Ladybug RPC, the healthcheck, the app's own API)
// where the URL comes from environment configuration rather than user input.
// SSRF blocking is NOT applied because these endpoints may legitimately be on
// RFC-1918 addresses in dev/staging.
//
// It ignores HTTPS_PROXY/HTTP_PROXY: use it for calls that stay inside the
// cluster, some of which carry a shared secret, so a chart-wide proxy without a matching
// NO_PROXY must not route them (or the secret) through the proxy. Trusted
// calls that leave the cluster use NewInternalEgress.
//
// It keeps HTTP/2, which a custom DialContext otherwise turns off. The dial is
// bounded even when timeout is 0 (no overall deadline, e.g. a streamed LLM
// turn): an unreachable host must fail in seconds, not hang until ctx ends.
//
// MaxIdleConnsPerHost is raised above http.DefaultMaxIdleConnsPerHost (2) so
// concurrent trusted calls to one host, such as serve-pod Ladybug RPCs,
// reuse connections instead of opening a new one each time.
func NewInternal(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: internalTransport(timeout, nil)}
}

// NewInternalEgress is NewInternal for trusted calls that leave the cluster
// (an operator-configured model server, Slack, an OIDC issuer): it honours
// HTTPS_PROXY/HTTP_PROXY/NO_PROXY, since such a host may sit behind an egress
// proxy. Never use it for in-cluster calls; see NewInternal.
func NewInternalEgress(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: internalTransport(timeout, http.ProxyFromEnvironment)}
}

// NewInternalVia is NewInternal for a trusted call that leaves the cluster
// through one operator-named proxy, or directly when proxy is nil. It never
// reads HTTPS_PROXY/HTTP_PROXY, for processes that must not carry them: in a
// process that runs nuclei they would also route scan traffic.
func NewInternalVia(timeout time.Duration, proxy *url.URL) *http.Client {
	var proxyFunc func(*http.Request) (*url.URL, error)
	if proxy != nil {
		proxyFunc = http.ProxyURL(proxy)
	}
	return &http.Client{Timeout: timeout, Transport: internalTransport(timeout, proxyFunc)}
}

func internalTransport(timeout time.Duration, proxy func(*http.Request) (*url.URL, error)) *http.Transport {
	return &http.Transport{
		Proxy: proxy,
		DialContext: (&net.Dialer{
			Timeout:   internalDialTimeout(timeout),
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       60 * time.Second,
	}
}

// maxInternalDialTimeout bounds a NewInternal/NewInternalEgress/NewInternalVia connect attempt.
const maxInternalDialTimeout = 30 * time.Second

// internalDialTimeout is the connect timeout for NewInternal: the overall
// timeout when it is shorter, else maxInternalDialTimeout — never unbounded.
func internalDialTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 && timeout < maxInternalDialTimeout {
		return timeout
	}
	return maxInternalDialTimeout
}

// NewWithTransport returns an http.Client with the provided transport and
// timeout. Use this when the transport chain already includes SSRF protection
// (e.g. oauth2.Transport wrapping a safenet transport) and you need to avoid
// the raw `&http.Client{Transport: t}` literal, which is banned outside this
// package.
func NewWithTransport(timeout time.Duration, transport http.RoundTripper) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// ErrPrivateAddress is returned by CheckPublicHost when the host is, or
// resolves to, a private, loopback, link-local or reserved address.
var ErrPrivateAddress = errors.New("safenet: host resolves to a private or reserved address")

// CheckPublicHost resolves host (a hostname or IP literal, without port) and
// returns ErrPrivateAddress if ANY resolved address is private or reserved.
// Use it to reject a user-supplied target up front for engines that dial
// with their own transport instead of a safenet client. It is a pre-check
// only: the engine must still enforce the policy at dial time, because DNS
// can change between this check and the connection.
func CheckPublicHost(ctx context.Context, host string) error {
	if host == "" {
		return errors.New("safenet: empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPrivate(ip) {
			return fmt.Errorf("%w: %s", ErrPrivateAddress, host)
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return fmt.Errorf("safenet: DNS lookup failed for %q: %w", host, err)
	}
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil && isPrivate(ip) {
			return fmt.Errorf("%w: %s resolves to %s", ErrPrivateAddress, host, ipStr)
		}
	}
	return nil
}
