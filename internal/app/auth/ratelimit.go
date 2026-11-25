package auth

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
)

// KeyedLimiter is an in-memory token bucket per key (client IP, account,
// user ID). It is per process: with N serve replicas the effective limit is
// N times the configured one. That is accepted for a single-replica default;
// a multi-replica deployment that needs exact limits must enforce them at the
// ingress.
type KeyedLimiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	buckets map[string]*bucket
	maxKeys int
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// limiterMaxKeys bounds memory: past it, the least recently used buckets are
// evicted (a stale bucket has refilled anyway).
const limiterMaxKeys = 50_000

// NewKeyedLimiter allows burst requests per key immediately, refilling at
// perMinute. perMinute <= 0 disables limiting (Allow always succeeds).
func NewKeyedLimiter(perMinute float64, burst int) *KeyedLimiter {
	return &KeyedLimiter{
		perSec:  perMinute / 60,
		burst:   float64(max(burst, 1)),
		buckets: map[string]*bucket{},
		maxKeys: limiterMaxKeys,
		now:     time.Now,
	}
}

// Allow takes one token from key's bucket. When none is left it returns false
// and how long until one will be.
func (l *KeyedLimiter) Allow(key string) (bool, time.Duration) {
	if l == nil || l.perSec <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		l.evictIfFull()
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.perSec)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.perSec * float64(time.Second))
	return false, wait
}

// evictIfFull drops the least recently touched quarter of the buckets once
// the map reaches maxKeys. Called with mu held.
func (l *KeyedLimiter) evictIfFull() {
	if len(l.buckets) < l.maxKeys {
		return
	}
	cutoff := l.oldestQuartile()
	for k, b := range l.buckets {
		if !b.last.After(cutoff) {
			delete(l.buckets, k)
		}
	}
}

func (l *KeyedLimiter) oldestQuartile() time.Time {
	times := make([]time.Time, 0, len(l.buckets))
	for _, b := range l.buckets {
		times = append(times, b.last)
	}
	slices.SortFunc(times, time.Time.Compare)
	return times[len(times)/4]
}

// retryAfterSeconds rounds a wait up to whole seconds for Retry-After.
func retryAfterSeconds(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}

type ctxClientIPKey struct{}

// ContextWithClientIP records the caller's resolved address. RequireAuth sets
// it on every authenticated request; tests use it directly.
func ContextWithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ctxClientIPKey{}, ip)
}

// ClientIPFromContext returns the address RequireAuth resolved with ClientIP
// (honouring CLIENT_IP_HEADER), or "" outside an authenticated request.
func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(ctxClientIPKey{}).(string)
	return ip
}

// ClientIP returns the caller's address. By default it is the TCP peer.
// Behind a proxy every request shares the proxy's address, so the operator
// names the header the proxy sets (CLIENT_IP_HEADER, e.g. X-Forwarded-For) and
// the proxy's addresses (TRUSTED_PROXY_CIDRS). The header's LAST entry is used
// — the one the nearest proxy appended — and only when the TCP peer is in
// trusted: a request that reached the pod directly could put any address there,
// and that address keys the login rate limit and the executor's same-address
// audit flag. No trusted ranges means the header is never honoured.
func ClientIP(r *http.Request, header string, trusted []netip.Prefix) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peer = host
	}
	if header == "" || !peerTrusted(peer, trusted) {
		return peer
	}
	if v := r.Header.Values(header); len(v) > 0 {
		parts := strings.Split(v[len(v)-1], ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	return peer
}

func peerTrusted(peer string, trusted []netip.Prefix) bool {
	addr, err := netip.ParseAddr(peer)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// ParseTrustedProxies parses TRUSTED_PROXY_CIDRS: comma-separated CIDRs or
// bare addresses. A malformed entry is an error, not skipped: a typo would
// otherwise silently stop honouring the client-IP header.
func ParseTrustedProxies(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("ParseTrustedProxies: %q: %w", s, err)
			}
			out = append(out, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("ParseTrustedProxies: %q: %w", s, err)
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			// ::ffff:a.b.c.d/n would never match: peers are unmapped before the check.
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// DefaultLLMPerUserPerMinute is the default per-user budget for LLM-backed
// routes (LLM_RATE_LIMIT_PER_USER).
const DefaultLLMPerUserPerMinute = 10

// RateLimitPerUser limits an authenticated route per user ID (wrap it inside
// RequireAuth). Used for the LLM-backed routes, whose cost any viewer could
// otherwise drive without bound.
func RateLimitPerUser(l *KeyedLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok {
			errs.WriteHTTPErrorCtx(r.Context(), w, "not authenticated", http.StatusUnauthorized)
			return
		}
		if allowed, wait := l.Allow(user.ID); !allowed {
			errs.WriteHTTPRateLimitError(r.Context(), w, retryAfterSeconds(wait))
			return
		}
		next(w, r)
	}
}
