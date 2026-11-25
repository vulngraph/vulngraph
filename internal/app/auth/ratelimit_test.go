package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func fakeClock(l *KeyedLimiter) *time.Time {
	now := time.Unix(1_800_000_000, 0)
	l.now = func() time.Time { return now }
	return &now
}

func TestKeyedLimiter_TokenBucket(t *testing.T) {
	l := NewKeyedLimiter(6, 3) // one token per 10s, burst 3
	now := fakeClock(l)

	for i := range 3 {
		ok, _ := l.Allow("k")
		require.True(t, ok, "burst request %d", i)
	}
	ok, wait := l.Allow("k")
	require.False(t, ok)
	require.Equal(t, 10*time.Second, wait)

	ok, _ = l.Allow("other")
	require.True(t, ok, "keys are independent")

	*now = now.Add(10 * time.Second)
	ok, _ = l.Allow("k")
	require.True(t, ok, "refilled one token")
	ok, _ = l.Allow("k")
	require.False(t, ok)

	*now = now.Add(time.Hour)
	for range 3 {
		ok, _ = l.Allow("k")
		require.True(t, ok)
	}
	ok, _ = l.Allow("k")
	require.False(t, ok, "refill is capped at burst")
}

func TestKeyedLimiter_DisabledAndNil(t *testing.T) {
	for range 100 {
		ok, _ := NewKeyedLimiter(0, 1).Allow("k")
		require.True(t, ok)
		ok, _ = (*KeyedLimiter)(nil).Allow("k")
		require.True(t, ok)
	}
}

func TestKeyedLimiter_EvictsWhenFull(t *testing.T) {
	l := NewKeyedLimiter(60, 1)
	now := fakeClock(l)
	l.maxKeys = 8
	for i := range 20 {
		*now = now.Add(time.Second)
		l.Allow(fmt.Sprintf("k%d", i))
		require.LessOrEqual(t, len(l.buckets), l.maxKeys)
	}
	_, recent := l.buckets["k19"]
	require.True(t, recent, "the most recent key survives eviction")
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	require.Equal(t, "10.0.0.1", ClientIP(r, "", proxies), "headers are ignored unless configured")
	require.Equal(t, "2.2.2.2", ClientIP(r, "X-Forwarded-For", proxies), "last hop, which the proxy appended")

	r.Header.Del("X-Forwarded-For")
	require.Equal(t, "10.0.0.1", ClientIP(r, "X-Forwarded-For", proxies), "falls back to the peer")
}

// CLIENT_IP_HEADER used to be honoured from any peer, so a caller that reached
// the pod directly chose the address keying its own login rate limit and the
// executor's same-address flag. The header now counts only from a trusted proxy.
func TestClientIP_HeaderOnlyFromTrustedProxies(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	require.Equal(t, "203.0.113.9", ClientIP(r, "X-Forwarded-For", nil), "no trusted proxies: header ignored")
	require.Equal(t, "203.0.113.9", ClientIP(r, "X-Forwarded-For", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}),
		"peer outside the trusted ranges: header ignored")
	require.Equal(t, "1.2.3.4", ClientIP(r, "X-Forwarded-For", []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32")}))

	r.RemoteAddr = "[::ffff:10.1.2.3]:443"
	require.Equal(t, "1.2.3.4", ClientIP(r, "X-Forwarded-For", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}),
		"an IPv4-mapped peer matches its IPv4 range")
}

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies(" 10.0.0.0/8, 192.168.1.7 ,fd00::/8,::ffff:172.16.0.0/108,")
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.1.7/32"), netip.MustParsePrefix("fd00::/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
	}, got, "an IPv4-mapped range is unmapped so it can match an unmapped peer")

	got, err = ParseTrustedProxies("")
	require.NoError(t, err)
	require.Empty(t, got)

	_, err = ParseTrustedProxies("10.0.0.0/8,10.0.0/8")
	require.Error(t, err, "a typo must fail loudly, not silently drop a range")
}

// RequireAuth resolves the client address once, with the configured trusted
// header, so downstream audit checks (the executor's same-address flag) see
// the client rather than the proxy.
func TestRequireAuth_AttachesTrustedClientIP(t *testing.T) {
	keys := fakeKeys{"gph_k": {ID: "k1", UserID: "u1", Scope: "read", OwnerEmail: "a@corp.example",
		OwnerRole: RoleViewer, ExpiresAt: time.Now().Add(time.Hour)}}
	seen := func(h *Handler) string {
		var ip string
		r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
		r.RemoteAddr = "10.0.0.1:5555"
		r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
		r.Header.Set("Authorization", "Bearer gph_k")
		h.RequireAuth(func(_ http.ResponseWriter, r *http.Request) { ip = ClientIPFromContext(r.Context()) })(httptest.NewRecorder(), r)
		return ip
	}

	h := NewHandler(NewService(newFakeRepo())).WithAPIKeys(keys)
	require.Equal(t, "10.0.0.1", seen(h), "without a configured header it is the TCP peer")
	proxy := netip.MustParsePrefix("10.0.0.0/8")
	require.Equal(t, "10.0.0.1", seen(h.WithClientIPHeader("X-Forwarded-For")), "a header without trusted proxies is ignored")
	require.Equal(t, "2.2.2.2", seen(h.WithClientIPHeader("X-Forwarded-For", proxy)))
	require.Equal(t, "2.2.2.2", seen(NewHandlerBypass().WithClientIPHeader("X-Forwarded-For", proxy)), "bypass mode too")
}

func loginRequestFor(email, password string) *http.Request {
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:1234"
	return r
}

func TestLoginHandler_RateLimitedPerAccount(t *testing.T) {
	h, _ := newTestHandler(t)
	h.WithLoginRateLimit(NewKeyedLimiter(100, 100), NewKeyedLimiter(2, 2))

	for range 2 {
		rec := httptest.NewRecorder()
		h.Login(rec, loginRequestFor("admin@example.com", "wrong-password-xx"))
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}
	rec := httptest.NewRecorder()
	h.Login(rec, loginRequestFor("ADMIN@example.com", testPassword))
	require.Equal(t, http.StatusTooManyRequests, rec.Code, "even the right password waits; case variants share a bucket")
	require.NotEmpty(t, rec.Header().Get("Retry-After"))
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))

	rec = httptest.NewRecorder()
	h.Login(rec, loginRequestFor("viewer@example.com", testPassword))
	require.Equal(t, http.StatusOK, rec.Code, "another account is unaffected")
}

func TestLoginHandler_RateLimitedPerIP(t *testing.T) {
	h, _ := newTestHandler(t)
	h.WithLoginRateLimit(NewKeyedLimiter(1, 1), NewKeyedLimiter(100, 100))

	rec := httptest.NewRecorder()
	h.Login(rec, loginRequestFor("a@example.com", "x"))
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	rec = httptest.NewRecorder()
	h.Login(rec, loginRequestFor("b@example.com", "x"))
	require.Equal(t, http.StatusTooManyRequests, rec.Code, "spraying other accounts from one IP is limited")
}

func TestLoginHandler_OneGenericErrorForEveryFactor(t *testing.T) {
	h, _ := newTestHandler(t)
	_, err := h.svc.EnrollTOTP(t.Context(), "admin@example.com")
	require.NoError(t, err)

	details := map[string]bool{}
	for _, tc := range []struct{ email, password string }{
		{"admin@example.com", testPassword},        // right password, missing code
		{"admin@example.com", "wrong-password-xx"}, // wrong password
		{"nobody@example.com", testPassword},       // unknown account
	} {
		rec := httptest.NewRecorder()
		h.Login(rec, loginRequestFor(tc.email, tc.password))
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		var problem struct{ Detail string }
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &problem))
		details[problem.Detail] = true
	}
	require.Len(t, details, 1, "responses must not distinguish the failed factor: %v", details)
	require.NotContains(t, loginFailedDetail, "required")
}

func TestRateLimitPerUser(t *testing.T) {
	l := NewKeyedLimiter(1, 1)
	calls := 0
	h := RateLimitPerUser(l, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	run := func(u *User) int {
		req := httptest.NewRequest(http.MethodPost, "/api/graph/nl", nil)
		if u != nil {
			req = req.WithContext(ContextWithUser(req.Context(), *u))
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec.Code
	}
	alice, bob := &User{ID: "alice"}, &User{ID: "bob"}
	require.Equal(t, http.StatusOK, run(alice))
	require.Equal(t, http.StatusTooManyRequests, run(alice))
	require.Equal(t, http.StatusOK, run(bob), "budgets are per user")
	require.Equal(t, http.StatusUnauthorized, run(nil))
	require.Equal(t, 2, calls)
}
