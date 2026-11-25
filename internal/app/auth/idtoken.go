package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// idTokenVerifier verifies OIDC ID tokens issued by one IdP for one client,
// against the keys the IdP publishes (discovery → jwks_uri). It is how the
// oauth2-proxy path proves identity: oauth2-proxy forwards the user's ID
// token (--set-authorization-header), and only the IdP can sign one.
type idTokenVerifier struct {
	// issuer is kept exactly as configured: iss is compared byte for byte
	// (OIDC Core 3.1.3.7), and some IdPs (Auth0) issue with a trailing slash.
	issuer          string
	audience        string
	allowUnverified bool  // OAUTH2_PROXY_OIDC_ALLOW_UNVERIFIED_EMAIL
	configErr       error // a bad issuer URL refuses every token
	client          *http.Client

	mu        sync.RWMutex
	keys      map[string]any // kid → *rsa.PublicKey | *ecdsa.PublicKey
	fetched   time.Time      // last successful key fetch
	attempted time.Time      // last fetch attempt, bounds refetch on unknown kid
}

const (
	idTokenKeyTTL        = time.Hour
	idTokenRefetchMinGap = time.Minute
	idTokenFetchTimeout  = 10 * time.Second
	// idTokenLeeway absorbs clock skew between the IdP and this host.
	idTokenLeeway = 30 * time.Second
)

// newIDTokenVerifier uses the internal client: the issuer is operator
// configuration, and may be an in-cluster IdP (Dex, Keycloak) that the
// SSRF-blocking client would refuse.
func newIDTokenVerifier(issuer, audience string, allowUnverified bool) *idTokenVerifier {
	return &idTokenVerifier{
		issuer:          issuer,
		audience:        audience,
		allowUnverified: allowUnverified,
		configErr:       ValidateOIDCIssuer(issuer),
		client:          safenet.NewInternalEgress(idTokenFetchTimeout),
	}
}

// ValidateOIDCIssuer requires an https issuer URL; plain http is accepted only
// for a loopback host (tests, a local IdP). Keys fetched over plain http from
// anywhere else could be swapped by anyone on the path.
func ValidateOIDCIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return fmt.Errorf("ValidateOIDCIssuer: %q is not an absolute URL", issuer)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("ValidateOIDCIssuer: %q must use https", issuer)
}

// idTokenClaims is the part of an ID token sign-in needs.
type idTokenClaims struct {
	Email         string     `json:"email"`
	EmailVerified *flexBool  `json:"email_verified"`
	Groups        stringList `json:"groups"`
	AZP           string     `json:"azp"`
	jwt.RegisteredClaims
}

// stringList accepts a JSON array of strings or a single string: IdPs differ
// in how they serialise a one-element groups claim.
type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = stringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("stringList: %w", err)
	}
	*s = many
	return nil
}

// Verify checks signature, issuer, audience, authorized party and expiry and
// returns the identity and groups the token asserts.
//
// email_verified must be true, as in identityFromUserInfo: the first token
// sign-in binds an existing unbound account by its email, so an IdP that lets
// users set an unverified address (Azure AD "nOAuth") would otherwise hand
// over whichever account owns it. allowUnverified is the opt-out for IdPs
// that never send the claim.
func (v *idTokenVerifier) Verify(ctx context.Context, raw string) (OIDCIdentity, []string, error) {
	if v.configErr != nil {
		return OIDCIdentity{}, nil, fmt.Errorf("idtoken: %w", v.configErr)
	}
	if err := v.refreshKeys(ctx, false); err != nil {
		return OIDCIdentity{}, nil, fmt.Errorf("idtoken: key refresh: %w", err)
	}
	var claims idTokenClaims
	_, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) { return v.key(ctx, t) },
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(idTokenLeeway),
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "PS256"}),
	)
	if err != nil {
		return OIDCIdentity{}, nil, fmt.Errorf("idtoken: %w", err)
	}
	// OIDC Core 3.1.3.7: with several audiences azp must name this client, and
	// a present azp must match it — otherwise the token was issued to another
	// client that merely listed this one.
	if (len(claims.Audience) > 1 || claims.AZP != "") && claims.AZP != v.audience {
		return OIDCIdentity{}, nil, fmt.Errorf("idtoken: azp %q is not this client", claims.AZP)
	}
	if claims.Subject == "" || claims.Email == "" {
		return OIDCIdentity{}, nil, fmt.Errorf("idtoken: token lacks sub or email")
	}
	verified := claims.EmailVerified != nil && bool(*claims.EmailVerified)
	absentButAllowed := v.allowUnverified && claims.EmailVerified == nil
	if !verified && !absentButAllowed {
		return OIDCIdentity{}, nil, ErrEmailNotVerified
	}
	id := OIDCIdentity{Issuer: v.issuer, Subject: claims.Subject, Email: NormalizeEmail(claims.Email)}
	return id, claims.Groups, nil
}

// key returns the verification key for t, refetching the key set once (rate
// limited) when the kid is unknown — the IdP rotated its keys.
func (v *idTokenVerifier) key(ctx context.Context, t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	if k := v.lookup(kid); k != nil {
		return k, nil
	}
	if err := v.refreshKeys(ctx, true); err != nil {
		return nil, fmt.Errorf("idtoken: key refresh: %w", err)
	}
	if k := v.lookup(kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("idtoken: unknown key id %q", kid)
}

func (v *idTokenVerifier) lookup(kid string) any {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keys[kid]
}

func (v *idTokenVerifier) refreshKeys(ctx context.Context, unknownKid bool) error {
	v.mu.RLock()
	have := len(v.keys) > 0
	fresh := have && time.Since(v.fetched) < idTokenKeyTTL
	recent := time.Since(v.attempted) < idTokenRefetchMinGap
	v.mu.RUnlock()
	switch {
	case fresh && !unknownKid, recent && have:
		// Fresh, or refetched within the last minute: an unknown kid or a
		// failing IdP must not turn every request into a fetch.
		return nil
	case recent:
		return errors.New("signing keys unavailable (last fetch failed)")
	}
	v.mu.Lock()
	v.attempted = time.Now()
	v.mu.Unlock()

	// The fetch outlives the request that triggered it: a client hanging up
	// mid-fetch must not leave the attempt marked failed and refuse every
	// sign-in until the refetch gap passes.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), idTokenFetchTimeout)
	defer cancel()

	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	discoveryURL := strings.TrimSuffix(v.issuer, "/") + "/.well-known/openid-configuration"
	if err := v.getJSON(ctx, discoveryURL, &discovery); err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	// Exact match, as for iss: OIDC Discovery 4.3.
	if discovery.Issuer != v.issuer || discovery.JWKSURI == "" {
		return fmt.Errorf("discovery: issuer %q / jwks_uri %q does not match the configured issuer", discovery.Issuer, discovery.JWKSURI)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := v.getJSON(ctx, discovery.JWKSURI, &set); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	keys := make(map[string]any, len(set.Keys))
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			if pub, err := jwkToRSA(k.N, k.E); err == nil {
				keys[k.Kid] = pub
			}
		case "EC":
			if pub, err := jwkToECDSA(k.Crv, k.X, k.Y); err == nil {
				keys[k.Kid] = pub
			}
		}
	}
	if len(keys) == 0 {
		return errors.New("jwks: no usable signing keys")
	}
	v.mu.Lock()
	v.keys = keys
	v.fetched = time.Now()
	v.mu.Unlock()
	return nil
}

func (v *idTokenVerifier) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("getJSON: %w", err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("getJSON: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("getJSON: %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("getJSON: %w", err)
	}
	return nil
}

func jwkToRSA(nB64, eB64 string) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	exp := new(big.Int).SetBytes(e)
	if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("unsupported RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}, nil
}
