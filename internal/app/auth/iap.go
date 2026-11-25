package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// iapKeySetURL is Google's published EC public-key set for IAP JWT verification.
const iapKeySetURL = "https://www.gstatic.com/iap/verify/public_key-jwk"

// iapClaims is the relevant payload of a GCP IAP JWT.
type iapClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// iapValidator validates X-Goog-IAP-JWT-Assertion JWTs issued by Cloud IAP.
// Keys are fetched once and refreshed every hour.
type iapValidator struct {
	audience string
	mu       sync.RWMutex
	keys     map[string]*ecdsa.PublicKey
	fetched  time.Time
}

func newIAPValidator(audience string) *iapValidator {
	return &iapValidator{audience: audience}
}

// iapIssuer is the iss every Cloud IAP assertion carries. Google documents the
// check as mandatory: the key set alone does not pin the token to IAP.
const iapIssuer = "https://cloud.google.com/iap"

// Validate validates the IAP JWT and returns the identity it asserts. The
// subject ("accounts.google.com:<id>") is what the account is bound to, exactly
// as an OIDC sign-in binds (issuer, sub): the email alone is a mutable
// attribute, and matching on it hands an account to whoever is later issued
// that address.
func (v *iapValidator) Validate(ctx context.Context, raw string) (OIDCIdentity, error) {
	if err := v.maybeRefreshKeys(ctx); err != nil {
		return OIDCIdentity{}, fmt.Errorf("iap: key refresh: %w", err)
	}
	var claims iapClaims
	_, err := jwt.ParseWithClaims(raw, &claims, v.keyFunc,
		jwt.WithAudience(v.audience),
		jwt.WithIssuer(iapIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{"ES256"}),
	)
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("iap: %w", err)
	}
	if claims.Email == "" || claims.Subject == "" {
		return OIDCIdentity{}, fmt.Errorf("iap: assertion lacks email or sub")
	}
	return OIDCIdentity{Issuer: iapIssuer, Subject: claims.Subject, Email: NormalizeEmail(claims.Email)}, nil
}

func (v *iapValidator) keyFunc(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	v.mu.RLock()
	key := v.keys[kid]
	v.mu.RUnlock()
	if key == nil {
		return nil, fmt.Errorf("iap: unknown key id %q", kid)
	}
	return key, nil
}

func (v *iapValidator) maybeRefreshKeys(ctx context.Context) error {
	v.mu.RLock()
	fresh := len(v.keys) > 0 && time.Since(v.fetched) < time.Hour
	v.mu.RUnlock()
	if fresh {
		return nil
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, iapKeySetURL, nil)
	client := safenet.New(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}

	keys := make(map[string]*ecdsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		pub, err := jwkToECDSA(k.Crv, k.X, k.Y)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}

	v.mu.Lock()
	v.keys = keys
	v.fetched = time.Now()
	v.mu.Unlock()
	return nil
}

// jwkToECDSA converts JWK base64url x/y coordinates to an ecdsa.PublicKey.
func jwkToECDSA(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unsupported curve %q", crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(xBytes) > size || len(yBytes) > size {
		return nil, fmt.Errorf("coordinate longer than %d bytes for %s", size, crv)
	}
	point := make([]byte, 1+2*size)
	point[0] = 4 // uncompressed SEC 1 encoding
	copy(point[1+size-len(xBytes):1+size], xBytes)
	copy(point[1+2*size-len(yBytes):], yBytes)
	key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("parse %s key: %w", crv, err)
	}
	return key, nil
}
