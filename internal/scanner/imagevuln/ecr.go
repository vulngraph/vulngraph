package imagevuln

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"golang.org/x/sync/singleflight"
)

// ECRToken is a registry credential for one private ECR registry, valid until
// ExpiresAt (ECR issues 12-hour tokens).
type ECRToken struct {
	Username  string
	Password  string
	ExpiresAt time.Time
}

// ECRTokenSource mints an ECR pull credential for the registry of accountID in
// region. An interface so this package never imports the AWS SDK or the
// connector domain: the adapter that resolves an account to a connector's
// credentials lives in cmd/graph.
type ECRTokenSource interface {
	Token(ctx context.Context, accountID, region string) (ECRToken, error)
}

// ecrRefreshMargin is how long before expiry a cached token is replaced, so a
// multi-minute pull never starts on a token that dies halfway through it.
const ecrRefreshMargin = 30 * time.Minute

// ecrMintTimeout bounds one token mint. Concurrent pulls of the same registry
// wait on the one in flight, so it must not hang on the first caller's
// deadline — or forever.
const ecrMintTimeout = 30 * time.Second

// ecrHosts match a private ECR registry host and capture its account and
// region: the IPv4 endpoint (plus FIPS and China partitions) and the dual-stack
// endpoint "<account>.dkr-ecr.<region>.on.aws" (AWS ECR user guide, "Making
// requests to Amazon ECR registries"). Public ECR (public.ecr.aws) is
// deliberately not matched: it is anonymous-pullable and falls through to the
// next keychain.
var ecrHosts = []*regexp.Regexp{
	regexp.MustCompile(`^(\d{12})\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$`),
	regexp.MustCompile(`^(\d{12})\.dkr-ecr\.([a-z0-9-]+)\.on\.aws$`),
}

// matchECRHost returns the account and region of a private ECR registry host.
func matchECRHost(host string) (account, region string, ok bool) {
	for _, re := range ecrHosts {
		if m := re.FindStringSubmatch(host); m != nil {
			return m[1], m[2], true
		}
	}
	return "", "", false
}

// ECRKeychain resolves credentials for private ECR registries. Any other host
// resolves to authn.Anonymous so authn.NewMultiKeychain moves on to the next
// keychain.
//
// A token failure is returned, never downgraded to anonymous: an anonymous pull
// against private ECR fails later with a bare 401, while the token error ("no
// AWS connector for account X", AccessDenied on ecr:GetAuthorizationToken) is
// what lands in image_scan_state.last_error and says what to fix.
type ECRKeychain struct {
	Tokens ECRTokenSource

	now   func() time.Time // nil = time.Now
	mu    sync.Mutex       // guards cache only; never held across a mint
	cache map[string]ECRToken
	mint  singleflight.Group // one in-flight mint per "<account>/<region>"
}

// Resolve implements authn.Keychain.
func (k *ECRKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	return k.ResolveContext(context.Background(), target)
}

// ResolveContext implements authn.ContextKeychain; remote passes the pull's ctx.
func (k *ECRKeychain) ResolveContext(ctx context.Context, target authn.Resource) (authn.Authenticator, error) {
	account, region, ok := matchECRHost(target.RegistryStr())
	if !ok || k.Tokens == nil {
		return authn.Anonymous, nil
	}
	tok, err := k.token(ctx, account, region)
	if err != nil {
		return nil, fmt.Errorf("ECRKeychain: %s: %w", target.RegistryStr(), err)
	}
	return authn.FromConfig(authn.AuthConfig{Username: tok.Username, Password: tok.Password}), nil
}

// token returns a cached token for the registry, minting a new one when none is
// cached or the cached one is inside ecrRefreshMargin of expiry. Concurrent
// pulls of one registry share one mint; pulls of other registries are never
// held up behind it, as a single lock across the network call would hold them.
func (k *ECRKeychain) token(ctx context.Context, accountID, region string) (ECRToken, error) {
	key := accountID + "/" + region
	if tok, ok := k.cached(key); ok {
		return tok, nil
	}
	v, err, _ := k.mint.Do(key, func() (any, error) {
		if tok, ok := k.cached(key); ok {
			return tok, nil // minted by the flight that just finished
		}
		// Detached from the first caller's cancellation: the others are
		// waiting on this same mint.
		mintCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ecrMintTimeout)
		defer cancel()
		tok, err := k.Tokens.Token(mintCtx, accountID, region)
		if err != nil {
			return ECRToken{}, err
		}
		k.mu.Lock()
		defer k.mu.Unlock()
		if k.cache == nil {
			k.cache = map[string]ECRToken{}
		}
		k.cache[key] = tok
		return tok, nil
	})
	if err != nil {
		return ECRToken{}, fmt.Errorf("token: %w", err)
	}
	tok, _ := v.(ECRToken)
	return tok, nil
}

// cached returns the registry's cached token if it is outside the refresh margin.
func (k *ECRKeychain) cached(key string) (ECRToken, bool) {
	now := time.Now
	if k.now != nil {
		now = k.now
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	tok, ok := k.cache[key]
	return tok, ok && now().Add(ecrRefreshMargin).Before(tok.ExpiresAt)
}
