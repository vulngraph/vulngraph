package imagevuln

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeECRTokens struct {
	calls []string
	tok   ECRToken
	err   error
}

func (f *fakeECRTokens) Token(_ context.Context, accountID, region string) (ECRToken, error) {
	f.calls = append(f.calls, accountID+"/"+region)
	return f.tok, f.err
}

func ecrTestRegistry(t *testing.T, host string) name.Registry {
	t.Helper()
	r, err := name.NewRegistry(host)
	require.NoError(t, err)
	return r
}

func TestECRHostMatching(t *testing.T) {
	cases := []struct {
		host    string
		account string
		region  string
	}{
		{"123456789012.dkr.ecr.eu-west-1.amazonaws.com", "123456789012", "eu-west-1"},
		{"123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com", "123456789012", "us-gov-west-1"},
		{"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn", "123456789012", "cn-north-1"},
		{"123456789012.dkr-ecr.us-west-1.on.aws", "123456789012", "us-west-1"},
		{"123456789012.dkr-ecr.us-west-1.on.aws.evil.com", "", ""},
		{"123456789012.dkr.ecr.us-west-1.on.aws", "", ""},
		{"public.ecr.aws", "", ""},
		{"index.docker.io", "", ""},
		{"gcr.io", "", ""},
		{"us-docker.pkg.dev", "", ""},
		{"12345.dkr.ecr.eu-west-1.amazonaws.com", "", ""},
		{"123456789012.dkr.ecr.eu-west-1.amazonaws.com.evil.com", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			account, region, ok := matchECRHost(tc.host)
			assert.Equal(t, tc.account != "", ok)
			assert.Equal(t, tc.account, account)
			assert.Equal(t, tc.region, region)
		})
	}
}

func TestECRKeychain_NonECRIsAnonymous(t *testing.T) {
	src := &fakeECRTokens{}
	k := &ECRKeychain{Tokens: src}
	auth, err := k.ResolveContext(t.Context(), ecrTestRegistry(t, "gcr.io"))
	require.NoError(t, err)
	assert.Equal(t, authn.Anonymous, auth)
	assert.Empty(t, src.calls, "a non-ECR host must never mint a token")
}

func TestECRKeychain_CachesUntilNearExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	src := &fakeECRTokens{tok: ECRToken{Username: "AWS", Password: "pw", ExpiresAt: now.Add(12 * time.Hour)}}
	k := &ECRKeychain{Tokens: src, now: func() time.Time { return now }}
	reg := ecrTestRegistry(t, "123456789012.dkr.ecr.eu-west-1.amazonaws.com")

	auth, err := k.ResolveContext(t.Context(), reg)
	require.NoError(t, err)
	cfg, err := auth.Authorization()
	require.NoError(t, err)
	assert.Equal(t, "AWS", cfg.Username)
	assert.Equal(t, "pw", cfg.Password)

	_, err = k.ResolveContext(t.Context(), reg)
	require.NoError(t, err)
	assert.Len(t, src.calls, 1, "a fresh token is reused")

	now = now.Add(12*time.Hour - ecrRefreshMargin + time.Minute)
	_, err = k.ResolveContext(t.Context(), reg)
	require.NoError(t, err)
	assert.Len(t, src.calls, 2, "a token inside the refresh margin is replaced")
}

// blockingECRTokens holds every mint for one account until released.
type blockingECRTokens struct {
	slowAccount string
	release     chan struct{}
	mints       atomic.Int32
}

func (b *blockingECRTokens) Token(_ context.Context, accountID, _ string) (ECRToken, error) {
	b.mints.Add(1)
	if accountID == b.slowAccount {
		<-b.release
	}
	return ECRToken{Username: "AWS", Password: accountID, ExpiresAt: time.Now().Add(12 * time.Hour)}, nil
}

// A slow mint for one registry must not hold up pulls from another — one lock
// held across the network call did — and concurrent pulls of the slow registry
// share its one mint.
func TestECRKeychain_MintsPerRegistryWithoutAGlobalLock(t *testing.T) {
	src := &blockingECRTokens{slowAccount: "111111111111", release: make(chan struct{})}
	k := &ECRKeychain{Tokens: src}
	slow := ecrTestRegistry(t, "111111111111.dkr.ecr.eu-west-1.amazonaws.com")
	fast := ecrTestRegistry(t, "222222222222.dkr-ecr.eu-west-1.on.aws")

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := k.ResolveContext(t.Context(), slow)
			assert.NoError(t, err)
		}()
	}
	require.Eventually(t, func() bool { return src.mints.Load() >= 1 }, time.Second, time.Millisecond)

	done := make(chan error, 1)
	go func() {
		_, err := k.ResolveContext(t.Context(), fast)
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("a mint for another registry was blocked behind the slow one")
	}

	close(src.release)
	wg.Wait()
	require.Equal(t, int32(2), src.mints.Load(), "one mint per registry, shared by concurrent pulls")
}

func TestECRKeychain_TokenErrorIsReturned(t *testing.T) {
	sentinel := errors.New("no AWS connector for account 123456789012")
	k := &ECRKeychain{Tokens: &fakeECRTokens{err: sentinel}}
	_, err := k.ResolveContext(t.Context(), ecrTestRegistry(t, "123456789012.dkr.ecr.eu-west-1.amazonaws.com"))
	require.ErrorIs(t, err, sentinel, "a token failure must not degrade to an anonymous pull")

	// Through the multi-keychain the error still surfaces rather than falling
	// through to anonymous.
	mk := authn.NewMultiKeychain(k, authn.DefaultKeychain)
	_, err = authn.Resolve(t.Context(), mk, ecrTestRegistry(t, "123456789012.dkr.ecr.eu-west-1.amazonaws.com"))
	require.ErrorIs(t, err, sentinel)
}
