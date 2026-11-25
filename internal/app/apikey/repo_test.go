package apikey

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func candidate(id, plaintext string, expiresAt *time.Time) keyCandidate {
	return keyCandidate{
		key:  APIKey{ID: id, Prefix: plaintext[:displayPrefixLen], ExpiresAt: expiresAt},
		hash: hashKey(plaintext),
	}
}

func TestHashKey_IsHexSHA256OfTheFullKey(t *testing.T) {
	k := "gph_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	sum := sha256.Sum256([]byte(k))
	require.Equal(t, hex.EncodeToString(sum[:]), hashKey(k))
	require.NotEqual(t, hashKey(k), hashKey(k[:len(k)-1]+"0"))
}

func TestMatchKey_ValidKeyAuthenticates(t *testing.T) {
	k := "gph_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, ok := matchKey(candidate("key-a", k, nil), k, time.Now())
	require.True(t, ok)
	require.Equal(t, "key-a", got.ID)
}

// A key whose lookup_id matches but whose secret part differs must not
// authenticate: the lookup_id is public (it is the first 16 chars) and only
// the digest proves possession.
func TestMatchKey_LookupMatchWithWrongSecretFails(t *testing.T) {
	a := "gph_abcdef012345" + "1111111111111111111111111111111111111111111111111111"
	forged := "gph_abcdef012345" + "2222222222222222222222222222222222222222222222222222"
	require.Equal(t, a[:lookupIDLen], forged[:lookupIDLen])
	c := candidate("key-a", a, nil)

	_, ok := matchKey(c, forged, time.Now())
	require.False(t, ok, "a key sharing the lookup_id but not the secret must not authenticate")
	_, ok = matchKey(c, a[:len(a)-1], time.Now())
	require.False(t, ok, "a truncated key must not authenticate")
}

// A stored value that is not the digest of the presented key never matches,
// the presented key itself included: the column holds a digest, not the key.
func TestMatchKey_StoredPlaintextIsNotADigest(t *testing.T) {
	k := "gph_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	c := keyCandidate{key: APIKey{ID: "k"}, hash: k}
	_, ok := matchKey(c, k, time.Now())
	require.False(t, ok)
	_, ok = matchKey(keyCandidate{key: APIKey{ID: "k"}}, k, time.Now())
	require.False(t, ok, "an empty stored digest must not match")
}

func TestMatchKey_ExpiredKeyDoesNotAuthenticate(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)
	k := "gph_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	_, ok := matchKey(candidate("k", k, &past), k, now)
	require.False(t, ok)
	_, ok = matchKey(candidate("k", k, &now), k, now)
	require.False(t, ok, "a key expires at expires_at, not after it")
	_, ok = matchKey(candidate("k", k, &future), k, now)
	require.True(t, ok)
}

func TestLastUsedStale(t *testing.T) {
	now := time.Now()
	recent := now.Add(-lastUsedResolution + time.Second)
	old := now.Add(-lastUsedResolution)
	cases := []struct {
		name string
		last *time.Time
		want bool
	}{
		{"never used", nil, true},
		{"used within the resolution", &recent, false},
		{"used a full resolution ago", &old, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, lastUsedStale(tc.last, now))
		})
	}
}

// TestMatchKeyComparesDigestsInConstantTime keeps the digest comparison in
// matchKey on subtle.ConstantTimeCompare. A plain == or != on the digests
// passes every behavioural test above while leaking, through response timing,
// how many leading bytes of a guessed digest are right.
func TestMatchKeyComparesDigestsInConstantTime(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "repo.go", nil, 0)
	require.NoError(t, err)

	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "matchKey" {
			fn = f
		}
	}
	require.NotNil(t, fn, "matchKey not found in repo.go")

	constantTime := false
	var plain []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			if isConstantTimeCompare(v) {
				constantTime = true
			}
		case *ast.BinaryExpr:
			if v.Op != token.EQL && v.Op != token.NEQ {
				return true
			}
			for _, side := range []ast.Expr{v.X, v.Y} {
				if mentionsDigest(side) {
					plain = append(plain, v.Op.String())
				}
			}
		}
		return true
	})
	require.True(t, constantTime, "matchKey must compare digests with subtle.ConstantTimeCompare")
	require.Empty(t, plain, "matchKey compares a digest with a plain operator")
}

func isConstantTimeCompare(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare"
}

// mentionsDigest reports whether e reads the stored digest (c.hash) or
// computes one (hashKey), outside a constant-time compare.
func mentionsDigest(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			if isConstantTimeCompare(v) {
				return false
			}
			if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "hashKey" {
				found = true
			}
		case *ast.SelectorExpr:
			if v.Sel.Name == "hash" {
				found = true
			}
		}
		return !found
	})
	return found
}

// The lookup id must be long enough that random keys do not collide in
// practice; the 16 bits of the 8-char display prefix collide after a few
// hundred.
func TestLookupIDCarriesAtLeast48Bits(t *testing.T) {
	require.GreaterOrEqual(t, (lookupIDLen-len(keyPrefix))*4, 48)
	require.Greater(t, lookupIDLen, displayPrefixLen)
}
