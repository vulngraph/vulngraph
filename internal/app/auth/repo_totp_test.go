package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

func testCipher(t *testing.T) *connector.Cipher {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	c, err := connector.NewCipher(base64.StdEncoding.EncodeToString(k))
	require.NoError(t, err)
	return c
}

// A stored TOTP seed is sealed: the column value never holds the seed, and it
// opens only for the user row it was written for.
func TestSealTOTP_NeverStoresTheSeed(t *testing.T) {
	c := testCipher(t)
	const seed = "JBSWY3DPEHPK3PXP"

	stored, err := sealTOTP(c, "user-1", seed)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(stored, sealedTOTPPrefix))
	assert.NotContains(t, stored, seed)

	got, err := openTOTP(c, "user-1", stored)
	require.NoError(t, err)
	assert.Equal(t, seed, got)

	_, err = openTOTP(c, "user-2", stored)
	require.Error(t, err, "a sealed seed copied onto another user must not open")
}

// Every write seals, so an unsealed value is not one this code wrote: it is
// refused rather than used as a seed.
func TestOpenTOTP_UnsealedValueIsRefused(t *testing.T) {
	got, err := openTOTP(testCipher(t), "user-1", "JBSWY3DPEHPK3PXP")
	require.Error(t, err)
	assert.Empty(t, got)
}

func TestOpenTOTP_CorruptSealedValueIsAnError(t *testing.T) {
	_, err := openTOTP(testCipher(t), "user-1", sealedTOTPPrefix+"!!not-base64")
	require.Error(t, err)
}

// A seed sealed under a retired key opens and is not current, which is what
// makes RewrapTOTPSecrets re-seal it.
func TestSealTOTP_RetiredKeyRowsAreNotCurrent(t *testing.T) {
	old := testCipher(t)
	stored, err := sealTOTP(old, "user-1", "JBSWY3DPEHPK3PXP")
	require.NoError(t, err)

	k := make([]byte, 32)
	_, err = rand.Read(k)
	require.NoError(t, err)
	rotated, err := connector.NewCipher(base64.StdEncoding.EncodeToString(k))
	require.NoError(t, err)
	ct, sealed, err := decodeSealedTOTP(stored)
	require.NoError(t, err)
	require.True(t, sealed)
	assert.False(t, rotated.IsCurrentEnvelope(ct))
	assert.True(t, old.IsCurrentEnvelope(ct))
}

// The OAuth-only password is random per user and fits bcrypt's 72-byte input.
func TestNewRandomPassword(t *testing.T) {
	a, b := newRandomPassword(), newRandomPassword()
	assert.NotEqual(t, a, b)
	assert.LessOrEqual(t, len(a), 72)
	assert.GreaterOrEqual(t, len(a), 43, "at least 256 bits of base32")
}

// A seed that cannot be opened, or a value that was never sealed, is named in
// the error and left as it is, and the rows after it are still re-sealed.
func TestRewrapTOTPRows_BadRowDoesNotStopThePass(t *testing.T) {
	oldKey, newKey := randomKey(t), randomKey(t)
	oldCipher, err := connector.NewCipher(oldKey)
	require.NoError(t, err)
	c, err := connector.NewCipher(newKey)
	require.NoError(t, err)
	c, err = c.WithRetiredKey(oldKey)
	require.NoError(t, err)

	plain := "JBSWY3DPEHPK3PXP"
	retired, err := sealTOTP(oldCipher, "b-retired", plain)
	require.NoError(t, err)
	current, err := sealTOTP(c, "d-current", plain)
	require.NoError(t, err)
	corrupt := sealedTOTPPrefix + "!!not-base64"
	rows := []sqlcgen.ListUserTOTPSecretsRow{
		{ID: "a-corrupt", TotpSecret: &corrupt},
		{ID: "b-retired", TotpSecret: &retired},
		{ID: "c-none"},
		{ID: "d-current", TotpSecret: &current},
		{ID: "e-unsealed", TotpSecret: &plain},
	}
	written := map[string]string{}
	n, err := rewrapTOTPRows(context.Background(), c, rows,
		func(_ context.Context, arg sqlcgen.ResealUserTOTPSecretParams) (int64, error) {
			written[arg.ID] = *arg.Sealed
			return 1, nil
		})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a-corrupt")
	assert.Contains(t, err.Error(), "e-unsealed")
	assert.Equal(t, 1, n, "only the retired-key row needed a re-seal")
	require.Contains(t, written, "b-retired")
	assert.NotContains(t, written, "a-corrupt")
	assert.NotContains(t, written, "d-current")
	assert.NotContains(t, written, "e-unsealed")
	got, err := openTOTP(c, "b-retired", written["b-retired"])
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

func randomKey(t *testing.T) string {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(k)
}
