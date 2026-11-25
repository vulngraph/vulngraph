package envelope

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testKey(b byte) Key {
	var k Key
	for i := range k {
		k[i] = b
	}
	return k
}

func sample(now time.Time) Access {
	return Access{
		ConnectorID: "c1", Type: "azure", Role: "client-1", OtherRoles: []string{"client-0"},
		Config: map[string]string{"disk_scan_client_secret": "s3cret"}, ExpiresAt: now.Add(time.Hour),
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	now := time.Now()
	sealed, err := Seal(testKey(1), "run-1", sample(now))
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "s3cret", "the secret must not appear in the clear")

	got, err := Open(testKey(1), "run-1", "c1", sealed, now)
	require.NoError(t, err)
	require.Equal(t, "s3cret", got.Config["disk_scan_client_secret"])
	require.Equal(t, []string{"client-0"}, got.OtherRoles)
}

func TestOpenRefusals(t *testing.T) {
	now := time.Now()
	sealed, err := Seal(testKey(1), "run-1", sample(now))
	require.NoError(t, err)
	flipped := append([]byte(nil), sealed...)
	flipped[len(flipped)-1] ^= 1

	for _, tc := range []struct {
		name      string
		key       Key
		run, conn string
		sealed    []byte
		at        time.Time
		want      error
	}{
		{"another key", testKey(2), "run-1", "c1", sealed, now, ErrInvalid},
		{"another run", testKey(1), "run-2", "c1", sealed, now, ErrInvalid},
		{"another connector", testKey(1), "run-1", "c2", sealed, now, ErrInvalid},
		{"tampered", testKey(1), "run-1", "c1", flipped, now, ErrInvalid},
		{"truncated", testKey(1), "run-1", "c1", sealed[:5], now, ErrInvalid},
		{"empty", testKey(1), "run-1", "c1", nil, now, ErrInvalid},
		{"expired", testKey(1), "run-1", "c1", sealed, now.Add(2 * time.Hour), ErrExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(tc.key, tc.run, tc.conn, tc.sealed, tc.at)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestSealRequiresBinding(t *testing.T) {
	now := time.Now()
	_, err := Seal(testKey(1), "", sample(now))
	require.ErrorIs(t, err, ErrInvalid)
	noExpiry := sample(now)
	noExpiry.ExpiresAt = time.Time{}
	_, err = Seal(testKey(1), "run-1", noExpiry)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestParseKey(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	k, err := ParseKey(good)
	require.NoError(t, err)
	require.Equal(t, byte('k'), k[0])

	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		_, err := ParseKey(bad)
		require.Error(t, err, bad)
	}
}

func TestAccessCarriesSessionsAndNeverALongLivedRoleSecret(t *testing.T) {
	now := time.Now()
	a := Access{
		ConnectorID: "c1", Type: "aws", Role: "arn:ds", OtherRoles: []string{"arn:ro"},
		Config:    map[string]string{"region": "eu-west-1"},
		AWSRead:   &Credentials{AccessKeyID: "ASIAR", SecretAccessKey: "rs", SessionToken: "rt", Expires: now.Add(time.Hour)},
		AWSWrite:  &Credentials{AccessKeyID: "ASIAW", SecretAccessKey: "ws", SessionToken: "wt", Expires: now.Add(time.Hour)},
		ExpiresAt: now.Add(time.Hour),
	}
	sealed, err := Seal(testKey(1), "run-1", a)
	require.NoError(t, err)
	got, err := Open(testKey(1), "run-1", "c1", sealed, now)
	require.NoError(t, err)
	require.Equal(t, "ASIAW", got.AWSWrite.AccessKeyID)
	require.True(t, got.AWSRead.Valid())
	require.WithinDuration(t, now.Add(time.Hour), got.AWSRead.Expires, time.Second)

	read := Access{ConnectorID: "c1", ExpiresAt: now.Add(time.Hour), AWSRead: a.AWSRead}
	sealed, err = Seal(testKey(1), "run-2", read)
	require.NoError(t, err)
	got, err = Open(testKey(1), "run-2", "c1", sealed, now)
	require.NoError(t, err)
	require.Nil(t, got.AWSWrite, "a read-only mode carries no write session")
}

func TestCredentialsValid(t *testing.T) {
	var none *Credentials
	require.False(t, none.Valid())
	require.False(t, (&Credentials{AccessKeyID: "a"}).Valid())
	require.True(t, (&Credentials{AccessKeyID: "a", SecretAccessKey: "s"}).Valid())
}
