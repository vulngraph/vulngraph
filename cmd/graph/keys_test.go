package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func randomKey(t *testing.T) string {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(k)
}

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// The rotation state: rows sealed under the retired key stay readable, writes
// go to the new key, and once re-sealed the retired key can be dropped.
func TestNewCipher_RetiredKeysOpenOldRowsAndWritesUseCurrent(t *testing.T) {
	oldKey, newKey := randomKey(t), randomKey(t)
	before, err := newCipher(envFrom(map[string]string{"GRAPH_SECRET_KEY": oldKey}))
	require.NoError(t, err)
	sealedOld, err := before.EncryptWithAAD([]byte("secret"), []byte("row-1"))
	require.NoError(t, err)

	during, err := newCipher(envFrom(map[string]string{
		"GRAPH_SECRET_KEY":          newKey,
		"GRAPH_RETIRED_SECRET_KEYS": " " + oldKey + " ,, " + randomKey(t),
	}))
	require.NoError(t, err)
	assert.False(t, during.IsCurrentEnvelope(sealedOld), "an old-key row must be picked up by the rewrap")
	plain, err := during.DecryptWithAAD(sealedOld, []byte("row-1"))
	require.NoError(t, err)
	resealed, err := during.EncryptWithAAD(plain, []byte("row-1"))
	require.NoError(t, err)
	assert.True(t, during.IsCurrentEnvelope(resealed))

	after, err := newCipher(envFrom(map[string]string{"GRAPH_SECRET_KEY": newKey}))
	require.NoError(t, err)
	got, err := after.DecryptWithAAD(resealed, []byte("row-1"))
	require.NoError(t, err)
	assert.Equal(t, "secret", string(got))
	_, err = after.DecryptWithAAD(sealedOld, []byte("row-1"))
	require.Error(t, err, "a row never re-sealed is unreadable once its key is dropped")
}

func TestNewCipher_RejectsBadKeys(t *testing.T) {
	key := randomKey(t)
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "missing current key", env: map[string]string{}, want: "GRAPH_SECRET_KEY"},
		{name: "malformed retired key", env: map[string]string{"GRAPH_SECRET_KEY": key, "GRAPH_RETIRED_SECRET_KEYS": "not-base64!"}, want: "GRAPH_RETIRED_SECRET_KEYS entry 1"},
		{name: "retired equals current", env: map[string]string{"GRAPH_SECRET_KEY": key, "GRAPH_RETIRED_SECRET_KEYS": randomKey(t) + "," + key}, want: "entry 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newCipher(envFrom(tt.env))
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestKeysRewrap_ReportsEachPassAndStopsAtFirstFailure(t *testing.T) {
	var ran []string
	pass := func(name string, n int, err error) rewrapPass {
		return rewrapPass{name: name, run: func(context.Context) (int, error) {
			ran = append(ran, name)
			return n, err
		}}
	}

	var out bytes.Buffer
	require.NoError(t, keysRewrap(context.Background(), &out, "abc", []rewrapPass{
		pass("connectors", 2, nil), pass("alert channels", 0, nil),
	}))
	assert.Equal(t, "connectors: re-sealed 2 row(s) under key abc\nalert channels: re-sealed 0 row(s) under key abc\n", out.String())

	ran = nil
	err := keysRewrap(context.Background(), &bytes.Buffer{}, "abc", []rewrapPass{
		pass("connectors", 0, errors.New("connector c1 could not be opened")), pass("alert channels", 0, nil),
	})
	require.ErrorContains(t, err, "connectors: connector c1")
	assert.Equal(t, []string{"connectors"}, ran)
}

func TestKeysCmd_Usage(t *testing.T) {
	for _, args := range [][]string{nil, {"rotate"}, {"rewrap", "extra"}} {
		err := keysCmd(context.Background(), args, envFrom(nil))
		require.ErrorContains(t, err, "usage: graph keys rewrap")
	}
}

// keysCmd refuses to touch the database with a bad key list.
func TestKeysCmd_BadKeyFailsBeforeConnecting(t *testing.T) {
	err := keysCmd(context.Background(), []string{"rewrap"}, envFrom(map[string]string{
		"DATABASE_URL": "postgres://unused.invalid/graph",
	}))
	require.ErrorContains(t, err, "GRAPH_SECRET_KEY")
}
