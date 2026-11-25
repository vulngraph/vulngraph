package graphstore

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// "listening" is logged only once the socket is bound: a port already in use
// returns an error and leaves no listening line for a reader to trust.
func TestStartInternalServer_LogsListeningOnlyAfterBind(t *testing.T) {
	logs := &lockedBuf{}
	prev := zlog.Logger
	zlog.Logger = zerolog.New(logs)
	t.Cleanup(func() { zlog.Logger = prev })

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()

	err = StartInternalServer(context.Background(), NewHandler(nil), taken.Addr().String(), "secret")
	require.ErrorContains(t, err, "listen")
	require.NotContains(t, logs.String(), "listening")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- StartInternalServer(ctx, NewHandler(nil), "127.0.0.1:0", "secret") }()
	require.Eventually(t, func() bool {
		return bytes.Contains([]byte(logs.String()), []byte("internal RPC listening"))
	}, 5*time.Second, 10*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

// The RPC listener bounds every phase of a connection, and its write deadline
// outlasts every budget a legitimate query can spend: the engine's own
// timeouts on the worker and the serve pod's client timeouts.
func TestNewInternalServer_SetsTimeouts(t *testing.T) {
	srv := newInternalServer(http.NotFoundHandler())

	require.Equal(t, rpcReadHeaderTimeout, srv.ReadHeaderTimeout)
	require.Equal(t, rpcReadTimeout, srv.ReadTimeout)
	require.Equal(t, rpcWriteTimeout, srv.WriteTimeout)
	require.Equal(t, rpcIdleTimeout, srv.IdleTimeout)
	require.Positive(t, srv.ReadHeaderTimeout)
	require.GreaterOrEqual(t, srv.ReadTimeout, srv.ReadHeaderTimeout)

	for name, budget := range map[string]time.Duration{
		"defaultQueryTimeout":             defaultQueryTimeout,
		"blastRadiusTimeout":              blastRadiusTimeout,
		"explore.LadybugRPCTimeout":       explore.LadybugRPCTimeout,
		"explore.LadybugRPCCypherTimeout": explore.LadybugRPCCypherTimeout,
	} {
		require.Greater(t, srv.WriteTimeout, budget, "WriteTimeout must outlast %s", name)
	}

	tr, ok := safenet.NewInternal(explore.LadybugRPCTimeout).Transport.(*http.Transport)
	require.True(t, ok)
	require.Greater(t, srv.IdleTimeout, tr.IdleConnTimeout,
		"the serve-side client must retire an idle connection before the server closes it")
}
