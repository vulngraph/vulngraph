package db

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// A database that accepts the TCP connection but never answers must fail the
// check before the chart's 3s probe timeout, not hang it.
func TestReadiness_UnresponsiveDatabaseFailsWithinProbeTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			accepted <- conn
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
		}
	})

	cfg, err := pgx.ParseConfig("postgres://graph:graph@" + ln.Addr().String() + "/graph?sslmode=disable")
	require.NoError(t, err)
	r := NewReadiness(cfg)
	t.Cleanup(func() { r.Close(context.Background()) })

	start := time.Now()
	err = r.Check(context.Background())
	require.ErrorContains(t, err, "Readiness")
	require.Less(t, time.Since(start), 3*time.Second)
}

func TestReadiness_UnreachableDatabaseFails(t *testing.T) {
	cfg, err := pgx.ParseConfig("postgres://graph:graph@127.0.0.1:1/graph?sslmode=disable")
	require.NoError(t, err)
	r := NewReadiness(cfg)
	require.ErrorContains(t, r.Check(context.Background()), "Readiness: connect")
}
