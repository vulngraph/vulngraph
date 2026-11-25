package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWorkerGraphOffWarning(t *testing.T) {
	require.Empty(t, workerGraphOffWarning(envFrom(map[string]string{"LADYBUG_INTERNAL_PORT": "8090"})))
	msg := workerGraphOffWarning(noEnv)
	require.Contains(t, msg, "LADYBUG_INTERNAL_PORT unset")
	require.Contains(t, msg, "internet-reach")
	require.Contains(t, msg, "saved-query")
}

func TestServeGraphOffWarning(t *testing.T) {
	rpcWithSecret := map[string]string{"LADYBUG_RPC_URL": "http://worker:8090", "LADYBUG_RPC_SECRET": "s"}
	rpcNoSecret := map[string]string{"LADYBUG_RPC_URL": "http://worker:8090"}
	tests := []struct {
		name    string
		env     map[string]string
		replica bool
		want    []string
	}{
		{name: "worker RPC", env: rpcWithSecret},
		{name: "own replica", env: map[string]string{}, replica: true},
		{name: "both", env: rpcWithSecret, replica: true},
		{name: "neither", env: map[string]string{}, want: []string{"raw Cypher", "NL-to-Cypher"}},
		{name: "worker RPC without secret", env: rpcNoSecret, want: []string{"LADYBUG_RPC_SECRET unset"}},
		{name: "both without secret", env: rpcNoSecret, replica: true, want: []string{"LADYBUG_RPC_SECRET unset"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := serveGraphOffWarning(envFrom(tt.env), tt.replica)
			if tt.want == nil {
				require.Empty(t, msg)
				return
			}
			for _, w := range tt.want {
				require.Contains(t, msg, w)
			}
		})
	}
}
