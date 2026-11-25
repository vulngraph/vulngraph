package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func noEnv(string) string { return "" }

func TestRun_NoCommand_ReturnsUsage(t *testing.T) {
	err := run(context.Background(), []string{"graph"}, noEnv)
	require.ErrorContains(t, err, "usage")
}

func TestRun_UnknownCommand_ReturnsError(t *testing.T) {
	err := run(context.Background(), []string{"graph", "frobnicate"}, noEnv)
	require.ErrorContains(t, err, `unknown command "frobnicate"`)
}

func TestEnvOr(t *testing.T) {
	getenv := func(k string) string {
		if k == "SET" {
			return "value"
		}
		return ""
	}
	require.Equal(t, "value", envOr(getenv, "SET", "fallback"))
	require.Equal(t, "fallback", envOr(getenv, "UNSET", "fallback"))
}

func TestPrintVersion(t *testing.T) {
	tests := []struct {
		name    string
		stamped string
		want    string
	}{
		{name: "unstamped build reports dev", stamped: "", want: "dev\n"},
		{name: "release build reports its tag", stamped: "v1.2.3", want: "v1.2.3\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.stamped != "" {
				prev := version
				version = tt.stamped
				t.Cleanup(func() { version = prev })
			}
			var out bytes.Buffer
			require.NoError(t, printVersion(&out))
			require.Equal(t, tt.want, out.String())
		})
	}
}

func TestRun_Version(t *testing.T) {
	require.NoError(t, run(context.Background(), []string{"graph", "version"}, noEnv))
}

func TestEnvInt(t *testing.T) {
	for name, tc := range map[string]struct {
		val  string
		want int
	}{
		"unset":        {"", 7},
		"valid":        {"12", 12},
		"trimmed":      {" 12 ", 12},
		"zero":         {"0", 7},
		"negative":     {"-3", 7},
		"garbage":      {"abc", 7},
		"max int32":    {"2147483647", 2147483647},
		"over int32":   {"2147483648", 7},
		"wraps to low": {"4294967297", 7},
		"over int64":   {"99999999999999999999", 7},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, envInt(envMap(map[string]string{"K": tc.val}), "K", 7))
		})
	}
}
