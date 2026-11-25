package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/chat"
)

func TestChatLimitsFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	l, err := chatLimitsFromEnv(env(nil))
	require.NoError(t, err)
	require.Equal(t, chat.Limits{}, l, "unset keeps chat.DefaultLimits (applied by WithLimits)")

	l, err = chatLimitsFromEnv(env(map[string]string{
		"CHAT_MAX_TOKENS_PER_TURN": "100000", "CHAT_MAX_TOOL_CALLS_PER_TURN": "8",
		"CHAT_TURN_TIMEOUT": "90s", "CHAT_MAX_HISTORY_MESSAGES": "20", "CHAT_MAX_HISTORY_BYTES": "50000",
	}))
	require.NoError(t, err)
	require.Equal(t, chat.Limits{MaxTokens: 100_000, MaxToolCalls: 8, Timeout: 90 * time.Second,
		MaxHistoryMessages: 20, MaxHistoryBytes: 50_000}, l)

	for k, v := range map[string]string{
		"CHAT_MAX_TOKENS_PER_TURN": "lots", "CHAT_MAX_TOOL_CALLS_PER_TURN": "0", "CHAT_TURN_TIMEOUT": "5",
	} {
		_, err := chatLimitsFromEnv(env(map[string]string{k: v}))
		require.Error(t, err, "%s=%s must fail startup, not read as uncapped", k, v)
	}
}
