package llm

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// An existing ANTHROPIC_API_KEY-only deploy must keep its exact behavior.
func TestFromEnv_AnthropicKeyOnlyIsBackCompat(t *testing.T) {
	c := FromEnv(env(map[string]string{"ANTHROPIC_API_KEY": "sk-ant"}))
	require.Equal(t, ProviderAnthropic, c.Provider)
	require.Equal(t, "sk-ant", c.APIKey)
	require.Equal(t, DefaultAnthropicModel, c.Model)
	require.Equal(t, DefaultAnthropicFastModel, c.FastModel)
	require.True(t, c.Enabled())
	require.NoError(t, c.Validate())
}

func TestFromEnv_OpenAIKeyOnly(t *testing.T) {
	c := FromEnv(env(map[string]string{"OPENAI_API_KEY": "sk-oa", "LLM_MODEL": "gpt-x"}))
	require.Equal(t, ProviderOpenAI, c.Provider)
	require.Equal(t, "sk-oa", c.APIKey)
	require.Equal(t, defaultOpenAIBaseURL, c.BaseURL)
	require.Equal(t, "gpt-x", c.FastModel, "fast tier defaults to LLM_MODEL")
	require.NoError(t, c.Validate())
}

func TestFromEnv_LocalServerIsKeyless(t *testing.T) {
	c := FromEnv(env(map[string]string{"LLM_BASE_URL": "http://localhost:11434/v1/", "LLM_MODEL": "llama3.3"}))
	require.Equal(t, ProviderOpenAI, c.Provider, "a bare base URL means an OpenAI-compatible server")
	require.Equal(t, "http://localhost:11434/v1", c.BaseURL, "trailing slash trimmed")
	require.True(t, c.Enabled())
	require.NoError(t, c.Validate())
}

func TestFromEnv_ExplicitProviderWinsAndAliases(t *testing.T) {
	c := FromEnv(env(map[string]string{
		"LLM_PROVIDER": "OpenAI-Compatible", "LLM_API_KEY": "k", "ANTHROPIC_API_KEY": "ignored",
		"LLM_BASE_URL": "https://openrouter.ai/api/v1", "LLM_MODEL": "anthropic/claude-opus-4-8",
	}))
	require.Equal(t, ProviderOpenAI, c.Provider)
	require.Equal(t, "k", c.APIKey)
}

func TestValidate(t *testing.T) {
	require.NoError(t, Config{}.Validate(), "no provider = LLM features off, which is valid")
	require.Error(t, Config{Provider: "gemini"}.Validate())
	require.ErrorContains(t, FromEnv(env(map[string]string{"LLM_PROVIDER": "openai", "LLM_API_KEY": "k"})).Validate(), "LLM_MODEL")
	require.ErrorContains(t, FromEnv(env(map[string]string{"LLM_PROVIDER": "anthropic"})).Validate(), "API key")
	require.ErrorContains(t, Config{Provider: ProviderOpenAI, APIKey: "k", Model: "m", BaseURL: "ftp://x"}.Validate(), "http(s)")
}

func TestNew(t *testing.T) {
	_, err := New(Config{})
	require.True(t, errors.Is(err, ErrNotConfigured))

	c, err := New(FromEnv(env(map[string]string{"ANTHROPIC_API_KEY": "k"})))
	require.NoError(t, err)
	require.Equal(t, ProviderAnthropic, c.Provider())

	c, err = New(FromEnv(env(map[string]string{"OPENAI_API_KEY": "k", "LLM_MODEL": "m"})))
	require.NoError(t, err)
	require.Equal(t, ProviderOpenAI, c.Provider())
}

func TestModelFor(t *testing.T) {
	c := Config{Model: "big", FastModel: "small"}
	require.Equal(t, "big", c.modelFor(Request{}))
	require.Equal(t, "small", c.modelFor(Request{Tier: TierFast}))
	require.Equal(t, "pinned", c.modelFor(Request{Model: "pinned", Tier: TierFast}))
}
