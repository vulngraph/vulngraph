package llm

import (
	"fmt"
	"net/url"
	"strings"
)

// Defaults for the anthropic backend: the current Opus for reasoning and the
// current Haiku for fast, high-volume calls. Bump deliberately (the -tags=eval
// golden set guards reasoning quality across model changes).
const (
	DefaultAnthropicModel     = "claude-opus-5-5"
	DefaultAnthropicFastModel = "claude-haiku-4-5"

	defaultOpenAIBaseURL = "https://api.openai.com/v1"
)

// Config selects and configures a backend. Build it with FromEnv.
type Config struct {
	Provider Provider
	APIKey   string
	// BaseURL overrides the backend endpoint. For the openai backend this is
	// how a non-OpenAI server is selected (e.g. http://localhost:11434/v1 for
	// Ollama); for anthropic it is rarely needed (a proxy/gateway).
	BaseURL   string
	Model     string
	FastModel string
	// ReasoningEffort is passed through as reasoning_effort on the openai
	// backend when a request asks for Reasoning (low|medium|high). Empty
	// leaves it unset — not every OpenAI-compatible server or model accepts it.
	ReasoningEffort string
}

// FromEnv reads the LLM configuration:
//
//	LLM_PROVIDER          anthropic | openai (default: inferred from which key is set)
//	LLM_API_KEY           API key for the selected provider
//	LLM_BASE_URL          endpoint override (required for non-OpenAI openai-compatible servers)
//	LLM_MODEL             capable model (reasoning, chat, translation)
//	LLM_FAST_MODEL        cheap model (high-volume triage); defaults to LLM_MODEL on openai
//	LLM_REASONING_EFFORT  openai backend only: reasoning_effort for reasoning-capable models
//
// Shorthand: ANTHROPIC_API_KEY alone selects the anthropic backend with its
// default models; OPENAI_API_KEY alone selects the openai backend.
func FromEnv(getenv func(string) string) Config {
	c := Config{
		Provider:        Provider(strings.ToLower(strings.TrimSpace(getenv("LLM_PROVIDER")))),
		APIKey:          getenv("LLM_API_KEY"),
		BaseURL:         strings.TrimRight(getenv("LLM_BASE_URL"), "/"),
		Model:           getenv("LLM_MODEL"),
		FastModel:       getenv("LLM_FAST_MODEL"),
		ReasoningEffort: getenv("LLM_REASONING_EFFORT"),
	}
	switch c.Provider {
	case "openai-compatible", "openai_compatible":
		c.Provider = ProviderOpenAI
	case "":
		switch {
		case getenv("ANTHROPIC_API_KEY") != "":
			c.Provider = ProviderAnthropic
		case getenv("OPENAI_API_KEY") != "":
			c.Provider = ProviderOpenAI
		case c.BaseURL != "":
			// A base URL with no provider named is almost always a local
			// OpenAI-compatible server (Ollama, vLLM, LM Studio).
			c.Provider = ProviderOpenAI
		case c.APIKey != "":
			c.Provider = ProviderAnthropic
		}
	}
	if c.APIKey == "" {
		switch c.Provider {
		case ProviderAnthropic:
			c.APIKey = getenv("ANTHROPIC_API_KEY")
		case ProviderOpenAI:
			c.APIKey = getenv("OPENAI_API_KEY")
		}
	}
	switch c.Provider {
	case ProviderAnthropic:
		if c.Model == "" {
			c.Model = DefaultAnthropicModel
		}
		if c.FastModel == "" {
			c.FastModel = DefaultAnthropicFastModel
		}
	case ProviderOpenAI:
		if c.BaseURL == "" {
			c.BaseURL = defaultOpenAIBaseURL
		}
		if c.FastModel == "" {
			c.FastModel = c.Model
		}
	}
	return c
}

// Enabled reports whether c names a usable backend. Keyless is allowed for an
// openai-compatible server on a non-default URL (a local Ollama/vLLM).
func (c Config) Enabled() bool {
	switch c.Provider {
	case ProviderAnthropic:
		return c.APIKey != ""
	case ProviderOpenAI:
		return c.APIKey != "" || (c.BaseURL != "" && c.BaseURL != defaultOpenAIBaseURL)
	default:
		return false
	}
}

// Validate returns a configuration error a deploy should surface at startup,
// or nil. A disabled config (no provider at all) is valid: LLM features are
// optional and degrade to 503/heuristics.
func (c Config) Validate() error {
	if c.Provider == "" {
		return nil
	}
	switch c.Provider {
	case ProviderAnthropic, ProviderOpenAI:
	default:
		return fmt.Errorf("llm: unknown LLM_PROVIDER %q (want anthropic or openai)", c.Provider)
	}
	if !c.Enabled() {
		return fmt.Errorf("llm: provider %s selected but no API key set (LLM_API_KEY)", c.Provider)
	}
	if c.Model == "" {
		return fmt.Errorf("llm: provider %s requires LLM_MODEL", c.Provider)
	}
	if c.BaseURL != "" {
		u, err := url.Parse(c.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("llm: LLM_BASE_URL %q is not an http(s) URL", c.BaseURL)
		}
	}
	return nil
}

// New builds the Client c describes. It returns ErrNotConfigured when no
// provider is configured, so callers can treat LLM features as optional.
func New(c Config) (Client, error) {
	if c.Provider == "" {
		return nil, ErrNotConfigured
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	switch c.Provider {
	case ProviderAnthropic:
		return newAnthropic(c), nil
	case ProviderOpenAI:
		return newOpenAI(c), nil
	default:
		return nil, ErrNotConfigured
	}
}

// modelFor resolves the model a request goes to.
func (c Config) modelFor(req Request) string {
	if req.Model != "" {
		return req.Model
	}
	if req.Tier == TierFast && c.FastModel != "" {
		return c.FastModel
	}
	return c.Model
}
