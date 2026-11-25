package nuclei

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

const protoHead = "info:\n  name: T\n  author: graph\n  severity: medium\n"

// Every protocol the embedded SDK runs without an extra capability is
// accepted and reported under its current name; the legacy spellings
// (requests, tcp) count as http and network.
func TestValidate_AcceptsEveryRunnableProtocol(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"legacy requests key", "requests:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n    matchers:\n      - type: word\n        words: [\"admin\"]", []string{"http"}},
		{"tcp", "tcp:\n  - inputs:\n      - data: \"PING\\r\\n\"\n    host:\n      - \"{{Hostname}}\"\n    port: \"6379\"\n    matchers:\n      - type: word\n        words: [\"PONG\"]", []string{"network"}},
		{"network", "network:\n  - inputs:\n      - data: \"PING\\r\\n\"\n    host:\n      - \"{{Hostname}}\"\n    port: \"6379\"\n    matchers:\n      - type: word\n        words: [\"PONG\"]", []string{"network"}},
		{"ssl", "ssl:\n  - address: \"{{Host}}:{{Port}}\"\n    matchers:\n      - type: dsl\n        dsl:\n          - \"len(not_after) > 0\"", []string{"ssl"}},
		{"websocket", "websocket:\n  - address: \"{{Scheme}}://{{Hostname}}\"\n    inputs:\n      - data: ping\n    matchers:\n      - type: word\n        words: [\"pong\"]", []string{"websocket"}},
		{"whois", "whois:\n  - query: \"{{Host}}\"\n    matchers:\n      - type: word\n        words: [\"registrar\"]", []string{"whois"}},
		{"http plus ssl reports both", "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n    matchers:\n      - type: word\n        words: [\"admin\"]\nssl:\n  - address: \"{{Host}}:{{Port}}\"\n    matchers:\n      - type: dsl\n        dsl:\n          - \"len(not_after) > 0\"", []string{"http", "ssl"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := Validate(t.Context(), "id: proto-check\n"+protoHead+tc.body)
			require.True(t, result.Valid, "%v", result.Errors)
			require.Equal(t, tc.want, result.Info.Protocols)
		})
	}
}

// The kinds Vulngraph cannot run are refused by name in phase 1, not reported
// as a parse failure, and a template with one is not also told it has no
// protocol block.
func TestValidate_RejectsUnrunnableKindsByName(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"headless", "headless:\n  - steps:\n      - action: navigate\n        args:\n          url: \"{{BaseURL}}\"", "headless templates are not supported"},
		{"workflow", "workflows:\n  - template: http/technologies/tech-detect.yaml", "workflow templates are not supported"},
		{"file", "file:\n  - extensions:\n      - all\n    matchers:\n      - type: word\n        words: [\"secret\"]", "file templates are not supported"},
		{"code", "code:\n  - engine:\n      - sh\n    source: echo hi", "code templates are not supported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := Validate(t.Context(), "id: kind-check\n"+protoHead+tc.body)
			require.False(t, result.Valid)
			require.Len(t, result.Errors, 1, "%v", result.Errors)
			require.Contains(t, result.Errors[0].Message, tc.want)
		})
	}
}

// Nuclei skips an unsigned javascript template at load; the reason is named.
func TestValidate_UnsignedJavascriptNamesTheSigningRule(t *testing.T) {
	body := "javascript:\n  - code: |\n      let m = require('nuclei/net');\n    args:\n      Host: \"{{Host}}\"\n    matchers:\n      - type: dsl\n        dsl:\n          - \"success == true\""
	result := Validate(t.Context(), "id: js-check\n"+protoHead+body)
	require.False(t, result.Valid)
	require.Contains(t, result.Errors[0].Message, "signed")
}

// A request whose context is gone does not keep building an engine, and the
// result says the validation did not finish rather than blaming the template.
func TestValidate_HonoursTheCallersContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	good := "id: ctx-check\n" + protoHead + "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n    matchers:\n      - type: word\n        words: [\"admin\"]"
	result := Validate(ctx, good)
	require.False(t, result.Valid)
	require.Contains(t, result.Errors[0].Message, "did not finish")
}
