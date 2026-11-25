package nuclei

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/scan"
)

const loopbackProbeTemplate = `id: loopback-probe
info:
  name: Loopback Probe
  author: graph
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words: ["sandbox-marker"]`

// TestTestTemplate_SandboxBlocksLoopback proves the dial-time policy, not just
// the handler pre-check: the same template against the same loopback server
// matches only when internal targets are explicitly allowed.
func TestTestTemplate_SandboxBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("sandbox-marker"))
	}))
	defer srv.Close()

	blocked, err := TestTemplate(t.Context(), loopbackProbeTemplate, srv.URL, false)
	require.NoError(t, err)
	assert.Empty(t, blocked, "loopback target must be unreachable by default")

	allowed, err := TestTemplate(t.Context(), loopbackProbeTemplate, srv.URL, true)
	require.NoError(t, err)
	assert.Len(t, allowed, 1, "opt-in must reach internal targets")
}

func TestNew_HonoursAllowInternalEnv(t *testing.T) {
	t.Setenv(scan.AllowInternalTargetsEnv, "")
	assert.False(t, New().allowInternal)
	assert.False(t, NewTemplateService().allowInternal)

	t.Setenv(scan.AllowInternalTargetsEnv, "true")
	assert.True(t, New().allowInternal)
	assert.True(t, NewTemplateService().allowInternal)
}

// TestTestTemplate_SandboxBlocksUnspecifiedIPv6 proves the extra excludes reach
// nuclei's dialer: the SDK's own deny list misses ::, which connects to a
// listener bound on the unspecified address.
func TestTestTemplate_SandboxBlocksUnspecifiedIPv6(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		t.Skipf("no IPv6 listener on this host: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("sandbox-marker"))
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	target := fmt.Sprintf("http://[::]:%d", ln.Addr().(*net.TCPAddr).Port)

	allowed, err := TestTemplate(t.Context(), loopbackProbeTemplate, target, true)
	require.NoError(t, err)
	if len(allowed) == 0 {
		t.Skip("this host cannot dial [::]; nothing to prove")
	}

	blocked, err := TestTemplate(t.Context(), loopbackProbeTemplate, target, false)
	require.NoError(t, err)
	assert.Empty(t, blocked, "[::] must be unreachable by default")
}

func TestSandboxExcludes(t *testing.T) {
	restricted := sandboxExcludes(false)
	internal := sandboxExcludes(true)
	for _, metadata := range []string{"169.254.0.0/16", "fd00:ec2::254/128", "100.100.100.200/32", "metadata.google.internal"} {
		assert.Contains(t, restricted, metadata)
		assert.Contains(t, internal, metadata, "allowing internal targets must never open %s", metadata)
	}
	assert.Contains(t, restricted, "::/96")
	assert.NotContains(t, internal, "::/96", "internal opt-in reaches local listeners")
}
