package nuclei

import (
	"os"
	"strings"
	"testing"

	nucleiSdk "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTestRunOptionsCapTheEngine(t *testing.T) {
	ne, err := nucleiSdk.NewNucleiEngineCtx(t.Context(), append(testRunOptions(t.Context()), egressOptions()...)...)
	require.NoError(t, err)
	defer ne.Close()

	o := ne.Options()
	assert.Equal(t, globalRateLimit, o.RateLimit)
	assert.Equal(t, globalRateInterval, o.RateLimitDuration)
	assert.Equal(t, 1, o.TemplateThreads)
	assert.Equal(t, 1, o.BulkSize)
	assert.Equal(t, 1, o.PayloadConcurrency)
	assert.Equal(t, 1, o.ProbeConcurrency)
	assert.Equal(t, maxTestResponseRead, o.ResponseReadSize)
}

func TestScanConcurrencyIsAcceptedBySDK(t *testing.T) {
	ne, err := nucleiSdk.NewNucleiEngineCtx(t.Context(), append([]nucleiSdk.NucleiSDKOptions{
		nucleiSdk.WithConcurrency(concurrency(templateConcurrency, hostConcurrency, probeConcurrency)),
	}, egressOptions()...)...)
	require.NoError(t, err)
	defer ne.Close()

	assert.Equal(t, templateConcurrency, ne.Options().TemplateThreads)
	assert.Equal(t, hostConcurrency, ne.Options().BulkSize)
}

// TestTestTemplateAppliesRunCaps fails if TestTemplate builds its engine
// without testRunOptions or drops its deadline.
func TestTestTemplateAppliesRunCaps(t *testing.T) {
	src, err := os.ReadFile("template_service.go")
	require.NoError(t, err)
	_, body, found := strings.Cut(string(src), "func TestTemplate(")
	require.True(t, found)
	assert.Contains(t, body, "testRunOptions(ctx)")
	assert.Contains(t, body, "context.WithTimeout(ctx, maxTestDuration)")
}
