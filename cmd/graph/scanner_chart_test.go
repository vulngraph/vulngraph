package main

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// The scanner pod parses untrusted VM disks, so the chart keeps
// the application secrets (graph.appSecretEnv: GRAPH_SECRET_KEY, LLM keys,
// signing secrets) and every cloud identity off it. That is only sound while
// the scanner needs none of them: if scanner.go starts building the cipher, an
// LLM client or the approver, this fails and the chart has to be revisited
// with it.
func TestScannerPodGetsNoAppSecretsOrCloudIdentity(t *testing.T) {
	src, err := os.ReadFile("scanner.go")
	require.NoError(t, err)
	for _, use := range []string{"newCipher", "GRAPH_SECRET_KEY", "llm.", "executor.", "APPROVAL_", "DECISION_WEBHOOK"} {
		require.NotContains(t, string(src), use, "the scanner now uses %s; the chart withholds it from the scanner pod", use)
	}

	const chart = chartDir + "templates/"
	helpers, err := os.ReadFile(chart + "_helpers.tpl")
	require.NoError(t, err)
	podEnv := regexp.MustCompile(`(?s)\{\{- define "graph.podEnv" -\}\}(.*?)\n\{\{- end -\}\}\n`).FindSubmatch(helpers)
	require.NotNil(t, podEnv, "graph.podEnv not found")
	for _, name := range []string{"GRAPH_SECRET_KEY", "GRAPH_RETIRED_SECRET_KEYS", "LLM_API_KEY", "ANTHROPIC_API_KEY",
		"APPROVAL_TOKEN_SECRET", "APPROVAL_WEBHOOK_SECRET", "DECISION_WEBHOOK_SECRET"} {
		require.NotContains(t, string(podEnv[1]), "name: "+name, "%s is in the env every pod shares, the scanner included", name)
	}
	for _, def := range []string{"graph.env", "graph.envFrom"} {
		body := regexp.MustCompile(`(?s)\{\{- define "` + regexp.QuoteMeta(def) + `" -\}\}(.*?)\n\{\{- end -\}\}\n`).FindSubmatch(helpers)
		require.NotNil(t, body, "%s not found", def)
		require.Contains(t, string(body[1]), `(eq .component "scanner")`,
			"%s hands the chart-wide extra env (where an operator may put GRAPH_SECRET_KEY) to the scanner", def)
	}

	scanner, err := os.ReadFile(chart + "deployment-scanner.yaml")
	require.NoError(t, err)
	require.NotContains(t, string(scanner), "graph.appSecretEnv")
	require.NotContains(t, string(scanner), "graph.awsEnv")
	require.NotContains(t, string(scanner), "azureWorkloadIdentityLabel")
	require.Contains(t, string(scanner), "serviceAccountName: {{ .Values.scanner.serviceAccountName }}")
	require.Contains(t, string(scanner), "automountServiceAccountToken: false")
	for _, f := range []string{"deployment-serve.yaml", "deployment-worker.yaml"} {
		body, err := os.ReadFile(chart + f)
		require.NoError(t, err)
		require.Contains(t, string(body), `include "graph.appSecretEnv"`, "%s needs the application secrets", f)
	}
}

// The scanner pod is the default: with it off, disk scanning runs in the worker,
// which holds GRAPH_SECRET_KEY and the cloud identity.
func TestChartIsolatesDiskReadsWhenEnabled(t *testing.T) {
	scanner, ok := chartValues(t)["scanner"].(map[string]any)
	require.True(t, ok, "values.yaml has no scanner block")
	require.Equal(t, true, scanner["enabled"], "scanner.enabled must default to true")
}
