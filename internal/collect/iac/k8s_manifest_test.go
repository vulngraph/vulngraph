package iac

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseK8sManifests_MultiDocAndKindFilter(t *testing.T) {
	files := map[string]string{
		"k8s/api.yaml": `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: billing
spec:
  replicas: 3
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: billing
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-config
  namespace: billing
`,
		"k8s/worker.yml": `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: worker
  namespace: jobs
`,
	}

	got := ParseK8sManifests(files)

	// Deployment + Service + StatefulSet kept; ConfigMap skipped.
	require.Len(t, got, 3)

	byKey := map[string]DeclaredK8sWorkload{}
	for _, d := range got {
		byKey[d.SuffixKey()] = d
	}
	require.Contains(t, byKey, "deployment/billing/api")
	require.Contains(t, byKey, "service/billing/api")
	require.Contains(t, byKey, "statefulset/jobs/worker")
	require.NotContains(t, byKey, "configmap/billing/api-config")

	require.Equal(t, "k8s/api.yaml", byKey["deployment/billing/api"].Path)
	require.Equal(t, "k8s/worker.yml", byKey["statefulset/jobs/worker"].Path)
}

func TestParseK8sManifests_NamespaceAbsentIsEmptySegment(t *testing.T) {
	files := map[string]string{
		"deploy.yaml": `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
`,
	}
	got := ParseK8sManifests(files)
	require.Len(t, got, 1)
	require.Equal(t, "", got[0].Namespace)
	require.Equal(t, "deployment//api", got[0].SuffixKey())
}

func TestParseK8sManifests_SkipsNamelessAndUnparseableDocs(t *testing.T) {
	files := map[string]string{
		// First doc is not valid k8s (no kind), second is a real Deployment; a
		// bad doc must not sink the good one that follows it.
		"mixed.yaml": `
just: some
random: yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: good
  namespace: default
`,
		// A totally invalid YAML file is skipped whole (best-effort ingest).
		"broken.yaml": "\tthis: [is not: valid",
	}
	got := ParseK8sManifests(files)
	require.Len(t, got, 1)
	require.Equal(t, "deployment/default/good", got[0].SuffixKey())
}

func TestParseK8sManifests_MalformedDocDoesNotSinkSiblings(t *testing.T) {
	// A genuinely malformed YAML document sits BETWEEN two valid documents in
	// the same file. With yaml.v3's streaming Decoder, a syntax error
	// corrupts the decoder's position in the stream, so a naive decode loop
	// that breaks on error would drop the StatefulSet that follows the bad
	// document too. Each document must be parsed independently.
	files := map[string]string{
		"mixed.yaml": `
apiVersion: apps/v1
kind: Deployment
metadata: { name: first, namespace: a }
---
this: [is not: valid yaml
---
apiVersion: apps/v1
kind: StatefulSet
metadata: { name: third, namespace: c }
`,
	}

	got := ParseK8sManifests(files)

	byKey := map[string]DeclaredK8sWorkload{}
	for _, d := range got {
		byKey[d.SuffixKey()] = d
	}
	require.Contains(t, byKey, "deployment/a/first")
	require.Contains(t, byKey, "statefulset/c/third")
	require.Len(t, got, 2)
}

func TestParseK8sManifests_HelmTemplatedYAMLIsSkippedNotCrashed(t *testing.T) {
	// The manifest parser does NOT render Helm; a raw templated file must be
	// tolerated (parsed as best-effort, no panic).
	files := map[string]string{
		"chart/templates/deploy.yaml": `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.name }}
  namespace: {{ .Release.Namespace }}
`,
	}
	require.NotPanics(t, func() { _ = ParseK8sManifests(files) })
}
