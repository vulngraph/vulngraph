package kubernetes

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

func unstructuredYAML(t *testing.T, doc string) unstructured.Unstructured {
	t.Helper()
	js, err := utilyaml.ToJSON([]byte(doc))
	require.NoError(t, err)
	var u unstructured.Unstructured
	require.NoError(t, u.UnmarshalJSON(js))
	return u
}

// Kyverno's own pod-security sample (policies/pod-security/subrule/restricted),
// in Enforce, excluding kube-system.
const kyvernoPSSEnforce = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: podsecurity-subrule-restricted
spec:
  background: true
  validationFailureAction: Enforce
  rules:
  - name: restricted
    match:
      any:
      - resources:
          kinds: [Pod]
    exclude:
      any:
      - resources:
          namespaces: [kube-system, legacy-*]
    validate:
      podSecurity:
        level: restricted
        version: latest
`

const gatekeeperPrivileged = `apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: psp-privileged-container
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: [Pod]
    excludedNamespaces: [kube-system]
`

func TestPodSecurityCoverage(t *testing.T) {
	ns := []string{"payments", "legacy-crm", "kube-system"}
	kyverno := unstructuredYAML(t, kyvernoPSSEnforce)
	audit := kyverno.DeepCopy()
	require.NoError(t, unstructured.SetNestedField(audit.Object, "Audit", "spec", "validationFailureAction"))
	ruleAction := audit.DeepCopy()
	rules, _, _ := unstructured.NestedSlice(ruleAction.Object, "spec", "rules")
	require.NoError(t, unstructured.SetNestedField(rules[0].(map[string]any), "Enforce", "validate", "failureAction"))
	require.NoError(t, unstructured.SetNestedSlice(ruleAction.Object, rules, "spec", "rules"))
	pattern := kyverno.DeepCopy()
	rules, _, _ = unstructured.NestedSlice(pattern.Object, "spec", "rules")
	unstructured.RemoveNestedField(rules[0].(map[string]any), "validate", "podSecurity")
	require.NoError(t, unstructured.SetNestedField(rules[0].(map[string]any), map[string]any{"pattern": map[string]any{}}, "validate"))
	require.NoError(t, unstructured.SetNestedSlice(pattern.Object, rules, "spec", "rules"))

	gk := unstructuredYAML(t, gatekeeperPrivileged)
	dryrun := gk.DeepCopy()
	require.NoError(t, unstructured.SetNestedField(dryrun.Object, "dryrun", "spec", "enforcementAction"))

	tests := []struct {
		name    string
		engines string
		crs     map[string][]unstructured.Unstructured
		want    map[string]string
	}{
		{"Kyverno PSS rule in Enforce covers, its excludes do not", "kyverno",
			map[string][]unstructured.Unstructured{"clusterpolicies": {kyverno}},
			map[string]string{"payments": "kyverno", "legacy-crm": "", "kube-system": ""}},
		{"Kyverno installed with no policies covers nothing", "kyverno", map[string][]unstructured.Unstructured{"clusterpolicies": nil},
			map[string]string{"payments": "", "legacy-crm": "", "kube-system": ""}},
		{"Audit-only policy covers nothing", "kyverno", map[string][]unstructured.Unstructured{"clusterpolicies": {*audit}},
			map[string]string{"payments": "", "legacy-crm": "", "kube-system": ""}},
		{"rule-level failureAction overrides the spec", "kyverno", map[string][]unstructured.Unstructured{"clusterpolicies": {*ruleAction}},
			map[string]string{"payments": "kyverno", "legacy-crm": "", "kube-system": ""}},
		{"a pattern rule is not recognised as pod security", "kyverno", map[string][]unstructured.Unstructured{"clusterpolicies": {*pattern}},
			map[string]string{"payments": "", "legacy-crm": "", "kube-system": ""}},
		{"Gatekeeper PSP-library constraint in deny", "gatekeeper", map[string][]unstructured.Unstructured{"k8spspprivilegedcontainer": {gk}},
			map[string]string{"payments": "gatekeeper", "legacy-crm": "gatekeeper", "kube-system": ""}},
		{"Gatekeeper dryrun covers nothing", "gatekeeper", map[string][]unstructured.Unstructured{"k8spspprivilegedcontainer": {*dryrun}},
			map[string]string{"payments": "", "legacy-crm": "", "kube-system": ""}},
		{"a VAP binding alone is never coverage", "validating-admission-policy", nil,
			map[string]string{"payments": "", "legacy-crm": "", "kube-system": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := podSecurityCoverage(context.Background(), &fakeK8s{customResources: tt.crs}, tt.engines, ns)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}

	_, err := podSecurityCoverage(context.Background(), &fakeK8s{crErr: map[string]error{"clusterpolicies": errors.New("forbidden")}}, "kyverno", ns)
	require.Error(t, err, "a forbidden policy read is unknown coverage, never none")
}

// The namespace asset carries the coverage only when it was read.
func TestCollect_PodSecurityEngineOnNamespaces(t *testing.T) {
	kyverno := unstructuredYAML(t, kyvernoPSSEnforce)
	base := func() *fakeK8s {
		return &fakeK8s{namespaces: appNamespace(), webhooks: []admissionv1.ValidatingWebhookConfiguration{webhookConfig("validate.kyverno.svc-fail")},
			customResources: map[string][]unstructured.Unstructured{"clusterpolicies": {kyverno}}}
	}
	nsMeta := func(f *fakeK8s) map[string]string {
		res, err := withFakeK8s(f).Collect(context.Background(), nil)
		require.NoError(t, err)
		for _, a := range res.Assets {
			if a.Type == "k8s_namespace" {
				return a.Metadata
			}
		}
		t.Fatal("no namespace asset")
		return nil
	}
	require.Equal(t, "kyverno", nsMeta(base())["pod_security_engine"])

	f := base()
	f.crErr = map[string]error{"policies": errors.New("forbidden")}
	md := nsMeta(f)
	require.NotContains(t, md, "pod_security_engine")
	require.Equal(t, "kyverno", md["cluster_policy_engines"], "the installed engine stays as evidence")
}
