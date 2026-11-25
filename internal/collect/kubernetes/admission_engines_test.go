package kubernetes

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func webhookConfig(names ...string) admissionv1.ValidatingWebhookConfiguration {
	cfg := admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "cfg"}}
	for _, n := range names {
		cfg.Webhooks = append(cfg.Webhooks, admissionv1.ValidatingWebhook{Name: n})
	}
	return cfg
}

func TestAdmissionPolicyEngines(t *testing.T) {
	audit := admissionv1.ValidatingAdmissionPolicyBinding{Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
		ValidationActions: []admissionv1.ValidationAction{admissionv1.Audit}}}
	deny := admissionv1.ValidatingAdmissionPolicyBinding{Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
		ValidationActions: []admissionv1.ValidationAction{admissionv1.Deny}}}
	tests := []struct {
		name string
		f    *fakeK8s
		want string
	}{
		// Webhook names as each engine registers them.
		{"kyverno and gatekeeper", &fakeK8s{webhooks: []admissionv1.ValidatingWebhookConfiguration{
			webhookConfig("validate.kyverno.svc-fail", "validate-policy.kyverno.svc"),
			webhookConfig("validation.gatekeeper.sh", "check-ignore-label.gatekeeper.sh"),
		}}, "gatekeeper,kyverno"},
		{"a denying ValidatingAdmissionPolicy binding", &fakeK8s{vapBindings: []admissionv1.ValidatingAdmissionPolicyBinding{audit, deny}},
			"validating-admission-policy"},
		{"audit-only bindings enforce nothing", &fakeK8s{vapBindings: []admissionv1.ValidatingAdmissionPolicyBinding{audit}}, ""},
		{"unrelated webhooks", &fakeK8s{webhooks: []admissionv1.ValidatingWebhookConfiguration{webhookConfig("webhook.cert-manager.io")}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := admissionPolicyEngines(context.Background(), tt.f)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// An unreadable webhook list leaves the key off the namespace: unknown, so the
// namespace check keeps reporting the label it observed.
func TestCollect_PolicyEnginesOnNamespaces(t *testing.T) {
	for _, tt := range []struct {
		name    string
		f       *fakeK8s
		want    string
		present bool
	}{
		{"engine found", &fakeK8s{namespaces: appNamespace(), webhooks: []admissionv1.ValidatingWebhookConfiguration{webhookConfig("validate.kyverno.svc")}}, "kyverno", true},
		{"none found", &fakeK8s{namespaces: appNamespace()}, "", true},
		{"list forbidden", &fakeK8s{namespaces: appNamespace(), webhookErr: errors.New("forbidden")}, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res, err := withFakeK8s(tt.f).Collect(context.Background(), nil)
			require.NoError(t, err)
			for _, a := range res.Assets {
				if a.Type == "k8s_namespace" {
					v, ok := a.Metadata["cluster_policy_engines"]
					require.Equal(t, tt.present, ok)
					require.Equal(t, tt.want, v)
					return
				}
			}
			t.Fatal("no namespace asset")
		})
	}
}
