package kubernetes

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// admission_engines.go names the cluster-wide admission policy mechanisms a
// namespace without a Pod Security Admission label may still be governed by
// (CIS Kubernetes 5.2.1: "at least one active policy control mechanism"):
// a policy-engine validating webhook (Kyverno, Gatekeeper, Kubewarden, the
// sigstore policy-controller, jsPolicy) or a ValidatingAdmissionPolicy binding
// that denies. The result is stamped on every namespace asset as
// cluster_policy_engines; it is omitted when either list could not be read, so
// the namespace check keeps reporting what it observed rather than assuming an
// engine.

// webhookEngines maps a substring of a validating webhook's name to its engine.
var webhookEngines = []struct{ marker, engine string }{
	{".kyverno.svc", "kyverno"},
	{"gatekeeper.sh", "gatekeeper"},
	{".kubewarden.admission", "kubewarden"},
	{"policy.sigstore.dev", "sigstore-policy-controller"},
	{"jspolicy", "jspolicy"},
}

// admissionPolicyEngines returns the sorted, comma-joined engines found ("" for
// none), or an error when either listing failed.
func admissionPolicyEngines(ctx context.Context, client k8sAPI) (string, error) {
	hooks, err := client.ListValidatingWebhookConfigurations(ctx)
	if err != nil {
		return "", fmt.Errorf("admissionPolicyEngines: webhooks: %w", err)
	}
	bindings, err := client.ListValidatingAdmissionPolicyBindings(ctx)
	if err != nil {
		return "", fmt.Errorf("admissionPolicyEngines: policy bindings: %w", err)
	}
	var engines []string
	add := func(e string) {
		if !slices.Contains(engines, e) {
			engines = append(engines, e)
		}
	}
	for _, cfg := range hooks {
		for _, w := range cfg.Webhooks {
			for _, m := range webhookEngines {
				if strings.Contains(w.Name, m.marker) {
					add(m.engine)
				}
			}
		}
	}
	for _, b := range bindings {
		if slices.Contains(b.Spec.ValidationActions, admissionv1.Deny) {
			add("validating-admission-policy")
		}
	}
	sort.Strings(engines)
	return strings.Join(engines, ","), nil
}

func (r *realK8s) ListValidatingWebhookConfigurations(ctx context.Context) ([]admissionv1.ValidatingWebhookConfiguration, error) {
	list, err := r.cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("ListValidatingWebhookConfigurations: %w", err)
	}
	return list.Items, nil
}

func (r *realK8s) ListValidatingAdmissionPolicyBindings(ctx context.Context) ([]admissionv1.ValidatingAdmissionPolicyBinding, error) {
	list, err := r.cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("ListValidatingAdmissionPolicyBindings: %w", err)
	}
	return list.Items, nil
}
