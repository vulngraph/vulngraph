package kubernetes

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// admission_coverage.go decides, per namespace, whether an installed policy
// engine actually ENFORCES pod security there (CIS Kubernetes 5.2.1). An
// installed engine is not evidence: Kyverno and Gatekeeper run their webhooks
// with zero policies, or with Audit-only ones. Only these count:
//
//   - a Kyverno ClusterPolicy (or a Policy in that namespace) with a rule that
//     matches Pods, uses validate.podSecurity, and fails Enforce (the rule's
//     validate.failureAction, else spec.validationFailureAction);
//   - a Gatekeeper constraint of a pod-security-library kind (K8sPSP*) whose
//     enforcementAction is deny (the default) and that matches Pods.
//
// ValidatingAdmissionPolicies are not counted: whether a CEL expression
// enforces pod security cannot be decided reliably from its text. Kyverno
// policies written as plain validate.pattern rules are not recognised either.
// A namespace without such evidence keeps its PSA grade; a failed read makes
// the coverage unknown and the namespace is graded as unlabelled.

var (
	kyvernoClusterPolicyGVR = schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "clusterpolicies"}
	kyvernoPolicyGVR        = schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "policies"}
)

// gatekeeperPSPKinds are the constraint templates of the Gatekeeper
// pod-security-policy library (gatekeeper-library library/pod-security-policy),
// as plural resource names under constraints.gatekeeper.sh.
var gatekeeperPSPKinds = []string{
	"k8spspallowedusers", "k8spspallowprivilegeescalationcontainer", "k8spspapparmor", "k8spspautomountserviceaccounttokenpod",
	"k8spspcapabilities", "k8spspflexvolumes", "k8spspforbiddensysctls", "k8spspfsgroup", "k8spsphostfilesystem",
	"k8spsphostnamespace", "k8spsphostnetworkingports", "k8spspprivilegedcontainer", "k8spspprocmount",
	"k8spspreadonlyrootfilesystem", "k8spspseccomp", "k8spspselinuxv2", "k8spspvolumetypes",
}

// podSecurityCoverage returns namespace → the engine enforcing pod security in
// it ("" for none) over the given namespaces. engines is the installed set
// (admissionPolicyEngines): an engine that is not installed is not read.
func podSecurityCoverage(ctx context.Context, client k8sAPI, engines string, namespaces []string) (map[string]string, error) {
	out := make(map[string]string, len(namespaces))
	for _, ns := range namespaces {
		out[ns] = ""
	}
	installed := strings.Split(engines, ",")
	if slices.Contains(installed, "kyverno") {
		if err := kyvernoCoverage(ctx, client, out); err != nil {
			return nil, fmt.Errorf("podSecurityCoverage: %w", err)
		}
	}
	if slices.Contains(installed, "gatekeeper") {
		if err := gatekeeperCoverage(ctx, client, out); err != nil {
			return nil, fmt.Errorf("podSecurityCoverage: %w", err)
		}
	}
	return out, nil
}

func kyvernoCoverage(ctx context.Context, client k8sAPI, out map[string]string) error {
	cluster, err := listOrNone(ctx, client, kyvernoClusterPolicyGVR)
	if err != nil {
		return fmt.Errorf("kyvernoCoverage: %w", err)
	}
	namespaced, err := listOrNone(ctx, client, kyvernoPolicyGVR)
	if err != nil {
		return fmt.Errorf("kyvernoCoverage: %w", err)
	}
	for _, p := range append(cluster, namespaced...) {
		specAction, _, _ := unstructured.NestedString(p.Object, "spec", "validationFailureAction")
		rules, _, _ := unstructured.NestedSlice(p.Object, "spec", "rules")
		for _, raw := range rules {
			rule, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if _, ok, _ := unstructured.NestedMap(rule, "validate", "podSecurity"); !ok {
				continue
			}
			action, _, _ := unstructured.NestedString(rule, "validate", "failureAction")
			if !strings.EqualFold(firstNonEmpty(action, specAction), "enforce") {
				continue
			}
			for ns := range out {
				if out[ns] == "" && (p.GetNamespace() == "" || p.GetNamespace() == ns) && kyvernoRuleCovers(rule, ns) {
					out[ns] = "kyverno"
				}
			}
		}
	}
	return nil
}

// kyvernoRuleCovers reports whether a rule's match selects Pods in ns and its
// exclude does not drop ns. Selector-based scoping (namespaceSelector,
// selector) is treated as not covering: which namespaces it selects is not
// decided here.
func kyvernoRuleCovers(rule map[string]any, ns string) bool {
	matched := false
	for _, res := range kyvernoResourceBlocks(rule, "match") {
		if hasSelector(res) || !kindsIncludePod(res) {
			continue
		}
		if names, _, _ := unstructured.NestedStringSlice(res, "namespaces"); len(names) == 0 || nsMatches(names, ns) {
			matched = true
		}
	}
	if !matched {
		return false
	}
	for _, res := range kyvernoResourceBlocks(rule, "exclude") {
		if hasSelector(res) {
			return false // an exclusion we cannot evaluate could drop ns
		}
		if names, _, _ := unstructured.NestedStringSlice(res, "namespaces"); nsMatches(names, ns) {
			return false
		}
	}
	return true
}

// kyvernoResourceBlocks returns the resource filters under match/exclude:
// .resources, and .any[].resources / .all[].resources.
func kyvernoResourceBlocks(rule map[string]any, key string) []map[string]any {
	var out []map[string]any
	if res, ok, _ := unstructured.NestedMap(rule, key, "resources"); ok {
		out = append(out, res)
	}
	for _, list := range []string{"any", "all"} {
		items, _, _ := unstructured.NestedSlice(rule, key, list)
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				if res, ok, _ := unstructured.NestedMap(m, "resources"); ok {
					out = append(out, res)
				}
			}
		}
	}
	return out
}

func hasSelector(res map[string]any) bool {
	_, ns := res["namespaceSelector"]
	_, sel := res["selector"]
	return ns || sel
}

func kindsIncludePod(res map[string]any) bool {
	kinds, _, _ := unstructured.NestedStringSlice(res, "kinds")
	for _, k := range kinds {
		if k == "Pod" || strings.HasSuffix(k, "/Pod") || k == "*" {
			return true
		}
	}
	return false
}

func nsMatches(patterns []string, ns string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, ns); ok {
			return true
		}
	}
	return false
}

func gatekeeperCoverage(ctx context.Context, client k8sAPI, out map[string]string) error {
	for _, kind := range gatekeeperPSPKinds {
		items, err := listOrNone(ctx, client, schema.GroupVersionResource{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Resource: kind})
		if err != nil {
			return fmt.Errorf("gatekeeperCoverage: %w", err)
		}
		for _, c := range items {
			action, _, _ := unstructured.NestedString(c.Object, "spec", "enforcementAction")
			if action != "" && action != "deny" {
				continue // dryrun, warn, scoped: not enforcing
			}
			match, _, _ := unstructured.NestedMap(c.Object, "spec", "match")
			if !gatekeeperMatchesPods(match) || hasSelector(match) {
				continue
			}
			only, _, _ := unstructured.NestedStringSlice(match, "namespaces")
			excluded, _, _ := unstructured.NestedStringSlice(match, "excludedNamespaces")
			for ns := range out {
				if out[ns] == "" && (len(only) == 0 || nsMatches(only, ns)) && !nsMatches(excluded, ns) {
					out[ns] = "gatekeeper"
				}
			}
		}
	}
	return nil
}

// gatekeeperMatchesPods reports whether spec.match.kinds selects Pods (no
// kinds selects everything).
func gatekeeperMatchesPods(match map[string]any) bool {
	kinds, _, _ := unstructured.NestedSlice(match, "kinds")
	if len(kinds) == 0 {
		return true
	}
	for _, k := range kinds {
		m, ok := k.(map[string]any)
		if !ok {
			continue
		}
		names, _, _ := unstructured.NestedStringSlice(m, "kinds")
		groups, _, _ := unstructured.NestedStringSlice(m, "apiGroups")
		if (slices.Contains(names, "Pod") || slices.Contains(names, "*")) &&
			(len(groups) == 0 || slices.Contains(groups, "") || slices.Contains(groups, "*")) {
			return true
		}
	}
	return false
}

// listOrNone lists a custom resource cluster-wide; an absent CRD is none.
func listOrNone(ctx context.Context, client k8sAPI, gvr schema.GroupVersionResource) ([]unstructured.Unstructured, error) {
	items, err := client.ListCustomResources(ctx, gvr)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", gvr.Resource, err)
	}
	return items, nil
}

func (r *realK8s) ListCustomResources(ctx context.Context, gvr schema.GroupVersionResource) ([]unstructured.Unstructured, error) {
	if r.dyn == nil {
		return nil, fmt.Errorf("ListCustomResources: no dynamic client")
	}
	list, err := r.dyn.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("ListCustomResources: %w", err)
	}
	return list.Items, nil
}
