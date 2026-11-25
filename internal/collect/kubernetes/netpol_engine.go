package kubernetes

import (
	"slices"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// netpol_engine.go names the NetworkPolicy enforcers running in the cluster, so
// CIS EKS 4.3.1/5.4.4 ("network policy is enabled") can be decided from the API
// without eks:DescribeAddon. A NetworkPolicy object is only an intent: with no
// enforcer it filters nothing.
//
// The Amazon VPC CNI enforces policy only when its network policy controller is
// on (addon configuration enableNetworkPolicy, surfaced as
// enable-network-policy-controller in kube-system/amazon-vpc-cni). The other
// engines are recognised by their node agent DaemonSet. The list is a closed
// set: an enforcer it does not know reads as none, which is why the check that
// consumes it grades EKS (where the VPC CNI is the default and these are
// the documented alternatives) at Medium and other clusters at Low.

// networkPolicyAgents maps a node-agent DaemonSet name to its engine.
var networkPolicyAgents = map[string]string{
	"calico-node":  "calico",
	"canal":        "calico",
	"cilium":       "cilium",
	"antrea-agent": "antrea",
	"kube-router":  "kube-router",
	"weave-net":    "weave",
	"azure-npm":    "azure-npm",
	"anetd":        "gke-dataplane-v2",
}

// networkPolicyEngines returns the network_policy_engines key: the sorted,
// comma-joined engines found ("" when none).
func networkPolicyEngines(daemonSets []appsv1.DaemonSet, kubeSystemCMs []corev1.ConfigMap) map[string]string {
	var engines []string
	for _, ds := range daemonSets {
		if e, ok := networkPolicyAgents[ds.Name]; ok && !slices.Contains(engines, e) {
			engines = append(engines, e)
		}
	}
	for _, cm := range kubeSystemCMs {
		if cm.Namespace == "kube-system" && cm.Name == "amazon-vpc-cni" &&
			strings.EqualFold(cm.Data["enable-network-policy-controller"], "true") {
			engines = append(engines, "vpc-cni")
		}
	}
	sort.Strings(engines)
	return map[string]string{"network_policy_engines": strings.Join(engines, ",")}
}
