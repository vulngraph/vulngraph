// Package k8sns holds the Kubernetes namespace list the collector and the
// check registry must agree on. It is a leaf package so the collector need
// not import the check registry, and the checks' description of the
// exemption is derived from the same list the collector applies.
package k8sns

import "maps"

// configMapSkipped are namespaces whose ConfigMaps the Kubernetes collector
// never maps to k8s_configmap assets: their ConfigMaps are the platform's.
var configMapSkipped = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true,
	"gke-system": true, "gmp-system": true, "gmp-public": true,
	"calico-system": true, "cert-manager": true, "monitoring": true,
	"istio-system": true,
}

// ConfigMapSkipped reports whether the collector skips the ConfigMaps of
// namespace ns.
func ConfigMapSkipped(ns string) bool { return configMapSkipped[ns] }

// ConfigMapSkippedNamespaces returns a copy of the skipped set.
func ConfigMapSkippedNamespaces() map[string]bool { return maps.Clone(configMapSkipped) }
