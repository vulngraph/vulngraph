package iac

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// DeclaredK8sWorkload is one workload/service object parsed from a plain k8s
// manifest in a repo. It is deliberately minimal: the ID of
// the live asset it correlates to is <cluster>/<kind>/<ns>/<name>, and a manifest
// never names the cluster, so the join key is the cluster-agnostic suffix.
type DeclaredK8sWorkload struct {
	Kind      string // canonical k8s kind, e.g. "Deployment"
	Namespace string // "" when the manifest omits it (templated or apply-time default)
	Name      string
	Path      string // repo-relative file the object was declared in
}

// workloadKinds are the manifest kinds correlated to live k8s assets.
// Deployment/StatefulSet/DaemonSet/Job become k8s_<kind> workload
// assets (NodeK8sWorkload); Service becomes a k8s_service asset (NodeAsset).
// Everything else (ConfigMap, Secret, CRDs, RBAC, …) is ignored here.
var workloadKinds = map[string]bool{
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"Job":         true,
	"Service":     true,
}

// SuffixKey is the cluster-agnostic join key <kind-lowercase>/<namespace>/<name>,
// matching the suffix of a live k8s asset ID (<cluster>/<kind>/<ns>/<name>). An
// absent namespace yields an empty middle segment; the correlator handles that
// as a lower-confidence, namespace-agnostic match.
func (d DeclaredK8sWorkload) SuffixKey() string {
	return strings.ToLower(d.Kind) + "/" + d.Namespace + "/" + d.Name
}

// manifestDoc is the minimal shape read from each YAML document. Only the fields
// needed for the correlation key are decoded; the rest of the object is ignored.
type manifestDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
}

// ParseK8sManifests parses each file as a (possibly multi-document) YAML stream
// and returns the declared workloads/services. Best-effort: a document that
// fails to decode, or is not a recognised workload kind, or has no name, is
// silently skipped so one malformed object never drops a whole repo's manifests.
//
// Documents are split on "---" separator lines and unmarshalled independently
// (rather than via yaml.Decoder.Decode in a loop): with yaml.v3's streaming
// decoder, a syntax error in one document corrupts the decoder's position in
// the underlying stream, so a single malformed document silently drops every
// document after it in the same file. Splitting first means one bad chunk
// only costs that chunk.
func ParseK8sManifests(files map[string]string) []DeclaredK8sWorkload {
	var out []DeclaredK8sWorkload
	for path, content := range files {
		for _, chunk := range splitYAMLDocs(content) {
			if strings.TrimSpace(chunk) == "" {
				continue
			}
			var doc manifestDoc
			if err := yaml.Unmarshal([]byte(chunk), &doc); err != nil {
				continue
			}
			if !workloadKinds[doc.Kind] || doc.Metadata.Name == "" {
				continue
			}
			out = append(out, DeclaredK8sWorkload{
				Kind:      doc.Kind,
				Namespace: doc.Metadata.Namespace,
				Name:      doc.Metadata.Name,
				Path:      path,
			})
		}
	}
	return out
}

// splitYAMLDocs splits a multi-document YAML stream into its individual
// document chunks, breaking on lines that are exactly "---" (the standard
// YAML document separator), ignoring trailing whitespace.
func splitYAMLDocs(content string) []string {
	var docs []string
	var cur strings.Builder
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "---" {
			docs = append(docs, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteString(line)
		cur.WriteString("\n")
	}
	docs = append(docs, cur.String())
	return docs
}
