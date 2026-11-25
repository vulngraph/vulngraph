package reason

import (
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// nodeLabelDocs is the prompt text for each queryable node label. Which labels
// are advertised is derived from the registry (QueryableNodeLabels); this map
// only words them. TestNodeLabelDocsMatchQueryableLabels fails on a doc for a
// label nothing loaded reaches, and on a queryable label with no doc.
var nodeLabelDocs = map[string]string{
	graphschema.NodeAsset: "generic cloud resources — EC2/S3/RDS/GCS/VMs/LBs/security groups/k8s_service/cloudrun_service/etc. " +
		"Filter by n.type (e.g. {type:'security_group'}, {type:'ec2_instance'})",
	graphschema.NodeK8sWorkload: "k8s_pod, k8s_deployment, k8s_daemonset, k8s_statefulset, k8s_service_account (NOT Asset)",
	graphschema.NodeIamRole: "ALL identity types — iam_role, iam_user, iam_group, gcp_service_account, " +
		"azure_service_principal, azure_managed_identity. Filter by n.type to distinguish",
	graphschema.NodeRepo:         "GitHub repositories",
	graphschema.NodePackage:      "SBOM packages (has cve_id, epss_score, has_kev fields)",
	graphschema.NodeDataClass:    "DSPM data classifications; ids like 'dataclass:pii'",
	graphschema.NodeCloudAccount: "cloud account/project nodes",
	graphschema.NodeSSOGroup:     "SSO groups (e.g. Okta groups). RESERVED label: MUST be written backtick-escaped as `Group`",
	graphschema.NodeSSOPermSet:   "AWS Identity Center permission sets",
}

// QueryableNodeLabels returns every node label that a loaded rel table
// touches, in registry order. A label no loaded rel reaches (Subnet, DNSZone,
// IamPolicy today) is unfed or unreachable by traversal, so advertising it
// teaches queries that silently return zero rows.
func QueryableNodeLabels() []string {
	seen := map[string]bool{graphschema.NodeAsset: true}
	labels := []string{graphschema.NodeAsset}
	for _, r := range graphschema.LoadedRels() {
		for _, l := range []string{r.From, r.To} {
			if !seen[l] {
				seen[l] = true
				labels = append(labels, l)
			}
		}
	}
	return labels
}

// NodeLabelBlock renders the queryable node labels for an LLM prompt.
func NodeLabelBlock() string {
	var b strings.Builder
	b.WriteString("Node labels (the ONLY queryable ones — do not invent others):\n")
	for _, l := range QueryableNodeLabels() {
		fmt.Fprintf(&b, "- %s: %s\n", l, nodeLabelDocs[l])
	}
	return b.String()
}

// RelSchemaBlock renders the traversable-edge schema section from the
// registry, so a prompt can never advertise an unloaded rel (a rel that exists
// in the DDL but is not loaded returns zero rows silently).
func RelSchemaBlock() string {
	var dead []string
	for _, r := range graphschema.Rels {
		if !r.Loaded {
			dead = append(dead, r.Name)
		}
	}
	var b strings.Builder
	b.WriteString("SCHEMA — Relationship tables (FROM → TO). These are the ONLY traversable edges; do\n")
	fmt.Fprintf(&b, "not invent others (%s exist in the model but are NOT queryable):\n", strings.Join(dead, "/"))
	for _, r := range graphschema.LoadedRels() {
		fmt.Fprintf(&b, "  %-22s %s → %s  %s\n", r.Name, r.From, r.To, r.Doc)
	}
	return b.String()
}
