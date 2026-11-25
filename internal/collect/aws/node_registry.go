package aws

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

// registryWriteAction is the one ECR action that rewrites what a tag points
// at. PutImage alone is enough to poison a tag (re-point it at any manifest
// already in the repository); the layer-upload actions only add new content.
const registryWriteAction = "ecr:PutImage"

// stampInstanceNodeFacts records two facts on each EC2 instance that
// aws-eks-node-imdsv1-registry-write combines: whether the instance is a
// Kubernetes worker node (k8s_node), and whether its instance role can push to
// ECR (iam_role_ecr_push, joined from the role asset collected in the same
// sweep). On a node, IMDSv1 hands the node role's credentials to any pod with an
// SSRF, and a push-capable node role turns that into a supply-chain write.
// Checks see one asset at a time, hence the join here.
//
// k8s_node is always written: it comes from the instance's own tags, read in
// the same DescribeInstances call, so its absence is an observation.
// iam_role_ecr_push is written only when the role was observed: an instance with
// no resolved role ARN, a role missing from this sweep, or a role whose policy
// set was not fully read (and is not already admin) leaves it absent — unknown.
func stampInstanceNodeFacts(assets []asset.Asset) {
	push := map[string]bool{}
	for _, a := range assets {
		if a.Type != "iam_role" {
			continue
		}
		if v, ok := roleCanPushImages(a.Metadata); ok {
			push[a.ID] = v
		}
	}
	nodes, imdsV1 := map[string]int{}, map[string]bool{}
	for i := range assets {
		a := &assets[i]
		if a.Type != "ec2_instance" {
			continue
		}
		isNode := kubernetesNodeTags(a.Tags)
		a.Metadata["k8s_node"] = strconv.FormatBool(isNode)
		role := a.Metadata["iam_role_arn"]
		if v, ok := push[role]; ok {
			a.Metadata["iam_role_ecr_push"] = strconv.FormatBool(v)
		}
		if isNode && role != "" {
			nodes[role]++
			if a.Metadata["http_tokens"] == "optional" && a.Metadata["http_endpoint"] != "disabled" {
				imdsV1[role] = true
			}
		}
	}
	stampNodeRoleFacts(assets, push, nodes, imdsV1)
}

// stampNodeRoleFacts records the same facts once per instance role, so a node
// role that can push to ECR is one finding however many nodes use it
// (aws-eks-node-role-ecr-write): k8s_node_role and k8s_node_count from the
// instances seen this sweep, k8s_node_imdsv1 when any of them answers IMDSv1
// (the per-instance High check then reports it), and ecr_push when the role's
// policy set was fully read.
func stampNodeRoleFacts(assets []asset.Asset, push map[string]bool, nodes map[string]int, imdsV1 map[string]bool) {
	for i := range assets {
		a := &assets[i]
		if a.Type != "iam_role" {
			continue
		}
		a.Metadata["k8s_node_role"] = strconv.FormatBool(nodes[a.ID] > 0)
		a.Metadata["k8s_node_count"] = strconv.Itoa(nodes[a.ID])
		a.Metadata["k8s_node_imdsv1"] = strconv.FormatBool(imdsV1[a.ID])
		if v, ok := push[a.ID]; ok {
			a.Metadata["ecr_push"] = strconv.FormatBool(v)
		}
	}
}

// kubernetesNodeTags reports whether an instance's tags mark it as a Kubernetes
// worker: EKS managed node groups tag eks:cluster-name, and self-managed,
// Karpenter and kOps nodes carry kubernetes.io/cluster/<name>.
func kubernetesNodeTags(tags map[string]string) bool {
	for k := range tags {
		if k == "eks:cluster-name" || k == "aws:eks:cluster-name" || strings.HasPrefix(k, "kubernetes.io/cluster/") {
			return true
		}
	}
	return false
}

// roleCanPushImages evaluates a role's collected policy set for ECR push.
// ok is false when the answer is unknown: the collector omits `policies` when
// any document was unreadable, and a partial set cannot prove absence. The
// evaluation is identity ∩ boundary, the same one isAdminish makes: SCPs are
// not on the role asset (they arrive from the management account's sweep).
// isAdminish already logged any NotAction Allow in this same policy set as
// widened to Allow *, so the widening here is not logged a second time.
func roleCanPushImages(meta map[string]string) (canPush, ok bool) {
	if meta["admin"] == "true" {
		return true, true // an admin grant observed even in a partial set is a grant
	}
	raw, present := meta["policies"]
	if !present {
		return false, false
	}
	var docs []policyDoc
	if err := json.Unmarshal([]byte(raw), &docs); err != nil {
		return false, false
	}
	policies := make([]ciem.Policy, 0, len(docs))
	for _, d := range docs {
		if d.Type == "trust" {
			continue // who may assume the role, not what it may do
		}
		policies = append(policies, ciem.Policy{Name: d.Name, Type: d.Type, Document: d.Document, IsManaged: d.Managed})
	}
	perms, err := ciem.EffectivePermissionsForPolicies(policies)
	if err != nil {
		return false, false
	}
	return ciem.HasPermission(perms, registryWriteAction), true
}
