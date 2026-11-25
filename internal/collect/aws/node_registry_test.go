package aws

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestStampInstanceNodeFacts(t *testing.T) {
	role := func(id string, meta map[string]string) asset.Asset {
		return asset.Asset{ID: id, Type: "iam_role", Metadata: meta}
	}
	policies := func(docs ...policyDoc) string { return encodePolicies(docs) }
	identity := func(doc string) policyDoc { return policyDoc{Name: "p", Type: "identity", Document: doc} }
	trust := policyDoc{Name: "t", Type: "trust", Document: `{"Statement":[{"Effect":"Allow","Action":"ecr:PutImage","Principal":{"Service":"ec2.amazonaws.com"}}]}`}
	instance := func(id, roleARN string) asset.Asset {
		meta := map[string]string{}
		if roleARN != "" {
			meta["iam_role_arn"] = roleARN
		}
		return asset.Asset{ID: id, Type: "ec2_instance", Metadata: meta}
	}

	assets := []asset.Asset{
		role("r-push", map[string]string{"policies": policies(identity(`{"Statement":[{"Effect":"Allow","Action":["ecr:PutImage","ecr:InitiateLayerUpload"],"Resource":"arn:aws:ecr:us-east-1:1:repository/app"}]}`))}),
		role("r-ecr-star", map[string]string{"policies": policies(identity(`{"Statement":[{"Effect":"Allow","Action":"ecr:*","Resource":"*"}]}`))}),
		role("r-read", map[string]string{"policies": policies(identity(`{"Statement":[{"Effect":"Allow","Action":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"],"Resource":"*"}]}`), trust)}),
		role("r-denied", map[string]string{"policies": policies(identity(`{"Statement":[{"Effect":"Allow","Action":"ecr:*","Resource":"*"},{"Effect":"Deny","Action":"ecr:PutImage","Resource":"*"}]}`))}),
		role("r-admin-partial", map[string]string{"admin": "true"}), // admin seen, policies omitted
		role("r-unread", map[string]string{}),                       // policy set incomplete
		instance("i-push", "r-push"),
		instance("i-ecr-star", "r-ecr-star"),
		instance("i-read", "r-read"),
		instance("i-denied", "r-denied"),
		instance("i-admin", "r-admin-partial"),
		instance("i-unread", "r-unread"),
		instance("i-role-not-swept", "r-elsewhere"),
		instance("i-no-role", ""),
	}
	stampInstanceNodeFacts(assets)

	got := map[string]map[string]string{}
	for _, a := range assets {
		got[a.ID] = a.Metadata
	}
	require.Equal(t, "true", got["i-push"]["iam_role_ecr_push"], "a repository-scoped PutImage is still a push")
	require.Equal(t, "true", got["i-ecr-star"]["iam_role_ecr_push"])
	require.Equal(t, "false", got["i-read"]["iam_role_ecr_push"], "a trust policy naming the action grants nothing")
	require.Equal(t, "false", got["i-denied"]["iam_role_ecr_push"], "explicit deny wins")
	require.Equal(t, "true", got["i-admin"]["iam_role_ecr_push"])
	for _, id := range []string{"i-unread", "i-role-not-swept", "i-no-role"} {
		require.NotContains(t, got[id], "iam_role_ecr_push", "%s: an unobserved role is unknown, not read-only", id)
	}

	for id, m := range got {
		if strings.HasPrefix(id, "i-") {
			require.Equal(t, "false", m["k8s_node"], "%s: untagged instance is observed not-a-node", id)
		}
	}
}

func TestStampInstanceNodeFacts_KubernetesNodeTags(t *testing.T) {
	for _, tags := range []map[string]string{
		{"eks:cluster-name": "prod", "eks:nodegroup-name": "ng-1"},
		{"kubernetes.io/cluster/prod": "owned"},
		{"aws:eks:cluster-name": "prod"},
	} {
		assets := []asset.Asset{{ID: "i-1", Type: "ec2_instance", Tags: tags, Metadata: map[string]string{}}}
		stampInstanceNodeFacts(assets)
		require.Equal(t, "true", assets[0].Metadata["k8s_node"], "tags %v", tags)
	}
}

// The node-role facts land once on the role, however many nodes use it.
func TestStampNodeRoleFacts(t *testing.T) {
	push := encodePolicies([]policyDoc{{Name: "p", Type: "identity", Document: `{"Statement":[{"Effect":"Allow","Action":"ecr:PutImage","Resource":"*"}]}`}})
	node := func(id, role, tokens string) asset.Asset {
		return asset.Asset{ID: id, Type: "ec2_instance", Tags: map[string]string{"eks:cluster-name": "prod"},
			Metadata: map[string]string{"iam_role_arn": role, "http_tokens": tokens}}
	}
	assets := []asset.Asset{
		{ID: "r-nodes", Type: "iam_role", Metadata: map[string]string{"policies": push}},
		{ID: "r-v1", Type: "iam_role", Metadata: map[string]string{"policies": push}},
		{ID: "r-app", Type: "iam_role", Metadata: map[string]string{"policies": push}},
		node("i-1", "r-nodes", "required"), node("i-2", "r-nodes", "required"), node("i-3", "r-nodes", "required"),
		node("i-4", "r-v1", "required"), node("i-5", "r-v1", "optional"),
	}
	stampInstanceNodeFacts(assets)
	by := map[string]map[string]string{}
	for _, a := range assets {
		by[a.ID] = a.Metadata
	}
	require.Equal(t, map[string]string{"k8s_node_role": "true", "k8s_node_count": "3", "k8s_node_imdsv1": "false", "ecr_push": "true"},
		map[string]string{"k8s_node_role": by["r-nodes"]["k8s_node_role"], "k8s_node_count": by["r-nodes"]["k8s_node_count"],
			"k8s_node_imdsv1": by["r-nodes"]["k8s_node_imdsv1"], "ecr_push": by["r-nodes"]["ecr_push"]})
	require.Equal(t, "true", by["r-v1"]["k8s_node_imdsv1"], "one IMDSv1 node marks the role")
	require.Equal(t, "false", by["r-app"]["k8s_node_role"])
}
