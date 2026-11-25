package correlate

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

const (
	testOIDCProvider = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/ABC123"
	testOIDCIssuer   = "https://oidc.eks.eu-west-1.amazonaws.com/id/ABC123"
)

// irsaTrustPolicy renders the trust policy AWS actually writes for an IRSA role.
func irsaTrustPolicy(provider string, subs ...string) string {
	var sub any = subs
	if len(subs) == 1 {
		sub = subs[0]
	}
	doc, err := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": map[string]any{
			"Effect":    "Allow",
			"Principal": map[string]any{"Federated": provider},
			"Action":    "sts:AssumeRoleWithWebIdentity",
			"Condition": map[string]any{
				"StringEquals": map[string]any{
					"oidc.eks.eu-west-1.amazonaws.com/id/ABC123:sub": sub,
					"oidc.eks.eu-west-1.amazonaws.com/id/ABC123:aud": "sts.amazonaws.com",
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	policies, err := json.Marshal([]map[string]string{{"type": "trust", "document": string(doc)}})
	if err != nil {
		panic(err)
	}
	return string(policies)
}

func irsaRole(arn, provider string, subs ...string) asset.Asset {
	return asset.Asset{ID: arn, Type: "iam_role", Metadata: map[string]string{
		"federated_provider": provider,
		"policies":           irsaTrustPolicy(provider, subs...),
	}}
}

func eksCluster(name string) asset.Asset {
	return asset.Asset{
		ID: "arn:aws:eks:eu-west-1:111122223333:cluster/" + name, Name: name, Type: "eks_cluster",
		Metadata: map[string]string{"oidc_provider_arn": testOIDCProvider, "oidc_issuer": testOIDCIssuer},
	}
}

func k8sSA(cluster, ns, name string) asset.Asset {
	return asset.Asset{
		ID:   cluster + "/namespace/" + ns + "/serviceaccount/" + name,
		Type: "k8s_service_account",
	}
}

func TestIRSATrust(t *testing.T) {
	t.Run("emits the SA→role edge when both sides are collected", func(t *testing.T) {
		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("prod", "payments", "api"),
			irsaRole("arn:aws:iam::111122223333:role/payments-api", testOIDCProvider, "system:serviceaccount:payments:api"),
		})
		edges := IRSATrust{}.Correlate(g)
		require.Len(t, edges, 1)
		e := edges[0]
		require.Equal(t, "prod/namespace/payments/serviceaccount/api", e.SrcID)
		require.Equal(t, "k8s_service_account", e.SrcType)
		require.Equal(t, "arn:aws:iam::111122223333:role/payments-api", e.DstID)
		require.Equal(t, "iam_role", e.DstType)
		require.Equal(t, EdgeFederatedAccess, e.EdgeType)
		require.Equal(t, "eks_irsa", e.Properties["trust_type"])
		require.Equal(t, "system:serviceaccount:payments:api", e.Properties["subject"])
	})

	t.Run("joins across a cluster_name the trust policy cannot know", func(t *testing.T) {
		// The k8s connector's cluster segment is operator-supplied and need not
		// equal the EKS cluster name — which is exactly why no ID may be MINTED
		// from the AWS side. A unique namespace/name suffix still resolves.
		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("example-cluster-blue", "payments", "api"),
			irsaRole("arn:aws:iam::1:role/r", testOIDCProvider, "system:serviceaccount:payments:api"),
		})
		edges := IRSATrust{}.Correlate(g)
		require.Len(t, edges, 1)
		require.Equal(t, "example-cluster-blue/namespace/payments/serviceaccount/api", edges[0].SrcID)
	})

	t.Run("prefers the cluster the OIDC provider names when the suffix is ambiguous", func(t *testing.T) {
		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("staging", "payments", "api"),
			k8sSA("prod", "payments", "api"),
			irsaRole("arn:aws:iam::1:role/r", testOIDCProvider, "system:serviceaccount:payments:api"),
		})
		edges := IRSATrust{}.Correlate(g)
		require.Len(t, edges, 1)
		require.Equal(t, "prod/namespace/payments/serviceaccount/api", edges[0].SrcID)
	})

	t.Run("an unresolvable ambiguity emits nothing", func(t *testing.T) {
		// Same namespace/name in two clusters, neither named by the provider: a
		// guess here is a fabricated attack path across a cluster boundary.
		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("blue", "payments", "api"),
			k8sSA("green", "payments", "api"),
			irsaRole("arn:aws:iam::1:role/r", testOIDCProvider, "system:serviceaccount:payments:api"),
		})
		require.Empty(t, IRSATrust{}.Correlate(g))
	})

	t.Run("no edge is minted for an uncollected ServiceAccount", func(t *testing.T) {
		// The most-clusters-uncollected case. A dangling edge would be invisible;
		// a missing one shows up in coverage. See the rule doc.
		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("prod", "other", "sa"), // forces a non-empty SA index
			irsaRole("arn:aws:iam::1:role/r", testOIDCProvider, "system:serviceaccount:payments:api"),
		})
		require.Empty(t, IRSATrust{}.Correlate(g))
	})

	t.Run("a wildcard subject links every SA it matches in the issuing cluster", func(t *testing.T) {
		// payments:* really does let every payments SA assume the role.
		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("prod", "payments", "api"),
			k8sSA("prod", "payments", "worker"),
			k8sSA("prod", "billing", "api"),
			k8sSA("staging", "payments", "api"),
			irsaRole("arn:aws:iam::1:role/r", testOIDCProvider, "system:serviceaccount:payments:*"),
		})
		var srcs []string
		for _, e := range (IRSATrust{}).Correlate(g) {
			srcs = append(srcs, e.SrcID)
			require.Equal(t, "system:serviceaccount:payments:*", e.Properties["subject"])
		}
		require.ElementsMatch(t, []string{
			"prod/namespace/payments/serviceaccount/api",
			"prod/namespace/payments/serviceaccount/worker",
		}, srcs)
	})

	t.Run("a wildcard across ambiguous unnamed clusters emits nothing", func(t *testing.T) {
		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("blue", "payments", "api"),
			k8sSA("green", "payments", "api"),
			irsaRole("arn:aws:iam::1:role/r", testOIDCProvider, "system:serviceaccount:payments:*"),
		})
		require.Empty(t, IRSATrust{}.Correlate(g))
	})

	t.Run("a wildcard resolves in a single differently-named cluster", func(t *testing.T) {
		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("blue", "payments", "api"),
			irsaRole("arn:aws:iam::1:role/r", testOIDCProvider, "system:serviceaccount:*"),
		})
		edges := IRSATrust{}.Correlate(g)
		require.Len(t, edges, 1)
		require.Equal(t, "blue/namespace/payments/serviceaccount/api", edges[0].SrcID)
	})

	t.Run("a non-EKS federated provider is ignored", func(t *testing.T) {
		// GitHub Actions OIDC is FederationTrust's job; attributing its subjects
		// to a ServiceAccount would invent a trust that does not exist.
		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("prod", "payments", "api"),
			irsaRole("arn:aws:iam::1:role/r",
				"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com",
				"system:serviceaccount:payments:api"),
		})
		require.Empty(t, IRSATrust{}.Correlate(g))
	})

	t.Run("subjects are attributed per statement, not per role", func(t *testing.T) {
		// A role federating two providers must not lend one provider's subjects
		// to the other. Two statements, one EKS and one GitHub, each with its own
		// sub — only the EKS one may produce an edge.
		trust := `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Principal":{"Federated":"` + testOIDCProvider + `"},
			 "Condition":{"StringEquals":{"oidc.eks.eu-west-1.amazonaws.com/id/ABC123:sub":"system:serviceaccount:payments:api"}}},
			{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
			 "Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"system:serviceaccount:payments:worker"}}}]}`
		policies, err := json.Marshal([]map[string]string{{"type": "trust", "document": trust}})
		require.NoError(t, err)

		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("prod", "payments", "api"),
			k8sSA("prod", "payments", "worker"),
			{ID: "arn:aws:iam::1:role/r", Type: "iam_role", Metadata: map[string]string{
				"federated_provider": testOIDCProvider, "policies": string(policies)}},
		})
		edges := IRSATrust{}.Correlate(g)
		require.Len(t, edges, 1)
		require.Equal(t, "prod/namespace/payments/serviceaccount/api", edges[0].SrcID)
	})

	t.Run("a Deny statement grants nothing", func(t *testing.T) {
		trust := `{"Statement":{"Effect":"Deny","Principal":{"Federated":"` + testOIDCProvider + `"},
			"Condition":{"StringEquals":{"oidc.eks.eu-west-1.amazonaws.com/id/ABC123:sub":"system:serviceaccount:payments:api"}}}}`
		policies, err := json.Marshal([]map[string]string{{"type": "trust", "document": trust}})
		require.NoError(t, err)
		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("prod", "payments", "api"),
			{ID: "arn:aws:iam::1:role/r", Type: "iam_role", Metadata: map[string]string{
				"federated_provider": testOIDCProvider, "policies": string(policies)}},
		})
		require.Empty(t, IRSATrust{}.Correlate(g))
	})

	t.Run("an uncollected cluster leaves the role unattributed", func(t *testing.T) {
		// Without the eks_cluster asset there is no provider→cluster mapping, so
		// the role's federated_provider cannot be recognised as EKS at all.
		g := NewGraph([]asset.Asset{
			k8sSA("prod", "payments", "api"),
			irsaRole("arn:aws:iam::1:role/r", testOIDCProvider, "system:serviceaccount:payments:api"),
		})
		require.Empty(t, IRSATrust{}.Correlate(g))
	})

	t.Run("one role trusting several ServiceAccounts emits one edge each", func(t *testing.T) {
		g := NewGraph([]asset.Asset{
			eksCluster("prod"),
			k8sSA("prod", "payments", "api"),
			k8sSA("prod", "billing", "cron"),
			irsaRole("arn:aws:iam::1:role/r", testOIDCProvider,
				"system:serviceaccount:payments:api", "system:serviceaccount:billing:cron"),
		})
		edges := IRSATrust{}.Correlate(g)
		require.Len(t, edges, 2)
		srcs := []string{edges[0].SrcID, edges[1].SrcID}
		require.ElementsMatch(t, []string{
			"prod/namespace/payments/serviceaccount/api",
			"prod/namespace/billing/serviceaccount/cron",
		}, srcs)
	})
}

// irsaRoleWithCondition is an IRSA role whose single trust statement carries
// the given Condition block.
func irsaRoleWithCondition(t *testing.T, cond map[string]any) asset.Asset {
	t.Helper()
	stmt := map[string]any{
		"Effect": "Allow", "Principal": map[string]any{"Federated": testOIDCProvider},
		"Action": "sts:AssumeRoleWithWebIdentity",
	}
	if cond != nil {
		stmt["Condition"] = cond
	}
	doc, err := json.Marshal(map[string]any{"Statement": stmt})
	require.NoError(t, err)
	policies, err := json.Marshal([]map[string]string{{"type": "trust", "document": string(doc)}})
	require.NoError(t, err)
	return asset.Asset{ID: "arn:aws:iam::1:role/r", Type: "iam_role", Metadata: map[string]string{
		"federated_provider": testOIDCProvider, "policies": string(policies)}}
}

// The service accounts a trust admits: its matching sub conditions (an
// ...IfExists form included, since every token carries sub), or every SA in
// the issuing cluster when it has none, less the SAs a negated sub keeps out.
func TestIRSATrust_SubOperators(t *testing.T) {
	const subKey = "oidc.eks.eu-west-1.amazonaws.com/id/ABC123:sub"
	const audKey = "oidc.eks.eu-west-1.amazonaws.com/id/ABC123:aud"
	tests := []struct {
		name string
		cond map[string]any
		want []string
	}{
		{"StringLikeIfExists admits like StringLike",
			map[string]any{"StringLikeIfExists": map[string]any{subKey: "system:serviceaccount:payments:*"}},
			[]string{"payments:api", "payments:worker"}},
		{"StringEqualsIfExists admits like StringEquals",
			map[string]any{"StringEqualsIfExists": map[string]any{subKey: "system:serviceaccount:billing:cron"}},
			[]string{"billing:cron"}},
		{"a negated sub alone admits every other SA in the cluster",
			map[string]any{"StringNotEquals": map[string]any{subKey: "system:serviceaccount:payments:api"}},
			[]string{"payments:worker", "billing:cron"}},
		{"a negated like sub keeps out every SA it matches",
			map[string]any{"StringNotLikeIfExists": map[string]any{subKey: "system:serviceaccount:payments:*"}},
			[]string{"billing:cron"}},
		{"a matching sub less a negated one",
			map[string]any{
				"StringLike":      map[string]any{subKey: "system:serviceaccount:payments:*"},
				"StringNotEquals": map[string]any{subKey: "system:serviceaccount:payments:api"},
			},
			[]string{"payments:worker"}},
		{"a negated literal is not a pattern",
			map[string]any{"StringNotEquals": map[string]any{subKey: "system:serviceaccount:payments:*"}},
			[]string{"payments:api", "payments:worker", "billing:cron"}},
		{"an aud check alone admits every SA in the cluster",
			map[string]any{"StringEquals": map[string]any{audKey: "sts.amazonaws.com"}},
			[]string{"payments:api", "payments:worker", "billing:cron"}},
		{"no Condition admits every SA in the cluster", nil,
			[]string{"payments:api", "payments:worker", "billing:cron"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGraph([]asset.Asset{
				eksCluster("prod"),
				k8sSA("prod", "payments", "api"),
				k8sSA("prod", "payments", "worker"),
				k8sSA("prod", "billing", "cron"),
				irsaRoleWithCondition(t, tt.cond),
			})
			var got []string
			for _, e := range (IRSATrust{}).Correlate(g) {
				subject, ok := serviceAccountSubject(asset.Asset{ID: e.SrcID})
				require.True(t, ok)
				got = append(got, subject)
			}
			require.ElementsMatch(t, tt.want, got)
		})
	}
}
