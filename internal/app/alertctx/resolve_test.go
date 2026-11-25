package alertctx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func matchTypes(p plan) []MatchType {
	var out []MatchType
	for _, l := range p.lookups {
		out = append(out, l.matchType)
	}
	return out
}

func TestPlanFor_Classification(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		normalized string
		types      []MatchType
	}{
		{"arn", "arn:aws:iam::123456789012:role/admin", "arn:aws:iam::123456789012:role/admin", []MatchType{MatchARN}},
		{"assumed-role session collapses to role", "arn:aws:sts::123456789012:assumed-role/deploy/i-0abc/sess",
			"arn:aws:iam::123456789012:role/deploy", []MatchType{MatchARN, MatchARN}},
		{"govcloud partition kept", "arn:aws-us-gov:sts::111122223333:assumed-role/r/s",
			"arn:aws-us-gov:iam::111122223333:role/r", []MatchType{MatchARN, MatchARN}},
		{"federated-user is not collapsed", "arn:aws:sts::123456789012:federated-user/bob",
			"arn:aws:sts::123456789012:federated-user/bob", []MatchType{MatchARN}},
		{"instance id", "i-0123456789abcdef0", "i-0123456789abcdef0", []MatchType{MatchInstanceID}},
		{"public ipv4", "203.0.113.7", "203.0.113.7", []MatchType{MatchIP}},
		{"ipv4-mapped ipv6 unmaps", "::ffff:10.0.0.5", "10.0.0.5", []MatchType{MatchIP}},
		{"email lowercased", "Alice@Example.COM", "alice@example.com", []MatchType{MatchID, MatchEmail}},
		{"hostname lowercased, trailing dot trimmed", "Web.Example.com.", "web.example.com", []MatchType{MatchID, MatchDNS}},
		{"k8s namespace/name", "payments/api-7d9f", "payments/api-7d9f", []MatchType{MatchID, MatchK8s}},
		{"bare name", "prod-db", "prod-db", []MatchType{MatchID, MatchName}},
		{"whitespace trimmed", "  10.1.2.3 ", "10.1.2.3", []MatchType{MatchIP}},
		{"empty", "   ", "", nil},
		{"colon rules out k8s", "https://x/y", "https://x/y", []MatchType{MatchID, MatchName}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := planFor(tt.input)
			assert.Equal(t, tt.normalized, p.normalized)
			assert.Equal(t, tt.types, matchTypes(p))
		})
	}
}

func TestPlanFor_IPConfidence(t *testing.T) {
	assert.Equal(t, ConfHigh, planFor("8.8.8.8").lookups[0].conf)
	for _, private := range []string{"10.0.0.1", "172.16.5.5", "192.168.1.1", "127.0.0.1", "169.254.169.254"} {
		assert.Equal(t, ConfMedium, planFor(private).lookups[0].conf, private)
	}
}

func TestPlanFor_Accept(t *testing.T) {
	role := asset.Asset{ID: "arn:aws:iam::123456789012:role/service-role/deploy", Name: "deploy", Type: "iam_role", AccountID: "123456789012"}
	otherAccount := asset.Asset{ID: "arn:aws:iam::999999999999:role/deploy", Name: "deploy", Type: "iam_role", AccountID: "999999999999"}
	notRole := asset.Asset{ID: "x", Name: "deploy", Type: "iam_user", AccountID: "123456789012"}

	byName := planFor("arn:aws:sts::123456789012:assumed-role/deploy/sess").lookups[1]
	assert.True(t, byName.accept(role), "pathed role matched by name+account")
	assert.False(t, byName.accept(otherAccount), "same role name in another account must not match")
	assert.False(t, byName.accept(notRole), "only iam_role")

	k8s := planFor("payments/api").lookups[1]
	pod := asset.Asset{ID: "c/pod/payments/api", Name: "api", Provider: asset.ProviderKubernetes, Metadata: map[string]string{"namespace": "payments"}}
	assert.True(t, k8s.accept(pod))
	pod.Metadata["namespace"] = "other"
	assert.False(t, k8s.accept(pod))
	pod.Metadata["namespace"], pod.Provider = "payments", asset.ProviderAWS
	assert.False(t, k8s.accept(pod), "namespace/name is a k8s match only for kubernetes assets")

	dns := planFor("api.example.com").lookups[1]
	assert.True(t, dns.accept(asset.Asset{Endpoint: "https://API.example.com:8443/v1"}))
	assert.True(t, dns.accept(asset.Asset{Domain: "api.example.com"}))
	assert.False(t, dns.accept(asset.Asset{Endpoint: "https://evil-api.example.com"}))

	ip := planFor("10.0.0.5").lookups[0]
	assert.True(t, ip.accept(asset.Asset{PrivateIP: "10.0.0.5"}))
	assert.True(t, ip.accept(asset.Asset{PublicIP: "10.0.0.5"}))
	assert.False(t, ip.accept(asset.Asset{PrivateIP: "10.0.0.50"}))

	email := planFor("Alice@example.com").lookups[1]
	assert.True(t, email.accept(asset.Asset{Name: "alice@example.com"}))
	assert.True(t, email.accept(asset.Asset{Domain: "ALICE@example.com"}))
	require.False(t, email.accept(asset.Asset{Name: "malice@example.com"}))
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://a.example.com:8443/x?y=1": "a.example.com",
		"a.example.com":                    "a.example.com",
		"http://a.example.com#frag":        "a.example.com",
		"":                                 "",
	} {
		assert.Equal(t, want, hostOf(in), in)
	}
}
