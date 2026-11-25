package ciem

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestEntryCap(t *testing.T) {
	role := func(meta map[string]string) asset.Asset {
		return asset.Asset{Type: "iam_role", Metadata: meta}
	}
	tests := []struct {
		name string
		a    asset.Asset
		want uint8
	}{
		{"federated entry (Okta/Identity Center)", role(map[string]string{"trust_entry": "federated"}), 45},
		{"service-only entry", role(map[string]string{"trust_entry": "service"}), 45},
		{"MFA-gated entry", role(map[string]string{"mfa_required_to_assume": "true"}), 45},
		{"cross-account specific principals", role(map[string]string{"trust_entry": "cross_account"}), 60},
		{"same-account specific principals", role(map[string]string{"trust_entry": "same_account"}), 60},
		{"public entry — no cap", role(map[string]string{"trust_entry": "public"}), 0},
		{"mixed entry — no cap", role(map[string]string{"trust_entry": "mixed"}), 0},
		{"no trust metadata — no cap", role(map[string]string{}), 0},
		{"iam_user never capped", asset.Asset{Type: "iam_user", Metadata: map[string]string{"trust_entry": "federated"}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, entryCap(tt.a))
		})
	}
}

func TestPrivescScore(t *testing.T) {
	critical := []PrivescResult{{Rule: PrivescRule{Severity: SeverityCritical}}}
	role := func(score uint8, meta map[string]string) asset.Asset {
		return asset.Asset{Type: "iam_role", RiskScore: score, Metadata: meta}
	}
	tests := []struct {
		name  string
		paths []PrivescResult
		a     asset.Asset
		want  uint8
	}{
		{"open entry gets the full critical bump", critical, role(10, map[string]string{"trust_entry": "public"}), 85},
		{"federated entry caps critical at 45", critical, role(10, map[string]string{"trust_entry": "federated"}), 45},
		{"cross-account entry caps critical at 60", critical, role(10, map[string]string{"trust_entry": "cross_account"}), 60},
		{"cap never lowers a pre-existing higher score", critical, role(70, map[string]string{"trust_entry": "federated"}), 70},
		{"medium paths below the cap pass through", []PrivescResult{{Rule: PrivescRule{Severity: SeverityMedium}}}, role(10, map[string]string{"trust_entry": "cross_account"}), 45},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, privescScore(tt.paths, tt.a))
		})
	}
}
