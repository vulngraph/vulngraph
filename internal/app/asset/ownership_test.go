package asset

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func definedIn(dst, conf, path string) Edge {
	return Edge{DstID: dst, EdgeType: EdgeTypeDefinedIn, Properties: map[string]string{"confidence": conf, "path": path}}
}

func TestResolveOwnership(t *testing.T) {
	repo := Asset{ID: "acme/infra", Type: "github_repo", Metadata: map[string]string{
		MetaCodeowners: "* @acme/platform\n/k8s/payments/ @acme/payments\n",
	}}
	repos := map[string]Asset{repo.ID: repo}

	tests := []struct {
		name string
		a    Asset
		ev   OwnershipEvidence
		keys []string
		want Ownership
	}{
		{
			name: "tag wins over IaC",
			a:    Asset{ID: "r", Tags: map[string]string{"team": "Payments"}},
			ev:   OwnershipEvidence{DefinedIn: []Edge{definedIn("acme/infra", "high", "k8s/payments/a.yaml")}, Repos: repos},
			want: Ownership{Team: "payments", Source: OwnerSourceTag, Confidence: "high", Evidence: "tag:team"},
		},
		{
			name: "owner tag outranks team tag",
			a:    Asset{ID: "r", Tags: map[string]string{"team": "a", "owner": "b"}},
			want: Ownership{Team: "b", Source: OwnerSourceTag, Confidence: "high", Evidence: "tag:owner"},
		},
		{
			name: "configured key outranks defaults",
			a:    Asset{ID: "r", Tags: map[string]string{"owner": "b", "cost-center": "finops"}},
			keys: OwnerTagKeys([]string{"cost-center"}),
			want: Ownership{Team: "finops", Source: OwnerSourceTag, Confidence: "high", Evidence: "tag:cost-center"},
		},
		{
			name: "k8s part-of label",
			a:    Asset{ID: "r", Tags: map[string]string{"app.kubernetes.io/part-of": "checkout"}},
			want: Ownership{Team: "checkout", Source: OwnerSourceTag, Confidence: "high", Evidence: "tag:app.kubernetes.io/part-of"},
		},
		{
			name: "blank tag value is not an owner",
			a:    Asset{ID: "r", Tags: map[string]string{"owner": "  "}},
			want: Ownership{Source: OwnerSourceNone},
		},
		{
			name: "CODEOWNERS path match refines the defining repo to a team",
			a:    Asset{ID: "r"},
			ev:   OwnershipEvidence{DefinedIn: []Edge{definedIn("acme/infra", "high", "k8s/payments/deploy.yaml")}, Repos: repos},
			want: Ownership{Team: "payments", Source: OwnerSourceCodeowners, Confidence: "high", Evidence: "codeowners:acme/infra:/k8s/payments/"},
		},
		{
			name: "CODEOWNERS catch-all carries the edge's confidence",
			a:    Asset{ID: "r"},
			ev:   OwnershipEvidence{DefinedIn: []Edge{definedIn("acme/infra", "low", "infra/roles.tf")}, Repos: repos},
			want: Ownership{Team: "platform", Source: OwnerSourceCodeowners, Confidence: "low", Evidence: "codeowners:acme/infra:*"},
		},
		{
			name: "no path on the edge: only the catch-all applies, capped at medium",
			a:    Asset{ID: "r"},
			ev:   OwnershipEvidence{DefinedIn: []Edge{definedIn("acme/infra", "high", "")}, Repos: repos},
			want: Ownership{Team: "platform", Source: OwnerSourceCodeowners, Confidence: "medium", Evidence: "codeowners:acme/infra:*"},
		},
		{
			name: "no path and no catch-all: the repo is the owner",
			a:    Asset{ID: "r"},
			ev: OwnershipEvidence{DefinedIn: []Edge{definedIn("acme/infra", "high", "")}, Repos: map[string]Asset{
				"acme/infra": {ID: "acme/infra", Metadata: map[string]string{MetaCodeowners: "/k8s/ @acme/k8s"}},
			}},
			want: Ownership{Team: "repo:acme/infra", Source: OwnerSourceIaC, Confidence: "high", Evidence: "defined_in:acme/infra"},
		},
		{
			name: "repo not in inventory: the repo is the owner",
			a:    Asset{ID: "r"},
			ev:   OwnershipEvidence{DefinedIn: []Edge{definedIn("Acme/Other", "", "x.tf")}},
			want: Ownership{Team: "repo:acme/other", Source: OwnerSourceIaC, Confidence: "low", Evidence: "defined_in:Acme/Other"},
		},
		{
			name: "higher-confidence edge wins regardless of order",
			a:    Asset{ID: "r"},
			ev: OwnershipEvidence{DefinedIn: []Edge{
				definedIn("acme/shared-modules", "low", ""),
				definedIn("acme/infra", "high", "k8s/payments/x.yaml"),
			}, Repos: repos},
			want: Ownership{Team: "payments", Source: OwnerSourceCodeowners, Confidence: "high", Evidence: "codeowners:acme/infra:/k8s/payments/"},
		},
		{
			name: "a repo's own CODEOWNERS default owns repo-keyed findings",
			a:    repo,
			want: Ownership{Team: "platform", Source: OwnerSourceCodeowners, Confidence: "medium", Evidence: "codeowners:acme/infra:*"},
		},
		{
			name: "nothing: unowned is an affirmative state",
			a:    Asset{ID: "r"},
			want: Ownership{Source: OwnerSourceNone},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveOwnership(tt.a, tt.ev, tt.keys)
			assert.Equal(t, tt.want, got)
			assert.True(t, got.Resolved())
		})
	}
}

func TestNormalizeOwner(t *testing.T) {
	for in, want := range map[string]string{
		"@acme/Payments": "payments",
		"@alice":         "alice",
		" Payments ":     "payments",
		"dev@acme.io":    "dev@acme.io",
		"repo:acme/x":    "repo:acme/x",
	} {
		assert.Equal(t, want, NormalizeOwner(in), in)
	}
}

func TestOwnerTagKeys_ConfiguredFirstDeduped(t *testing.T) {
	assert.Equal(t,
		[]string{"cost-center", "team", "owner", "Owner", "Team", "app.kubernetes.io/part-of"},
		OwnerTagKeys([]string{" cost-center ", "team", ""}))
}

func TestOwnershipZeroValueIsUnresolvedNotUnowned(t *testing.T) {
	var o Ownership
	assert.False(t, o.Resolved())
	assert.False(t, o.Unowned())
}

type edgeErrRepo struct {
	*fakeRepo
	edgesErr, getErr error
}

func (r edgeErrRepo) EdgesOut(ctx context.Context, src, typ string) ([]Edge, error) {
	if r.edgesErr != nil {
		return nil, r.edgesErr
	}
	return r.fakeRepo.EdgesOut(ctx, src, typ)
}

func (r edgeErrRepo) GetAsset(ctx context.Context, id string) (Asset, error) {
	if r.getErr != nil {
		return Asset{}, r.getErr
	}
	return r.fakeRepo.GetAsset(ctx, id)
}

func TestServiceResolveOwner(t *testing.T) {
	ctx := context.Background()
	fr := newFakeRepo()
	fr.assets["acme/infra"] = Asset{ID: "acme/infra", Type: "github_repo",
		Metadata: map[string]string{MetaCodeowners: "/tf/ @acme/net\n"}}
	fr.edges["vpc-1"] = []Edge{definedIn("acme/infra", "high", "tf/vpc.tf")}

	t.Run("walks defined_in to CODEOWNERS", func(t *testing.T) {
		o, err := NewService(fr).ResolveOwner(ctx, Asset{ID: "vpc-1"}, nil)
		require.NoError(t, err)
		assert.Equal(t, "net", o.Team)
		assert.Equal(t, OwnerSourceCodeowners, o.Source)
	})
	t.Run("tag short-circuits without a graph read", func(t *testing.T) {
		svc := NewService(edgeErrRepo{fakeRepo: fr, edgesErr: errors.New("boom")})
		o, err := svc.ResolveOwner(ctx, Asset{ID: "vpc-1", Tags: map[string]string{"team": "x"}}, nil)
		require.NoError(t, err)
		assert.Equal(t, "x", o.Team)
	})
	t.Run("edge read failure is an error, never unowned", func(t *testing.T) {
		svc := NewService(edgeErrRepo{fakeRepo: fr, edgesErr: errors.New("ch down")})
		o, err := svc.ResolveOwner(ctx, Asset{ID: "vpc-1"}, nil)
		require.Error(t, err)
		assert.False(t, o.Resolved())
	})
	t.Run("repo read failure is an error", func(t *testing.T) {
		svc := NewService(edgeErrRepo{fakeRepo: fr, getErr: errors.New("ch down")})
		_, err := svc.ResolveOwner(ctx, Asset{ID: "vpc-1"}, nil)
		require.Error(t, err)
	})
	t.Run("missing repo keeps the IaC claim", func(t *testing.T) {
		svc := NewService(edgeErrRepo{fakeRepo: fr, getErr: ErrNotFound})
		o, err := svc.ResolveOwner(ctx, Asset{ID: "vpc-1"}, nil)
		require.NoError(t, err)
		assert.Equal(t, OwnerSourceIaC, o.Source)
		assert.Equal(t, "repo:acme/infra", o.Team)
	})
	t.Run("no evidence resolves unowned", func(t *testing.T) {
		o, err := NewService(fr).ResolveOwner(ctx, Asset{ID: "lonely"}, nil)
		require.NoError(t, err)
		assert.True(t, o.Unowned())
	})
}
