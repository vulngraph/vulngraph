package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// ── conditionExpired: the only CEL we evaluate, and only to subtract ──

func TestConditionExpired(t *testing.T) {
	now := at("2026-08-02T12:00:00Z")
	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"unconditional", "", false},
		// A grant of roles/pubsub.publisher under a window that closed in 2021
		// must not count as a live grant.
		{"expired window", `request.time < timestamp("2021-10-31T23:00:00Z")`, true},
		{"window still open", `request.time < timestamp("2027-01-01T00:00:00Z")`, false},
		{"not yet started", `request.time > timestamp("2027-01-01T00:00:00Z")`, true},
		{"already started", `request.time > timestamp("2020-01-01T00:00:00Z")`, false},
		{"<= form", `request.time <= timestamp("2021-01-01T00:00:00Z")`, true},
		{"whitespace tolerated", `request.time   <  timestamp( "2021-01-01T00:00:00Z" )`, true},

		// Everything we cannot decide must fail OPEN — the grant keeps counting.
		// A false "expired" hides a live privilege, which is the worse error.
		{"resource condition", `resource.name.startsWith("projects/_/buckets/x")`, false},
		{"unparseable timestamp", `request.time < timestamp("not-a-date")`, false},
		{"no timestamp call", `request.time < 12345`, false},
		{"compound with open window", `request.time < timestamp("2027-01-01T00:00:00Z") && resource.type == "x"`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, conditionExpired(tt.expr, now))
		})
	}
}

// ── grantsByMember ──

func TestGrantsByMember_SplitsScopeAndCondition(t *testing.T) {
	now := at("2026-08-02T12:00:00Z")
	bindings := []iamBinding{
		{Role: "roles/viewer", Members: []string{"serviceAccount:a@x"}, Resource: "projects/p"},
		{Role: "roles/resourcemanager.organizationAdmin", Members: []string{"serviceAccount:a@x"}, Resource: "organizations/358"},
		{Role: "roles/storage.admin", Members: []string{"serviceAccount:a@x"}, Resource: "folders/144"},
		{
			Role: "roles/pubsub.publisher", Members: []string{"serviceAccount:a@x"},
			Resource: "projects/p", Condition: `request.time < timestamp("2021-10-31T23:00:00Z")`,
		},
		{
			Role: "roles/bigquery.dataViewer", Members: []string{"serviceAccount:a@x"},
			Resource: "projects/p", Condition: `resource.name.startsWith("x")`,
		},
	}

	got := grantsByMember(bindings, now)["serviceAccount:a@x"]

	require.Equal(t, []string{
		"roles/bigquery.dataViewer", // conditional but not disprovable — still counts
		"roles/resourcemanager.organizationAdmin",
		"roles/storage.admin",
		"roles/viewer",
	}, got.effectiveRoles)
	require.Equal(t, []string{
		"roles/resourcemanager.organizationAdmin",
		"roles/storage.admin",
	}, got.inheritedRoles)
	require.Equal(t, []string{"roles/bigquery.dataViewer", "roles/pubsub.publisher"}, got.conditionalRoles)
	require.Equal(t, []string{"roles/pubsub.publisher"}, got.expiredRoles)
	require.NotContains(t, got.effectiveRoles, "roles/pubsub.publisher",
		"a provably-closed time window must not count as a live grant")
}

func TestGrantsByMember_DedupesAcrossScopes(t *testing.T) {
	now := at("2026-08-02T12:00:00Z")
	bindings := []iamBinding{
		{Role: "roles/viewer", Members: []string{"serviceAccount:a@x"}, Resource: "projects/p"},
		{Role: "roles/viewer", Members: []string{"serviceAccount:a@x"}, Resource: "organizations/358"},
	}

	got := grantsByMember(bindings, now)["serviceAccount:a@x"]

	require.Equal(t, []string{"roles/viewer"}, got.effectiveRoles)
}

func TestGrantsByMember_SkipsEmptyRoleAndMember(t *testing.T) {
	now := at("2026-08-02T12:00:00Z")
	bindings := []iamBinding{
		{Role: "", Members: []string{"serviceAccount:a@x"}, Resource: "projects/p"},
		{Role: "roles/viewer", Members: []string{""}, Resource: "projects/p"},
	}

	require.Empty(t, grantsByMember(bindings, now))
}

func TestScopeOf(t *testing.T) {
	require.Equal(t, "organization", scopeOf("organizations/358"))
	require.Equal(t, "folder", scopeOf("folders/144"))
	require.Equal(t, "project", scopeOf("projects/example-gcp-project"))
	require.Equal(t, "project", scopeOf(""))
}

// ── effectivePolicy: inheritance and its failure modes ──

func TestEffectiveBindings_IncludesAncestors(t *testing.T) {
	f := &fakeIAM{
		ancestors: []string{"folders/144", "organizations/358"},
		policies: map[string][]iamBinding{
			"projects/p":        {{Role: "roles/viewer", Members: []string{"serviceAccount:a@x"}, Resource: "projects/p"}},
			"folders/144":       {{Role: "roles/storage.admin", Members: []string{"serviceAccount:a@x"}, Resource: "folders/144"}},
			"organizations/358": {{Role: "roles/owner", Members: []string{"serviceAccount:a@x"}, Resource: "organizations/358"}},
		},
	}

	got, err := effectivePolicy(context.Background(), f, "p")

	require.NoError(t, err)
	require.Len(t, got.bindings, 3)
	require.True(t, got.ancestorsComplete)
}

// An org-only grant must be visible: a service account holding
// roles/resourcemanager.organizationAdmin at the ORG would read, from a
// project-only policy, as zero permissions and zero findings.
func TestEffectiveBindings_OrgOnlyGrantIsVisible(t *testing.T) {
	f := &fakeIAM{
		ancestors: []string{"organizations/246802468024"},
		policies: map[string][]iamBinding{
			"projects/example-gcp-project": nil,
			"organizations/246802468024": {{
				Role:     "roles/resourcemanager.organizationAdmin",
				Members:  []string{"serviceAccount:legacy-admin@example-gcp-project.iam.gserviceaccount.com"},
				Resource: "organizations/246802468024",
			}},
		},
	}

	eff, err := effectivePolicy(context.Background(), f, "example-gcp-project")
	require.NoError(t, err)

	g := grantsByMember(eff.bindings, at("2026-08-02T12:00:00Z"))["serviceAccount:legacy-admin@example-gcp-project.iam.gserviceaccount.com"]
	require.Equal(t, []string{"roles/resourcemanager.organizationAdmin"}, g.effectiveRoles)
	require.Equal(t, []string{"roles/resourcemanager.organizationAdmin"}, g.inheritedRoles)
}

// A project-scoped credential usually cannot read folder/org policies. Losing
// that coverage must never fail the sweep — that trades a partial blind spot for
// a total one.
func TestEffectiveBindings_AncestorErrorsAreBestEffort(t *testing.T) {
	f := &fakeIAM{
		ancestors: []string{"folders/144", "organizations/358"},
		policies: map[string][]iamBinding{
			"projects/p":        {{Role: "roles/viewer", Members: []string{"serviceAccount:a@x"}, Resource: "projects/p"}},
			"organizations/358": {{Role: "roles/owner", Members: []string{"serviceAccount:a@x"}, Resource: "organizations/358"}},
		},
		policyErr: map[string]error{"folders/144": errors.New("permission denied")},
	}

	got, err := effectivePolicy(context.Background(), f, "p")

	require.NoError(t, err)
	require.Len(t, got.bindings, 2, "the readable policies must still be returned")
	require.False(t, got.ancestorsComplete, "an unread ancestor must be recorded")
}

func TestEffectiveBindings_AncestryErrorFallsBackToProject(t *testing.T) {
	f := &fakeIAM{
		ancestryErr: errors.New("permission denied"),
		policies: map[string][]iamBinding{
			"projects/p": {{Role: "roles/viewer", Members: []string{"serviceAccount:a@x"}, Resource: "projects/p"}},
		},
	}

	got, err := effectivePolicy(context.Background(), f, "p")

	require.NoError(t, err)
	require.Len(t, got.bindings, 1)
	require.False(t, got.ancestorsComplete)
}

// The project policy itself is still fatal — that is unchanged behaviour.
func TestEffectiveBindings_ProjectPolicyErrorIsFatal(t *testing.T) {
	f := &fakeIAM{policyErr: map[string]error{"projects/p": errors.New("boom")}}

	_, err := effectivePolicy(context.Background(), f, "p")

	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "effectivePolicy"))
}

// ── end to end through collect ──

func TestCollectIAM_OrgGrantReachesServiceAccountPermissions(t *testing.T) {
	f := &fakeIAM{
		accounts:  []gcpServiceAccount{{Email: "legacy-admin@example-gcp-project.iam.gserviceaccount.com"}},
		ancestors: []string{"organizations/358"},
		policies: map[string][]iamBinding{
			"projects/example-gcp-project": nil,
			"organizations/358": {{
				Role:     "roles/resourcemanager.organizationAdmin",
				Members:  []string{"serviceAccount:legacy-admin@example-gcp-project.iam.gserviceaccount.com"},
				Resource: "organizations/358",
			}},
		},
		rolePerms: map[string][]string{
			"roles/resourcemanager.organizationAdmin": {"resourcemanager.projects.setIamPolicy"},
		},
	}
	c := withFakeIAMProject(f, "example-gcp-project")

	assets, err := c.collect(context.Background(), nil, time.Now())

	require.NoError(t, err)
	require.Len(t, assets, 2, "the service account plus the project anchor")
	require.Equal(t, "resourcemanager.projects.setIamPolicy", assets[0].Metadata["permissions"],
		"an org-level grant must reach the CIEM permission set")
	require.Equal(t, "roles/resourcemanager.organizationAdmin", assets[0].Metadata["inherited_roles"])
}

func TestCollectIAM_ExpiredConditionalGrantIsNotCounted(t *testing.T) {
	f := &fakeIAM{
		accounts: []gcpServiceAccount{{Email: "a@x.iam.gserviceaccount.com"}},
		policies: map[string][]iamBinding{
			"projects/p": {{
				Role:      "roles/pubsub.publisher",
				Members:   []string{"serviceAccount:a@x.iam.gserviceaccount.com"},
				Resource:  "projects/p",
				Condition: `request.time < timestamp("2021-10-31T23:00:00Z")`,
			}},
		},
		rolePerms: map[string][]string{"roles/pubsub.publisher": {"pubsub.topics.publish"}},
	}
	c := withFakeIAMProject(f, "p")

	assets, err := c.collect(context.Background(), nil, at("2026-08-02T12:00:00Z"))

	require.NoError(t, err)
	require.Empty(t, assets[0].Metadata["permissions"], "an expired grant confers nothing")
	require.Equal(t, "roles/pubsub.publisher", assets[0].Metadata["expired_roles"])
	require.Equal(t, "roles/pubsub.publisher", assets[0].Metadata["conditional_roles"])
}

// withFakeIAMProject is withFakeIAM with a caller-chosen project id, so a test
// can key the fake's policies map on the real resource name.
func withFakeIAMProject(f iamAPI, projectID string) iamCollector {
	return iamCollector{
		newIAM: func(context.Context, map[string]string) (iamAPI, string, error) {
			return f, projectID, nil
		},
		auth: testAuthCache(),
	}
}
