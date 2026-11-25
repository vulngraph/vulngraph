package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func projectMD(t *testing.T, f *fakeIAM) map[string]string {
	t.Helper()
	assets, err := withFakeIAMProject(f, "p").collect(context.Background(), nil, time.Now())
	require.NoError(t, err)
	last := assets[len(assets)-1]
	require.Equal(t, "cloud_account", last.Type)
	require.Equal(t, "gcp:p", last.ID)
	require.Equal(t, "p", last.AccountID)
	return last.Metadata
}

var fullAudit = []auditConfig{{Service: "allServices", Logs: []auditLog{
	{Type: "ADMIN_READ"}, {Type: "DATA_READ"}, {Type: "DATA_WRITE"},
}}}

func TestProjectAsset_IAMPosture(t *testing.T) {
	md := projectMD(t, &fakeIAM{
		policies: map[string][]iamBinding{
			"projects/p": {
				{Role: roleSAUser, Resource: "projects/p", Members: []string{
					"user:dev@corp.example", "serviceAccount:ci@p.iam.gserviceaccount.com", "group:ops@corp.example",
				}},
				{Role: roleSATokenCreator, Resource: "projects/p", Members: []string{"user:dev@corp.example"}},
				{Role: roleSAAdmin, Resource: "projects/p", Members: []string{"user:dev@corp.example"}},
				{Role: roleKMSAdmin, Resource: "projects/p", Members: []string{"user:kms@corp.example"}},
				{Role: "roles/cloudkms.cryptoKeyDecrypter", Resource: "projects/p", Members: []string{"user:kms@corp.example"}},
				{Role: "roles/viewer", Resource: "projects/p", Members: []string{"user:someone@gmail.com", "user:x@GoogleMail.com"}},
			},
		},
		audit: map[string][]auditConfig{"projects/p": fullAudit},
	})
	require.Equal(t, "user:someone@gmail.com,user:x@GoogleMail.com", md["consumer_account_members"])
	require.Equal(t,
		"group:ops@corp.example=roles/iam.serviceAccountUser,user:dev@corp.example=roles/iam.serviceAccountTokenCreator,user:dev@corp.example=roles/iam.serviceAccountUser",
		md["sa_impersonation_project_members"], "service accounts are excluded; humans and groups are not")
	require.Equal(t, "user:dev@corp.example", md["sa_admin_user_members"])
	require.Equal(t, "user:kms@corp.example", md["kms_admin_crypto_members"])
	require.Equal(t, "true", md["audit_logging_all_services"])
	require.Equal(t, "", md["audit_logging_gaps"])
}

// Inherited impersonation grants are not the project-level grant CIS 1.7 is
// about; inherited separation-of-duties pairs still count, because the
// principal holds both roles on the project either way.
func TestProjectAsset_ScopeOfGrants(t *testing.T) {
	md := projectMD(t, &fakeIAM{
		ancestors: []string{"organizations/1"},
		policies: map[string][]iamBinding{
			"projects/p": {{Role: roleSAUser, Resource: "projects/p", Members: []string{"user:a@corp.example"}}},
			"organizations/1": {
				{Role: roleSATokenCreator, Resource: "organizations/1", Members: []string{"user:b@corp.example"}},
				{Role: roleSAAdmin, Resource: "organizations/1", Members: []string{"user:a@corp.example"}},
			},
		},
		audit: map[string][]auditConfig{"organizations/1": fullAudit},
	})
	require.Equal(t, "user:a@corp.example=roles/iam.serviceAccountUser", md["sa_impersonation_project_members"])
	require.Equal(t, "user:a@corp.example", md["sa_admin_user_members"])
	require.Equal(t, "true", md["audit_logging_all_services"], "an org-level audit config is inherited")
}

func TestProjectAsset_ObservedNone(t *testing.T) {
	md := projectMD(t, &fakeIAM{policies: map[string][]iamBinding{"projects/p": nil}})
	for _, k := range []string{"consumer_account_members", "sa_impersonation_project_members", "sa_admin_user_members", "kms_admin_crypto_members"} {
		require.Contains(t, md, k)
		require.Equal(t, "", md[k], k)
	}
	require.Equal(t, "false", md["audit_logging_all_services"])
	require.Equal(t, "missing:ADMIN_READ,missing:DATA_READ,missing:DATA_WRITE", md["audit_logging_gaps"])
}

func TestAuditGaps(t *testing.T) {
	require.Empty(t, auditGaps(fullAudit))
	require.Equal(t, []string{"missing:DATA_READ", "missing:DATA_WRITE"},
		auditGaps([]auditConfig{
			{Service: "allServices", Logs: []auditLog{{Type: "ADMIN_READ"}}},
			{Service: "storage.googleapis.com", Logs: []auditLog{{Type: "DATA_READ"}, {Type: "DATA_WRITE"}}},
		}), "a per-service config is not allServices")
	require.Equal(t, []string{"exempted:user:noisy@corp.example"},
		auditGaps([]auditConfig{{Service: "allServices", Logs: []auditLog{
			{Type: "ADMIN_READ"}, {Type: "DATA_READ", Exempted: []string{"user:noisy@corp.example"}}, {Type: "DATA_WRITE"},
		}}}))
}

// The audit configuration is the union over the hierarchy: an unread ancestor
// can both supply a missing log type and add an exemption, so neither answer
// is stamped without every policy.
func TestProjectAsset_AuditUnknownWhenAncestorsUnread(t *testing.T) {
	md := projectMD(t, &fakeIAM{
		ancestryErr: context.DeadlineExceeded,
		policies:    map[string][]iamBinding{"projects/p": nil},
	})
	require.NotContains(t, md, "audit_logging_all_services")
	require.NotContains(t, md, "audit_logging_gaps")
	require.Contains(t, md, "sa_impersonation_project_members", "project-scope facts do not depend on ancestors")
}

// CIS GCP 1.2 compares members with the organization's own domain.
func TestProjectAsset_OutsideDomainMembers(t *testing.T) {
	policies := map[string][]iamBinding{
		"projects/p": {{Role: "roles/viewer", Resource: "projects/p", Members: []string{
			"user:dev@corp.example", "user:eu@emea.corp.example", "user:c@contractor.example",
			"group:eng@googlegroups.com", "domain:partner.example", "user:me@gmail.com",
			"serviceAccount:x@other.iam.gserviceaccount.com",
		}}},
	}
	md := projectMD(t, &fakeIAM{policies: policies, ancestors: []string{"organizations/1"}, orgDomain: "Corp.Example"})
	require.Equal(t, "corp.example", md["organization_domain"])
	require.Equal(t, "domain:partner.example,group:eng@googlegroups.com,user:c@contractor.example", md["non_org_domain_members"],
		"subdomains belong to the org; consumer accounts and service accounts are graded elsewhere")

	md = projectMD(t, &fakeIAM{policies: policies, ancestors: []string{"organizations/1"}, orgDomainErr: errors.New("denied")})
	require.NotContains(t, md, "non_org_domain_members", "an unread organization domain is unknown")
	md = projectMD(t, &fakeIAM{policies: policies})
	require.NotContains(t, md, "non_org_domain_members", "a project outside any organization has no org domain")
}
