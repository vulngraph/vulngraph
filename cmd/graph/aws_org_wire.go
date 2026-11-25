package main

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	collectaws "github.com/vulngraph/vulngraph/internal/collect/aws"
)

// awsOrgDiscoverer adapts the AWS org client to connector.OrgDiscoverer: the
// collect packages stay free of app-domain types, so the mapping lives here.
type awsOrgDiscoverer struct{ org *collectaws.Org }

func newAWSOrgDiscoverer() awsOrgDiscoverer { return awsOrgDiscoverer{org: collectaws.NewOrg()} }

func (d awsOrgDiscoverer) ListAccounts(ctx context.Context, cfg map[string]string, withOUs bool) ([]connector.DiscoveredAccount, error) {
	accts, err := d.org.ListAccounts(ctx, cfg, withOUs)
	if err != nil {
		return nil, fmt.Errorf("awsOrgDiscoverer: %w", err)
	}
	out := make([]connector.DiscoveredAccount, len(accts))
	for i, a := range accts {
		out[i] = connector.DiscoveredAccount{
			ID: a.ID, Name: a.Name, Email: a.Email, State: a.State, OUPath: a.OUPath, OUPathKnown: a.OUPathKnown,
		}
	}
	return out, nil
}

func (d awsOrgDiscoverer) Test(ctx context.Context, cfg map[string]string) connector.OrgTestReport {
	r := d.org.Test(ctx, cfg)
	out := connector.OrgTestReport{
		HubOK: r.HubOK, HubIdentity: r.HubIdentity, HubError: r.HubError,
		ListRan: r.ListRan, ListOK: r.ListOK, AccountCount: r.AccountCount, ListError: r.ListError,
		Members: make([]connector.MemberCheck, len(r.Members)),
	}
	for i, m := range r.Members {
		out.Members[i] = connector.MemberCheck(m)
	}
	return out
}
