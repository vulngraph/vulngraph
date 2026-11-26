package connector

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// UpsertOrgAccounts records a bounded batch from one organization's discovery.
// Parallel arrays are constructed together so PostgreSQL cannot pad missing rows.
func (r *PGRepo) UpsertOrgAccounts(ctx context.Context, accounts []OrgAccount, at time.Time) error {
	if len(accounts) == 0 {
		return nil
	}
	if len(accounts) > 500 {
		return fmt.Errorf("UpsertOrgAccounts: batch exceeds 500 accounts")
	}
	p := sqlcgen.UpsertAWSOrgAccountsParams{OrgConnectorID: accounts[0].OrgConnectorID, SeenAt: at}
	for _, a := range accounts {
		if a.OrgConnectorID != p.OrgConnectorID {
			return fmt.Errorf("UpsertOrgAccounts: mixed organizations")
		}
		p.AccountIds = append(p.AccountIds, a.AccountID)
		p.Names = append(p.Names, a.Name)
		p.Emails = append(p.Emails, a.Email)
		p.AwsStates = append(p.AwsStates, a.AWSState)
		p.OuPaths = append(p.OuPaths, a.OUPath)
		p.Statuses = append(p.Statuses, string(a.Status))
		p.StatusDetails = append(p.StatusDetails, a.StatusDetail)
		p.ChildIds = append(p.ChildIds, a.ChildConnectorID)
		p.LastSeenAts = append(p.LastSeenAts, a.LastSeenAt)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := r.q.UpsertAWSOrgAccounts(ctx, p); err != nil {
		return fmt.Errorf("UpsertOrgAccounts: %w", err)
	}
	return nil
}
