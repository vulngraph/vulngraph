package connector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Org-account storage for fakeRepo, mirroring the real join: a row's Child is
// read from the child connector's current row.

func (f *fakeRepo) SetEnabled(_ context.Context, id string, enabled bool) error {
	sc, ok := f.rows[id]
	if !ok {
		return ErrNotFound
	}
	sc.Enabled = enabled
	f.rows[id] = sc
	return nil
}

func (f *fakeRepo) DeleteOrg(ctx context.Context, id string) error {
	for _, a := range f.orgAccounts[id] {
		if a.ChildConnectorID != "" {
			_ = f.SetEnabled(ctx, a.ChildConnectorID, false)
		}
	}
	delete(f.orgAccounts, id)
	return f.Delete(ctx, id)
}

func (f *fakeRepo) ListOrgAccounts(_ context.Context, orgID string) ([]OrgAccount, error) {
	var out []OrgAccount
	for _, a := range f.orgAccounts[orgID] {
		if sc, ok := f.rows[a.ChildConnectorID]; ok {
			a.Child = &ChildHealth{Enabled: sc.Enabled, SyncStatus: sc.SyncStatus, CreatedAt: sc.CreatedAt}
		}
		out = append(out, a)
	}
	return out, nil
}

func (f *fakeRepo) UpsertOrgAccount(_ context.Context, a OrgAccount, _ time.Time) error {
	if f.orgAccounts == nil {
		f.orgAccounts = map[string]map[string]OrgAccount{}
	}
	if f.orgAccounts[a.OrgConnectorID] == nil {
		f.orgAccounts[a.OrgConnectorID] = map[string]OrgAccount{}
	}
	a.Child = nil
	f.orgAccounts[a.OrgConnectorID][a.AccountID] = a
	return nil
}

// fakeDiscoverer serves a scripted organization listing.
type fakeDiscoverer struct {
	accounts []DiscoveredAccount
	err      error
	withOUs  bool
}

func (d *fakeDiscoverer) ListAccounts(_ context.Context, _ map[string]string, withOUs bool) ([]DiscoveredAccount, error) {
	d.withOUs = withOUs
	return d.accounts, d.err
}

func (d *fakeDiscoverer) Test(context.Context, map[string]string) OrgTestReport {
	return OrgTestReport{HubOK: true, ListRan: true, ListOK: true, AccountCount: len(d.accounts)}
}

const (
	testMgmtRole = "arn:aws:iam::111111111111:role/GraphOrgDiscovery"
	testHubRole  = "arn:aws:iam::333333333333:role/GraphHub"
)

func orgConfig(extra map[string]string) map[string]string {
	cfg := map[string]string{
		OrgKeyManagementRoleARN: testMgmtRole,
		OrgKeyExternalID:        "graph-ext-0123456789abcdef",
		OrgKeyRegion:            "eu-west-1",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

func newOrgFixture(t *testing.T, extra map[string]string) (*Service, *fakeRepo, *fakeDiscoverer, Connector) {
	t.Helper()
	svc, repo := newTestService(t)
	disc := &fakeDiscoverer{}
	svc.WithOrgDiscoverer(disc)
	org, err := svc.Create(context.Background(), TypeAWSOrg, "acme", orgConfig(extra), "")
	require.NoError(t, err)
	return svc, repo, disc, org
}

func active(id string) DiscoveredAccount {
	return DiscoveredAccount{ID: id, Name: "acct-" + id, State: "ACTIVE"}
}

func accountRow(t *testing.T, repo *fakeRepo, orgID, acct string) OrgAccount {
	t.Helper()
	rows, err := repo.ListOrgAccounts(context.Background(), orgID)
	require.NoError(t, err)
	for _, r := range rows {
		if r.AccountID == acct {
			return r
		}
	}
	t.Fatalf("no row for account %s", acct)
	return OrgAccount{}
}

func TestReconcileOrg_CreatesAChildPerActiveAccount(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, nil)
	disc.accounts = []DiscoveredAccount{active("222222222222"), active("333333333333"),
		{ID: "444444444444", State: "SUSPENDED"}, {ID: "555555555555", State: "PENDING_ACTIVATION"}}

	res, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.Len(t, res.Created, 2)

	row := accountRow(t, repo, org.ID, "222222222222")
	require.Equal(t, OrgAccountActive, row.Status)
	require.True(t, row.Child.Enabled)
	child, err := svc.getStored(context.Background(), row.ChildConnectorID)
	require.NoError(t, err)
	require.Equal(t, TypeAWS, child.Type)
	require.Equal(t, "acme-222222222222", child.Name)
	require.Equal(t, map[string]string{
		ChildKeyOrgConnectorID: org.ID,
		"role_arn":             "arn:aws:iam::222222222222:role/GraphReadOnly",
		"region":               "eu-west-1",
		"aws_account_id":       "222222222222",
	}, child.Config)

	require.Equal(t, OrgAccountSuspended, accountRow(t, repo, org.ID, "444444444444").Status)
	require.Empty(t, accountRow(t, repo, org.ID, "444444444444").ChildConnectorID, "no child for a suspended account")
	require.Empty(t, accountRow(t, repo, org.ID, "555555555555").ChildConnectorID, "no child until activation")

	stored, err := svc.Get(context.Background(), org.ID)
	require.NoError(t, err)
	require.Equal(t, SyncOK, stored.SyncStatus, "discovery records its outcome on the org connector")
}

// The no-copied-keys rule: with a stored hub key, the child's STORED config
// holds neither the key nor the ExternalId; Get supplies both in memory.
func TestReconcileOrg_ChildrenNeverStoreCopiedKeys(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, map[string]string{
		OrgKeyHubAuth: HubAuthAccessKey, "aws_access_key_id": "AKIAHUB", "aws_secret_access_key": "hub-secret",
		OrgKeyHubRoleARN:      testHubRole,
		OrgKeyExecuteRoleName: "GraphExecute",
	})
	disc.accounts = []DiscoveredAccount{active("222222222222")}
	_, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)

	childID := accountRow(t, repo, org.ID, "222222222222").ChildConnectorID
	stored, err := svc.getStored(context.Background(), childID)
	require.NoError(t, err)
	for _, k := range childSecretKeys {
		require.NotContains(t, stored.Config, k, "child must not store %s", k)
	}
	require.NotContains(t, string(repo.rows[childID].ConfigCiphertext), "AKIAHUB")

	resolved, err := svc.Get(context.Background(), childID)
	require.NoError(t, err)
	require.Equal(t, "AKIAHUB", resolved.Config["aws_access_key_id"])
	require.Equal(t, "hub-secret", resolved.Config["aws_secret_access_key"])
	require.Equal(t, testHubRole, resolved.Config[OrgKeyHubRoleARN], "the child assumes the hub role first, like discovery")
	require.Equal(t, "graph-ext-0123456789abcdef", resolved.Config["external_id"])
	require.Equal(t, "arn:aws:iam::222222222222:role/GraphExecute", resolved.Config["execute_role_arn"])
	require.Equal(t, "graph-ext-0123456789abcdef", resolved.Config["execute_external_id"])
}

// Ambient hub: the resolved child has a role and an ExternalId and no key, so
// the collector assumes the member role from graph's own identity.
func TestGet_AmbientOrgChildCarriesNoKey(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, nil)
	disc.accounts = []DiscoveredAccount{active("222222222222")}
	_, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)

	resolved, err := svc.Get(context.Background(), accountRow(t, repo, org.ID, "222222222222").ChildConnectorID)
	require.NoError(t, err)
	require.NotContains(t, resolved.Config, "aws_access_key_id")
	require.NotContains(t, resolved.Config, OrgKeyHubRoleARN)
	require.Equal(t, "graph-ext-0123456789abcdef", resolved.Config["external_id"])
}

func TestGet_OrgChildWithMissingOrgFails(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, nil)
	disc.accounts = []DiscoveredAccount{active("222222222222")}
	_, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	childID := accountRow(t, repo, org.ID, "222222222222").ChildConnectorID
	delete(repo.rows, org.ID) // the org row is gone, the child is not

	_, err = svc.Get(context.Background(), childID)
	require.ErrorIs(t, err, ErrOrgParentMissing, "a child must never fall back to the pod's ambient identity")
}

// A child whose org link points at a plain aws connector cannot borrow that
// connector's keys.
func TestGet_OrgChildPointingAtNonOrgFails(t *testing.T) {
	svc, repo := newTestService(t)
	other, err := svc.Create(context.Background(), TypeAWS, "keys", map[string]string{
		"region": "eu-west-1", "aws_access_key_id": "AKIA", "aws_secret_access_key": "s",
	}, "")
	require.NoError(t, err)
	stored, err := repo.Create(context.Background(), Connector{Type: TypeAWS, Name: "child", Enabled: true},
		func(id string) ([]byte, error) {
			return svc.encryptConfig(id, map[string]string{ChildKeyOrgConnectorID: other.ID, "role_arn": "arn:aws:iam::2:role/x", "region": "eu-west-1"})
		})
	require.NoError(t, err)

	_, err = svc.Get(context.Background(), stored.ID)
	require.ErrorIs(t, err, ErrOrgParentMissing)
}

func TestReconcileOrg_LifecycleDisablesAndReenables(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, nil)
	ctx := context.Background()
	disc.accounts = []DiscoveredAccount{active("222222222222"), active("333333333333")}
	_, err := svc.ReconcileOrg(ctx, org.ID)
	require.NoError(t, err)
	childID := accountRow(t, repo, org.ID, "222222222222").ChildConnectorID

	disc.accounts = []DiscoveredAccount{{ID: "222222222222", State: "SUSPENDED"}, active("333333333333")}
	res, err := svc.ReconcileOrg(ctx, org.ID)
	require.NoError(t, err)
	require.Equal(t, 1, res.Disabled)
	row := accountRow(t, repo, org.ID, "222222222222")
	require.Equal(t, OrgAccountSuspended, row.Status)
	require.Equal(t, childID, row.ChildConnectorID, "the child is kept")
	require.False(t, repo.rows[childID].Enabled)

	disc.accounts = []DiscoveredAccount{active("333333333333")}
	_, err = svc.ReconcileOrg(ctx, org.ID)
	require.NoError(t, err)
	require.Equal(t, OrgAccountRemoved, accountRow(t, repo, org.ID, "222222222222").Status)
	require.Contains(t, repo.rows, childID, "a removed account's child is never deleted")

	disc.accounts = []DiscoveredAccount{active("222222222222"), active("333333333333")}
	res, err = svc.ReconcileOrg(ctx, org.ID)
	require.NoError(t, err)
	require.Equal(t, 1, res.Enabled)
	require.Empty(t, res.Created, "the existing child is re-enabled, not duplicated")
	require.True(t, repo.rows[childID].Enabled)
	require.Equal(t, OrgAccountActive, accountRow(t, repo, org.ID, "222222222222").Status)
}

// Degraded input: a failed or empty listing must not disable any child — it
// is "could not list", not "every account left".
func TestReconcileOrg_DiscoveryFailureKeepsChildren(t *testing.T) {
	for _, tc := range []struct {
		name     string
		accounts []DiscoveredAccount
		err      error
		want     error
	}{
		{"listing error", nil, errors.New("AccessDenied: organizations:ListAccounts"), nil},
		{"empty listing", []DiscoveredAccount{}, nil, ErrEmptyDiscovery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, disc, org := newOrgFixture(t, nil)
			ctx := context.Background()
			disc.accounts = []DiscoveredAccount{active("222222222222")}
			_, err := svc.ReconcileOrg(ctx, org.ID)
			require.NoError(t, err)
			childID := accountRow(t, repo, org.ID, "222222222222").ChildConnectorID

			disc.accounts, disc.err = tc.accounts, tc.err
			_, err = svc.ReconcileOrg(ctx, org.ID)
			require.Error(t, err)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			}
			require.True(t, repo.rows[childID].Enabled, "discovery failure must not disable children")
			require.Equal(t, OrgAccountActive, accountRow(t, repo, org.ID, "222222222222").Status)
			require.Equal(t, SyncError, repo.rows[org.ID].SyncStatus, "the failure is visible on the org connector")
		})
	}
}

func TestReconcileOrg_FiltersExcludeAndDisable(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, map[string]string{OrgKeyExcludeAccounts: "333333333333"})
	disc.accounts = []DiscoveredAccount{active("222222222222"), active("333333333333")}
	res, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.Len(t, res.Created, 1)
	require.Equal(t, OrgAccountExcluded, accountRow(t, repo, org.ID, "333333333333").Status)
	require.False(t, disc.withOUs, "no OU walk without an OU filter")
}

func TestReconcileOrg_OUFilterAsksForOUPaths(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, map[string]string{OrgKeyIncludeOUs: "ou-ab12-11111111"})
	disc.accounts = []DiscoveredAccount{
		{ID: "222222222222", State: "ACTIVE", OUPath: []string{"r-ab12", "ou-ab12-11111111"}, OUPathKnown: true},
		{ID: "333333333333", State: "ACTIVE", OUPath: []string{"r-ab12"}, OUPathKnown: true},
		{ID: "444444444444", State: "ACTIVE"},
	}
	res, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.True(t, disc.withOUs)
	require.Len(t, res.Created, 1)
	require.Equal(t, "r-ab12/ou-ab12-11111111", accountRow(t, repo, org.ID, "222222222222").OUPath)
	require.Equal(t, OrgAccountExcluded, accountRow(t, repo, org.ID, "333333333333").Status)
	require.Equal(t, OrgAccountUnknown, accountRow(t, repo, org.ID, "444444444444").Status)
}

// An account another aws connector already collects gets no second child.
func TestReconcileOrg_ExistingConnectorIsAConflict(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, nil)
	manual, err := svc.Create(context.Background(), TypeAWS, "aws-222222222222", map[string]string{
		"region": "eu-west-1", "role_arn": "arn:aws:iam::222222222222:role/GraphReadOnly",
	}, "")
	require.NoError(t, err)
	disc.accounts = []DiscoveredAccount{active("222222222222")}

	res, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.Empty(t, res.Created)
	row := accountRow(t, repo, org.ID, "222222222222")
	require.Equal(t, OrgAccountConflict, row.Status)
	require.Contains(t, row.StatusDetail, manual.ID)
}

// One account's failure is that account's status, not the pass's.
func TestReconcileOrg_ChildNameClashIsAnAccountError(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, nil)
	_, err := svc.Create(context.Background(), TypeAWS, "acme-333333333333", map[string]string{
		"region": "eu-west-1", "role_arn": "arn:aws:iam::999999999999:role/x",
	}, "")
	require.NoError(t, err)
	disc.accounts = []DiscoveredAccount{active("222222222222"), active("333333333333")}

	res, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.Len(t, res.Created, 1)
	require.Equal(t, 1, res.Errors)
	require.Equal(t, OrgAccountError, accountRow(t, repo, org.ID, "333333333333").Status)
	require.Equal(t, SyncError, repo.rows[org.ID].SyncStatus)
}

func TestPlanAccount(t *testing.T) {
	none := orgFilters{}
	for _, tc := range []struct {
		state  string
		status OrgAccountStatus
		action childAction
	}{
		{"ACTIVE", OrgAccountActive, childEnsure},
		{"PENDING_ACTIVATION", OrgAccountPending, childKeep},
		{"SUSPENDED", OrgAccountSuspended, childDisable},
		{"PENDING_CLOSURE", OrgAccountClosed, childDisable},
		{"CLOSED", OrgAccountClosed, childDisable},
		{"", OrgAccountUnknown, childKeep},
		{"SOMETHING_NEW", OrgAccountUnknown, childKeep},
	} {
		t.Run(tc.state, func(t *testing.T) {
			status, _, action := planAccount(none, &DiscoveredAccount{ID: "222222222222", State: tc.state})
			require.Equal(t, tc.status, status)
			require.Equal(t, tc.action, action)
		})
	}
	status, _, action := planAccount(none, nil)
	require.Equal(t, OrgAccountRemoved, status)
	require.Equal(t, childDisable, action)
}

func TestOrgFiltersInScope(t *testing.T) {
	placed := func(id string, path ...string) DiscoveredAccount {
		return DiscoveredAccount{ID: id, OUPath: path, OUPathKnown: true}
	}
	unplaced := DiscoveredAccount{ID: "222222222222"}
	for _, tc := range []struct {
		name      string
		cfg       map[string]string
		acct      DiscoveredAccount
		in, known bool
	}{
		{"no filters", nil, unplaced, true, true},
		{"excluded account", map[string]string{OrgKeyExcludeAccounts: "222222222222"}, unplaced, false, true},
		{"included account", map[string]string{OrgKeyIncludeAccounts: "222222222222"}, unplaced, true, true},
		{"not in include list", map[string]string{OrgKeyIncludeAccounts: "333333333333"}, unplaced, false, true},
		{"exclude beats include", map[string]string{OrgKeyIncludeAccounts: "222222222222", OrgKeyExcludeAccounts: "222222222222"}, unplaced, false, true},
		{"in included OU (nested)", map[string]string{OrgKeyIncludeOUs: "ou-a1b2-11111111"}, placed("222222222222", "r-a1b2", "ou-a1b2-11111111", "ou-a1b2-22222222"), true, true},
		{"outside included OU", map[string]string{OrgKeyIncludeOUs: "ou-a1b2-11111111"}, placed("222222222222", "r-a1b2"), false, true},
		{"in excluded OU", map[string]string{OrgKeyExcludeOUs: "ou-a1b2-11111111"}, placed("222222222222", "r-a1b2", "ou-a1b2-11111111"), false, true},
		{"excluded OU beats included account", map[string]string{OrgKeyIncludeAccounts: "222222222222", OrgKeyExcludeOUs: "ou-a1b2-11111111"}, placed("222222222222", "ou-a1b2-11111111"), false, true},
		{"OU filter, path unknown", map[string]string{OrgKeyIncludeOUs: "ou-a1b2-11111111"}, unplaced, false, false},
		{"OU exclude, path unknown", map[string]string{OrgKeyExcludeOUs: "ou-a1b2-11111111"}, unplaced, false, false},
		{"included account, OU include, path unknown", map[string]string{OrgKeyIncludeAccounts: "222222222222", OrgKeyIncludeOUs: "ou-a1b2-11111111"}, unplaced, true, true},
		{"included account, OU exclude, path unknown", map[string]string{OrgKeyIncludeAccounts: "222222222222", OrgKeyExcludeOUs: "ou-a1b2-11111111"}, unplaced, false, false},
		{"root as include", map[string]string{OrgKeyIncludeOUs: "r-a1b2"}, placed("222222222222", "r-a1b2"), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, known := parseOrgFilters(tc.cfg).inScope(tc.acct)
			require.Equal(t, tc.known, known)
			if known {
				require.Equal(t, tc.in, in)
			}
		})
	}
}

func TestCreate_OrgValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra map[string]string
		ok    bool
	}{
		{"defaults", nil, true},
		{"access key", map[string]string{OrgKeyHubAuth: HubAuthAccessKey, "aws_access_key_id": "AKIA", "aws_secret_access_key": "s", OrgKeyHubRoleARN: testHubRole}, true},
		{"access key without hub role", map[string]string{OrgKeyHubAuth: HubAuthAccessKey, "aws_access_key_id": "AKIA", "aws_secret_access_key": "s"}, false},
		{"access key with malformed hub role", map[string]string{OrgKeyHubAuth: HubAuthAccessKey, "aws_access_key_id": "AKIA", "aws_secret_access_key": "s", OrgKeyHubRoleARN: "GraphHub"}, false},
		{"ambient principal hub role", map[string]string{OrgKeyHubRoleARN: testHubRole}, true},
		{"malformed hub role", map[string]string{OrgKeyHubRoleARN: "arn:aws:iam::333333333333:user/hub"}, false},
		{"access key missing secret", map[string]string{OrgKeyHubAuth: HubAuthAccessKey, "aws_access_key_id": "AKIA"}, false},
		{"keys with ambient", map[string]string{"aws_access_key_id": "AKIA", "aws_secret_access_key": "s"}, false},
		{"bad hub_auth", map[string]string{OrgKeyHubAuth: "sso"}, false},
		{"bad role arn", map[string]string{OrgKeyManagementRoleARN: "GraphOrgDiscovery"}, false},
		{"govcloud role arn", map[string]string{OrgKeyManagementRoleARN: "arn:aws-us-gov:iam::111111111111:role/GraphOrgDiscovery"}, true},
		{"short external id", map[string]string{OrgKeyExternalID: "x"}, false},
		{"external id with space", map[string]string{OrgKeyExternalID: "has space"}, false},
		{"long external id", map[string]string{OrgKeyExternalID: strings.Repeat("a", 1225)}, false},
		{"bad member role", map[string]string{OrgKeyMemberRoleName: "bad name"}, false},
		{"execute role equals member role", map[string]string{OrgKeyExecuteRoleName: "GraphReadOnly"}, false},
		{"bad account filter", map[string]string{OrgKeyIncludeAccounts: "1234"}, false},
		{"bad OU filter", map[string]string{OrgKeyExcludeOUs: "Prod"}, false},
		{"good filters", map[string]string{OrgKeyIncludeAccounts: "222222222222, 333333333333", OrgKeyIncludeOUs: "ou-ab12-12345678,r-ab12"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestService(t)
			_, err := svc.Create(context.Background(), TypeAWSOrg, "org", orgConfig(tc.extra), "")
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestCreate_OrgRequiresManagementRoleAndExternalID(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.Create(context.Background(), TypeAWSOrg, "org", map[string]string{OrgKeyManagementRoleARN: testMgmtRole}, "")
	require.ErrorIs(t, err, ErrMissingConfig)
}

// Children are made by discovery; the API cannot mint one by hand.
func TestCreate_RejectsHandMadeOrgChild(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.Create(context.Background(), TypeAWS, "child", map[string]string{
		"region": "eu-west-1", "role_arn": "arn:aws:iam::2:role/x", ChildKeyOrgConnectorID: "org",
	}, "")
	require.ErrorIs(t, err, ErrManagedChild)
}

func TestCheckChildConfig_RejectsEverySecretKey(t *testing.T) {
	for _, k := range childSecretKeys {
		require.ErrorIs(t, checkChildConfig(map[string]string{"role_arn": "r", k: "v"}), ErrChildStoresSecret, k)
	}
	require.NoError(t, checkChildConfig(childConfig(Connector{ID: "o", Config: orgConfig(map[string]string{
		OrgKeyHubAuth: HubAuthAccessKey, "aws_access_key_id": "AKIA", "aws_secret_access_key": "s", OrgKeyHubRoleARN: testHubRole, OrgKeyExecuteRoleName: "GraphExecute",
	})}, "222222222222")))
}

func TestDelete_OrgDisablesChildrenKeepsThem(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, nil)
	disc.accounts = []DiscoveredAccount{active("222222222222")}
	_, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	childID := accountRow(t, repo, org.ID, "222222222222").ChildConnectorID

	require.NoError(t, svc.Delete(context.Background(), org.ID))
	require.NotContains(t, repo.rows, org.ID)
	require.Contains(t, repo.rows, childID)
	require.False(t, repo.rows[childID].Enabled)
}

func TestReconcileAllOrgs_OneFailureDoesNotStopTheOthers(t *testing.T) {
	svc, repo := newTestService(t)
	disc := &fakeDiscoverer{accounts: []DiscoveredAccount{active("222222222222")}}
	svc.WithOrgDiscoverer(disc)
	ctx := context.Background()
	a, err := svc.Create(ctx, TypeAWSOrg, "a", orgConfig(nil), "")
	require.NoError(t, err)
	b, err := svc.Create(ctx, TypeAWSOrg, "b", orgConfig(map[string]string{OrgKeyExcludeAccounts: "222222222222"}), "")
	require.NoError(t, err)

	created, err := svc.ReconcileAllOrgs(ctx)
	require.NoError(t, err)
	require.Len(t, created, 1)
	require.Equal(t, OrgAccountActive, accountRow(t, repo, a.ID, "222222222222").Status)
	require.Equal(t, OrgAccountExcluded, accountRow(t, repo, b.ID, "222222222222").Status)
}

// Re-creating an org connector: the old org's disabled children are adopted
// (same connector, same data, now pointing at the new org), not reported as
// conflicts.
func TestReconcileOrg_AdoptsOrphanedChildren(t *testing.T) {
	svc, repo, disc, old := newOrgFixture(t, nil)
	ctx := context.Background()
	disc.accounts = []DiscoveredAccount{active("222222222222")}
	_, err := svc.ReconcileOrg(ctx, old.ID)
	require.NoError(t, err)
	childID := accountRow(t, repo, old.ID, "222222222222").ChildConnectorID
	require.NoError(t, svc.Delete(ctx, old.ID))
	require.False(t, repo.rows[childID].Enabled)

	org, err := svc.Create(ctx, TypeAWSOrg, "acme-v2", orgConfig(nil), "")
	require.NoError(t, err)
	res, err := svc.ReconcileOrg(ctx, org.ID)
	require.NoError(t, err)
	require.Empty(t, res.Created)
	require.Equal(t, 1, res.Adopted)

	row := accountRow(t, repo, org.ID, "222222222222")
	require.Equal(t, OrgAccountActive, row.Status)
	require.Equal(t, childID, row.ChildConnectorID)
	require.True(t, repo.rows[childID].Enabled)
	stored, err := svc.getStored(ctx, childID)
	require.NoError(t, err)
	require.Equal(t, org.ID, stored.Config[ChildKeyOrgConnectorID])
	_, err = svc.Get(ctx, childID)
	require.NoError(t, err, "the adopted child resolves through its new org")
}

// A child of another LIVE org is that org's; it is a conflict, never adopted.
func TestReconcileOrg_LiveOrgsChildIsNotAdopted(t *testing.T) {
	svc, repo, disc, a := newOrgFixture(t, nil)
	ctx := context.Background()
	disc.accounts = []DiscoveredAccount{active("222222222222")}
	_, err := svc.ReconcileOrg(ctx, a.ID)
	require.NoError(t, err)
	aChild := accountRow(t, repo, a.ID, "222222222222").ChildConnectorID

	b, err := svc.Create(ctx, TypeAWSOrg, "other", orgConfig(nil), "")
	require.NoError(t, err)
	res, err := svc.ReconcileOrg(ctx, b.ID)
	require.NoError(t, err)
	require.Zero(t, res.Adopted)
	require.Equal(t, OrgAccountConflict, accountRow(t, repo, b.ID, "222222222222").Status)
	stored, err := svc.getStored(ctx, aChild)
	require.NoError(t, err)
	require.Equal(t, a.ID, stored.Config[ChildKeyOrgConnectorID])
}

// A failure reading the existing connectors is shown on the org connector,
// and changes no child.
func TestReconcileOrg_OwnerLookupFailureIsRecorded(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, nil)
	disc.accounts = []DiscoveredAccount{active("222222222222")}
	repo.rows["broken"] = storedConnector{Connector: Connector{ID: "broken", Type: TypeAWS, Name: "broken"}, ConfigCiphertext: []byte("not a ciphertext")}

	_, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.Error(t, err)
	require.Equal(t, SyncError, repo.rows[org.ID].SyncStatus)
	require.Empty(t, repo.orgAccounts[org.ID])
}

func TestReconcileOrg_NotAnOrg(t *testing.T) {
	svc, _ := newTestService(t)
	svc.WithOrgDiscoverer(&fakeDiscoverer{})
	c, err := svc.Create(context.Background(), TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)
	_, err = svc.ReconcileOrg(context.Background(), c.ID)
	require.ErrorIs(t, err, ErrNotOrgConnector)
	_, err = svc.OrgAccounts(context.Background(), c.ID)
	require.ErrorIs(t, err, ErrNotOrgConnector)
}

func TestTestOrg_RequiresDiscoverer(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.TestOrg(context.Background(), "x")
	require.ErrorIs(t, err, ErrNoOrgDiscoverer)
}

func (f *fakeRepo) UpsertOrgAccounts(ctx context.Context, rows []OrgAccount, at time.Time) error {
	f.orgBatchCalls++
	if f.orgBatchErr != nil {
		return f.orgBatchErr
	}
	for _, row := range rows {
		if err := f.UpsertOrgAccount(ctx, row, at); err != nil {
			return err
		}
	}
	return nil
}
