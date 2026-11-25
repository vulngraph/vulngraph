package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// fakeIAM serves canned service accounts, bindings, and role permissions, and
// counts RolePermissions calls to verify the union + (impl-side) caching shape.
type fakeIAM struct {
	accounts []gcpServiceAccount
	// bindings is the project policy, kept in the original role→members shape so
	// the existing tests read unchanged; collect() sees it as project-scoped
	// unconditional bindings.
	bindings map[string][]string
	// policies is the richer form, keyed by resource name ("projects/p",
	// "folders/1", "organizations/2"), for tests that exercise inheritance or
	// conditions.
	policies    map[string][]iamBinding
	audit       map[string][]auditConfig // resource → audit configs
	ancestors   []string
	ancestryErr error
	policyErr   map[string]error
	// orgDomain is the organization's primary domain (its displayName).
	orgDomain    string
	orgDomainErr error
	rolePerms    map[string][]string
	roleCalls    int

	keys    map[string][]gcpSAKey // email → USER_MANAGED keys
	keysErr error
	saAuth  map[string]time.Time // SA uniqueID/email → last auth
	keyAuth map[string]time.Time // key ID → last auth
	authErr error                // Policy Analyzer failure (both activity types)
}

func (f *fakeIAM) ServiceAccounts(context.Context, string) ([]gcpServiceAccount, error) {
	return f.accounts, nil
}
func (f *fakeIAM) Policy(_ context.Context, resource string) (iamPolicy, error) {
	if err := f.policyErr[resource]; err != nil {
		return iamPolicy{}, err
	}
	if bs, ok := f.policies[resource]; ok {
		return iamPolicy{Bindings: bs, AuditConfigs: f.audit[resource]}, nil
	}
	if !strings.HasPrefix(resource, "projects/") {
		return iamPolicy{AuditConfigs: f.audit[resource]}, nil
	}
	out := make([]iamBinding, 0, len(f.bindings))
	for role, members := range f.bindings {
		out = append(out, iamBinding{Role: role, Members: members, Resource: resource})
	}
	return iamPolicy{Bindings: out, AuditConfigs: f.audit[resource]}, nil
}

func (f *fakeIAM) Ancestry(context.Context, string) ([]string, error) {
	return f.ancestors, f.ancestryErr
}
func (f *fakeIAM) OrganizationDomain(context.Context, string) (string, error) {
	return f.orgDomain, f.orgDomainErr
}
func (f *fakeIAM) RolePermissions(_ context.Context, role string) ([]string, error) {
	f.roleCalls++
	return f.rolePerms[role], nil
}
func (f *fakeIAM) UserManagedKeys(_ context.Context, email string) ([]gcpSAKey, error) {
	if f.keysErr != nil {
		return nil, f.keysErr
	}
	return f.keys[email], nil
}
func (f *fakeIAM) LastAuthentications(_ context.Context, _ string, activityType string) (map[string]time.Time, error) {
	if f.authErr != nil {
		return nil, f.authErr
	}
	if activityType == activitySALastAuth {
		return f.saAuth, nil
	}
	return f.keyAuth, nil
}

func withFakeIAM(f iamAPI) iamCollector {
	return iamCollector{
		newIAM: func(context.Context, map[string]string) (iamAPI, string, error) {
			return f, "proj-1", nil
		},
		auth: testAuthCache(),
	}
}

func TestCollectIAM_EffectivePermissionsUnion(t *testing.T) {
	fake := &fakeIAM{
		accounts: []gcpServiceAccount{{Email: "sa@proj.iam.gserviceaccount.com"}},
		bindings: map[string][]string{
			"roles/editor":                 {"serviceAccount:sa@proj.iam.gserviceaccount.com"},
			"roles/iam.serviceAccountUser": {"serviceAccount:sa@proj.iam.gserviceaccount.com"},
		},
		rolePerms: map[string][]string{
			"roles/editor":                 {"compute.instances.create"},
			"roles/iam.serviceAccountUser": {"iam.serviceAccounts.actAs"},
		},
	}
	assets, err := withFakeIAM(fake).collect(context.Background(), nil, time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 2, "the service account plus the project anchor")

	sa := assets[0]
	require.Equal(t, "gcp_service_account", sa.Type)
	require.Equal(t, asset.ProviderGCP, sa.Provider)
	require.Equal(t, "serviceAccount:sa@proj.iam.gserviceaccount.com", sa.ID)

	perms := sa.Metadata["permissions"]
	require.Contains(t, perms, "compute.instances.create")
	require.Contains(t, perms, "iam.serviceAccounts.actAs")
	// Sorted union → deterministic.
	require.Equal(t, "compute.instances.create,iam.serviceAccounts.actAs", perms)
	require.Equal(t, 2, len(strings.Split(sa.Metadata["roles"], ",")))
}

func TestCollectIAM_ServiceAccountWithNoBindings(t *testing.T) {
	fake := &fakeIAM{
		accounts: []gcpServiceAccount{{Email: "lonely@proj.iam.gserviceaccount.com"}},
		bindings: map[string][]string{},
	}
	assets, err := withFakeIAM(fake).collect(context.Background(), nil, time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 2, "the service account plus the project anchor")
	require.Empty(t, assets[0].Metadata["permissions"])
}

func TestCollectIAM_NoServiceAccounts(t *testing.T) {
	assets, err := withFakeIAM(&fakeIAM{bindings: map[string][]string{}}).
		collect(context.Background(), nil, time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.Equal(t, "cloud_account", assets[0].Type, "only the project anchor")
}

// --- credential hygiene: USER_MANAGED keys + Policy Analyzer last-auth ---

var credNow = time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

func credSA(email, uniqueID string) gcpServiceAccount {
	return gcpServiceAccount{Email: email, UniqueID: uniqueID}
}

// The full happy path: an active user-managed key that authenticated recently,
// plus SA-level last auth — field-for-field parity with the AWS iam_user shape.
func TestCollectIAM_KeyAndAuthMetadata(t *testing.T) {
	fake := &fakeIAM{
		accounts: []gcpServiceAccount{credSA("sa@p.iam.gserviceaccount.com", "111")},
		bindings: map[string][]string{},
		keys: map[string][]gcpSAKey{
			"sa@p.iam.gserviceaccount.com": {
				{ID: "k1", ValidAfter: credNow.AddDate(0, 0, -120)},                 // 120d old, used
				{ID: "k2", ValidAfter: credNow.AddDate(0, 0, -200), Disabled: true}, // disabled — not counted
			},
		},
		keyAuth: map[string]time.Time{"k1": credNow.AddDate(0, 0, -3)},
		saAuth:  map[string]time.Time{"111": credNow.AddDate(0, 0, -2)},
	}
	assets, err := withFakeIAM(fake).collect(context.Background(), nil, credNow)
	require.NoError(t, err)
	require.Len(t, assets, 2, "the service account plus the project anchor")
	m := assets[0].Metadata
	require.Equal(t, "1", m["key_count"], "disabled keys are not active")
	require.Equal(t, "120", m["key_age_days"])
	require.Equal(t, "3", m["key_last_used_days"])
	require.Equal(t, "false", m["key_stale"], "recently-used key is not stale")
	require.Equal(t, "false", m["key_exposed"])
	require.Equal(t, "2", m["sa_last_auth_days"], "matched via unique ID")
}

// An old active key with no activity in the Policy Analyzer window is stale —
// the leaked-and-never-noticed credential. A YOUNG never-seen key is not (it
// may simply be freshly provisioned), mirroring the AWS collector exactly.
func TestCollectIAM_KeyStaleness(t *testing.T) {
	tests := []struct {
		name      string
		key       gcpSAKey
		keyAuth   map[string]time.Time
		wantStale string
	}{
		{"old key never seen in window", gcpSAKey{ID: "k", ValidAfter: credNow.AddDate(0, 0, -180)}, map[string]time.Time{}, "true"},
		{"young key never seen", gcpSAKey{ID: "k", ValidAfter: credNow.AddDate(0, 0, -10)}, map[string]time.Time{}, "false"},
		{"old key recently used", gcpSAKey{ID: "k", ValidAfter: credNow.AddDate(0, 0, -180)}, map[string]time.Time{"k": credNow.AddDate(0, 0, -1)}, "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeIAM{
				accounts: []gcpServiceAccount{credSA("sa@p.iam.gserviceaccount.com", "111")},
				bindings: map[string][]string{},
				keys:     map[string][]gcpSAKey{"sa@p.iam.gserviceaccount.com": {tt.key}},
				keyAuth:  tt.keyAuth,
			}
			assets, err := withFakeIAM(fake).collect(context.Background(), nil, credNow)
			require.NoError(t, err)
			require.Equal(t, tt.wantStale, assets[0].Metadata["key_stale"])
		})
	}
}

// A Google-flagged exposed/compromised key surfaces even when disabled —
// disabling contains it, but the key must be deleted and rotated.
func TestCollectIAM_ExposedKeyFlagged(t *testing.T) {
	fake := &fakeIAM{
		accounts: []gcpServiceAccount{credSA("sa@p.iam.gserviceaccount.com", "111")},
		bindings: map[string][]string{},
		keys: map[string][]gcpSAKey{
			"sa@p.iam.gserviceaccount.com": {{ID: "k", ValidAfter: credNow.AddDate(0, 0, -5), Disabled: true, Exposed: true}},
		},
	}
	assets, err := withFakeIAM(fake).collect(context.Background(), nil, credNow)
	require.NoError(t, err)
	require.Equal(t, "true", assets[0].Metadata["key_exposed"])
	require.Equal(t, "0", assets[0].Metadata["key_count"])
}

// Fail-unknown: when Policy Analyzer is unavailable, usage metadata is OMITTED
// (not defaulted), so the unused-credential checks stay silent — a lookup
// error must never fire a High false positive. Key inventory (count/age)
// stays present: it comes from Keys.List, not the analyzer.
func TestCollectIAM_AuthLookupFailure_OmitsUsageMetadata(t *testing.T) {
	fake := &fakeIAM{
		accounts: []gcpServiceAccount{credSA("sa@p.iam.gserviceaccount.com", "111")},
		bindings: map[string][]string{},
		keys: map[string][]gcpSAKey{
			"sa@p.iam.gserviceaccount.com": {{ID: "k", ValidAfter: credNow.AddDate(0, 0, -180)}},
		},
		authErr: errors.New("policyanalyzer API not enabled"),
	}
	assets, err := withFakeIAM(fake).collect(context.Background(), nil, credNow)
	require.NoError(t, err, "analyzer failure must not fail IAM collection")
	m := assets[0].Metadata
	require.NotContains(t, m, "key_stale")
	require.NotContains(t, m, "key_last_used_days")
	require.NotContains(t, m, "sa_last_auth_days")
	require.Equal(t, "1", m["key_count"])
	require.Equal(t, "180", m["key_age_days"])
}

// A keys.list failure skips key metadata for that SA but keeps the SA asset
// (and its CIEM permissions) — key hygiene degrades, identity coverage doesn't.
func TestCollectIAM_KeysLookupFailure_KeepsSA(t *testing.T) {
	fake := &fakeIAM{
		accounts: []gcpServiceAccount{credSA("sa@p.iam.gserviceaccount.com", "111")},
		bindings: map[string][]string{},
		keysErr:  errors.New("permission denied"),
		saAuth:   map[string]time.Time{"111": credNow.AddDate(0, 0, -400)},
	}
	assets, err := withFakeIAM(fake).collect(context.Background(), nil, credNow)
	require.NoError(t, err)
	require.Len(t, assets, 2, "the service account plus the project anchor")
	m := assets[0].Metadata
	require.NotContains(t, m, "key_count")
	require.Equal(t, "400", m["sa_last_auth_days"], "SA-level auth is independent of key listing")
}

// No activity record for the SA within the window → -1 (dormant signal for
// the gcp-sa-unused check).
func TestCollectIAM_SANeverAuthenticated(t *testing.T) {
	fake := &fakeIAM{
		accounts: []gcpServiceAccount{credSA("sa@p.iam.gserviceaccount.com", "111")},
		bindings: map[string][]string{},
		saAuth:   map[string]time.Time{},
	}
	assets, err := withFakeIAM(fake).collect(context.Background(), nil, credNow)
	require.NoError(t, err)
	require.Equal(t, "-1", assets[0].Metadata["sa_last_auth_days"])
}

// TestCollectIAM_CarriesUsageMetadataThroughAnAnalyzerOutage is the fix for the
// oscillation: Policy Analyzer is quota-limited to 10 requests/minute for the
// whole estate, and a failed lookup used to strip sa_last_auth_days from EVERY
// service account in the project for that sweep — SAs flipping between having
// and lacking the key, inflating asset_change_log's write volume. A failed
// refresh must serve the last good
// read, stamped with its age so a consumer can tell carried from fresh.
func TestCollectIAM_CarriesUsageMetadataThroughAnAnalyzerOutage(t *testing.T) {
	fake := &fakeIAM{
		accounts: []gcpServiceAccount{credSA("sa@p.iam.gserviceaccount.com", "111")},
		bindings: map[string][]string{},
		keys: map[string][]gcpSAKey{
			"sa@p.iam.gserviceaccount.com": {{ID: "k", ValidAfter: credNow.AddDate(0, 0, -180)}},
		},
		saAuth:  map[string]time.Time{"111": credNow.AddDate(0, 0, -2)},
		keyAuth: map[string]time.Time{"k": credNow.AddDate(0, 0, -5)},
	}
	cache, advance := testAuthCacheWithClock()
	c := iamCollector{
		newIAM: func(context.Context, map[string]string) (iamAPI, string, error) { return fake, "proj-1", nil },
		auth:   cache,
	}

	assets, err := c.collect(context.Background(), nil, credNow)
	require.NoError(t, err)
	require.Equal(t, "2", assets[0].Metadata["sa_last_auth_days"])
	require.Equal(t, "0", assets[0].Metadata["sa_last_auth_observed_days"], "a fresh read is age 0")
	require.Equal(t, "5", assets[0].Metadata["key_last_used_days"])
	require.Equal(t, "0", assets[0].Metadata["key_last_used_observed_days"])

	// The analyzer starts failing and the refresh window opens.
	fake.authErr = errors.New("Quota exceeded for quota metric 'QueryActivities'")
	advance(authRefreshInterval + 25*time.Hour)

	assets, err = c.collect(context.Background(), nil, credNow)
	require.NoError(t, err)
	require.Equal(t, "2", assets[0].Metadata["sa_last_auth_days"], "a failed refresh must not erase the observation")
	require.Equal(t, "1", assets[0].Metadata["sa_last_auth_observed_days"], "…but it must say the read is a day old")
	require.Equal(t, "5", assets[0].Metadata["key_last_used_days"])
	require.Equal(t, "1", assets[0].Metadata["key_last_used_observed_days"])

	// Past the staleness ceiling the carried value is dropped, not silently aged.
	advance(authMaxAge)
	assets, err = c.collect(context.Background(), nil, credNow)
	require.NoError(t, err)
	require.NotContains(t, assets[0].Metadata, "sa_last_auth_days")
	require.NotContains(t, assets[0].Metadata, "sa_last_auth_observed_days")
	require.NotContains(t, assets[0].Metadata, "key_last_used_days")
	require.NotContains(t, assets[0].Metadata, "key_stale")
}
