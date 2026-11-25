package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appengine "google.golang.org/api/appengine/v1"
	artifactregistry "google.golang.org/api/artifactregistry/v1"
	bigquery "google.golang.org/api/bigquery/v2"
	dataproc "google.golang.org/api/dataproc/v1"
)

type fakeBigQuery struct {
	datasets map[string]*bigquery.Dataset
	tables   map[string][]string
	keys     map[string]string
	keyErr   map[string]error
}

func (f fakeBigQuery) DatasetIDs(context.Context, string) ([]string, error) {
	var ids []string
	for id := range f.datasets {
		ids = append(ids, id)
	}
	return ids, nil
}
func (f fakeBigQuery) Dataset(_ context.Context, _, id string) (*bigquery.Dataset, error) {
	return f.datasets[id], nil
}
func (f fakeBigQuery) TableIDs(_ context.Context, _, id string) ([]string, error) {
	return f.tables[id], nil
}
func (f fakeBigQuery) TableKMSKey(_ context.Context, _, ds, t string) (string, error) {
	return f.keys[ds+"."+t], f.keyErr[ds+"."+t]
}

func TestCollectBigQuery(t *testing.T) {
	f := fakeBigQuery{
		datasets: map[string]*bigquery.Dataset{
			"public": {Location: "EU", Access: []*bigquery.DatasetAccess{
				{Role: "OWNER", SpecialGroup: "projectOwners"},
				{Role: "READER", SpecialGroup: "allAuthenticatedUsers"},
				{Role: "READER", IamMember: "allUsers"},
				nil,
			}},
			"cmek":    {DefaultEncryptionConfiguration: &bigquery.EncryptionConfiguration{KmsKeyName: "projects/p/locations/eu/keyRings/r/cryptoKeys/k"}},
			"partial": {DefaultEncryptionConfiguration: &bigquery.EncryptionConfiguration{KmsKeyName: "k"}},
			"empty":   {},
		},
		tables: map[string][]string{"cmek": {"old", "new"}, "public": {"t", "own-key"}, "partial": {"a"}},
		keys:   map[string]string{"cmek.new": "k", "public.own-key": "k2"},
		keyErr: map[string]error{"partial.a": errors.New("denied")},
	}
	got, err := collectBigQuery(context.Background(), f, "p", time.Now())
	require.Error(t, err, "an unreadable table is a partial read")
	md := byID(got)
	require.Equal(t, "allAuthenticatedUsers=READER,allUsers=READER", md["p/bigquery/public"]["public_access_entries"])
	require.Equal(t, "", md["p/bigquery/public"]["default_cmek"])
	require.Equal(t, "t", md["p/bigquery/public"]["tables_without_cmek"],
		"a table carries its own key whatever the dataset default: own-key passes, t fails")
	require.Equal(t, "0", md["p/bigquery/empty"]["tables_without_cmek_count"], "a dataset with no tables has none unencrypted")
	require.Equal(t, "1", md["p/bigquery/cmek"]["tables_without_cmek_count"])
	require.Equal(t, "old", md["p/bigquery/cmek"]["tables_without_cmek"])
	require.Equal(t, "", md["p/bigquery/cmek"]["public_access_entries"])
	require.NotContains(t, md["p/bigquery/partial"], "tables_without_cmek_count")
}

// The table budget is spent in dataset-ID order, so the same datasets are
// graded every sweep however the listing and fan-out are ordered.
func TestCollectBigQuery_BudgetIsDeterministic(t *testing.T) {
	big := make([]string, bigQueryTableLimit)
	for i := range big {
		big[i] = "t"
	}
	f := fakeBigQuery{
		datasets: map[string]*bigquery.Dataset{"a_small": {}, "b_huge": {}, "c_after": {}},
		tables:   map[string][]string{"a_small": {"x"}, "b_huge": big, "c_after": {"y"}},
	}
	for range 5 {
		got, err := collectBigQuery(context.Background(), f, "p", time.Now())
		require.NoError(t, err, "a bounded read is not a partial sweep")
		md := byID(got)
		require.Equal(t, "1", md["p/bigquery/a_small"]["tables_without_cmek_count"])
		require.NotContains(t, md["p/bigquery/b_huge"], "tables_without_cmek_count", "over budget: unknown")
		require.NotContains(t, md["p/bigquery/c_after"], "tables_without_cmek_count", "after the budget ran out")
	}
}

type fakeDataproc struct {
	clusters map[string][]*dataproc.Cluster
	err      map[string]error
	calls    *int
}

func (f fakeDataproc) Regions(context.Context, string) ([]string, error) {
	return []string{"europe-west4", "us-east1"}, nil
}
func (f fakeDataproc) Clusters(_ context.Context, _, region string) ([]*dataproc.Cluster, error) {
	if f.calls != nil {
		*f.calls++
	}
	return f.clusters[region], f.err[region]
}

func TestCollectDataproc(t *testing.T) {
	f := fakeDataproc{clusters: map[string][]*dataproc.Cluster{
		"europe-west4": {{ClusterName: "etl", Config: &dataproc.ClusterConfig{EncryptionConfig: &dataproc.EncryptionConfig{GcePdKmsKeyName: "k"}}}},
		"us-east1":     {{ClusterName: "adhoc"}},
	}}
	got, err := collectDataproc(context.Background(), f, "p", time.Now())
	require.NoError(t, err)
	md := byID(got)
	require.Equal(t, "k", md["p/dataproc/europe-west4/etl"]["disk_cmek"])
	require.Equal(t, "", md["p/dataproc/us-east1/adhoc"]["disk_cmek"])

	calls := 0
	_, err = collectDataproc(context.Background(), fakeDataproc{err: map[string]error{"europe-west4": serviceDisabled}, calls: &calls}, "p", time.Now())
	require.True(t, serviceDisabledErr(context.Background(), err))
	require.Equal(t, 1, calls, "a disabled API is detected on the first region, not fanned out")
}

type fakeAppEngine struct {
	services []*appengine.Service
	versions map[string][]*appengine.Version
}

func (f fakeAppEngine) Services(context.Context, string) ([]*appengine.Service, error) {
	return f.services, nil
}
func (f fakeAppEngine) Versions(_ context.Context, _, s string) ([]*appengine.Version, error) {
	return f.versions[s], nil
}

func TestCollectAppEngine(t *testing.T) {
	f := fakeAppEngine{
		services: []*appengine.Service{{Id: "default", Split: &appengine.TrafficSplit{Allocations: map[string]float64{"v2": 0.9, "flex1": 0.1}}}},
		versions: map[string][]*appengine.Version{"default": {
			{Id: "v1", Handlers: []*appengine.UrlMap{{SecurityLevel: "SECURE_OPTIONAL"}}}, // no traffic
			{Id: "v2", Handlers: []*appengine.UrlMap{{SecurityLevel: "SECURE_ALWAYS"}, {}}},
			{Id: "flex1", Env: "flex", Handlers: []*appengine.UrlMap{{}}},
		}},
	}
	got, err := collectAppEngine(context.Background(), f, "p", time.Now())
	require.NoError(t, err)
	require.Equal(t, "v2", byID(got)["p/appengine/default"]["http_allowed_versions"],
		"an unset handler level serves HTTP; versions without traffic and flex are not graded")
}

type fakeAR struct {
	repos    map[string][]*artifactregistry.Repository
	grants   map[string][]string
	grantErr error
}

func (f fakeAR) Locations(context.Context, string) ([]string, error) { return []string{"europe"}, nil }
func (f fakeAR) Repositories(_ context.Context, _, loc string) ([]*artifactregistry.Repository, error) {
	return f.repos[loc], nil
}
func (f fakeAR) PublicGrants(_ context.Context, r string) ([]string, error) {
	return f.grants[r], f.grantErr
}

func TestCollectArtifactRegistry(t *testing.T) {
	const prefix = "projects/p/locations/europe/repositories/"
	f := fakeAR{
		repos: map[string][]*artifactregistry.Repository{"europe": {
			{Name: prefix + "images", Format: "DOCKER", VulnerabilityScanningConfig: &artifactregistry.VulnerabilityScanningConfig{
				EnablementState: "SCANNING_DISABLED", EnablementStateReason: "API containerscanning.googleapis.com is not enabled."}},
			{Name: prefix + "npm", Format: "NPM", VulnerabilityScanningConfig: &artifactregistry.VulnerabilityScanningConfig{EnablementState: "SCANNING_UNSUPPORTED"}},
			{Name: prefix + "bare", Format: "DOCKER"},
		}},
		grants: map[string][]string{prefix + "images": {"allUsers=roles/artifactregistry.reader"}},
	}
	got, err := collectArtifactRegistry(context.Background(), f, "p", time.Now())
	require.NoError(t, err)
	md := byID(got)
	require.Equal(t, "SCANNING_DISABLED", md[prefix+"images"]["scanning_state"])
	require.Equal(t, "allUsers=roles/artifactregistry.reader", md[prefix+"images"]["public_grants"])
	require.NotContains(t, md[prefix+"npm"], "scanning_state", "unsupported formats are not graded")
	require.NotContains(t, md[prefix+"bare"], "scanning_state", "no scanning config returned is unknown")
	require.Equal(t, "", md[prefix+"bare"]["public_grants"])

	got, err = collectArtifactRegistry(context.Background(), fakeAR{repos: f.repos, grantErr: errors.New("denied")}, "p", time.Now())
	require.Error(t, err)
	require.NotContains(t, byID(got)[prefix+"images"], "public_grants")
}
