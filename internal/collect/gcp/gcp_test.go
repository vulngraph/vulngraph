package gcp

import (
	"context"
	"errors"
	"fmt"
	"testing"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

type fakeCompute struct {
	instances   []gceInstance
	unreachable []string
	err         error

	projControls map[string]string
	projErr      error
	projCalls    int
}

func (f *fakeCompute) ListInstances(context.Context, string) ([]gceInstance, []string, error) {
	return f.instances, f.unreachable, f.err
}

func (f *fakeCompute) ProjectMetadata(context.Context, string) (map[string]string, error) {
	f.projCalls++
	if f.projErr != nil {
		return nil, f.projErr
	}
	if f.projControls == nil {
		return map[string]string{}, nil
	}
	return f.projControls, nil
}

func withFake(f *fakeCompute) *Collector {
	return &Collector{newClient: func(context.Context, map[string]string) (computeAPI, string, error) {
		return f, "proj-1", nil
	}}
}

func TestCollect_InstancesNetworksAndEdges(t *testing.T) {
	fake := &fakeCompute{instances: []gceInstance{
		{Name: "web", NumericID: 5001234567890123456, Zone: "europe-west4-a", Machine: "e2-small", Status: "RUNNING",
			Network: "default", PrivateIP: "10.0.0.2", PublicIP: "34.1.2.3",
			Labels: map[string]string{"env": "prod"}, ServiceAccount: "compute@proj-1.iam.gserviceaccount.com"},
		{Name: "db", Zone: "europe-west4-b", Machine: "e2-medium", Status: "RUNNING",
			Network: "default", PrivateIP: "10.0.0.3"},
	}}

	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	byID := map[string]asset.Asset{}
	for _, a := range res.Assets {
		byID[a.ID] = a
	}
	// 2 instances + 1 deduped network.
	require.Len(t, res.Assets, 3)

	web := byID["proj-1/europe-west4-a/web"]
	require.Equal(t, "gce_instance", web.Type)
	require.Equal(t, asset.ProviderGCP, web.Provider)
	require.Equal(t, "proj-1", web.AccountID)
	require.Equal(t, "34.1.2.3", web.PublicIP)
	require.Equal(t, "e2-small", web.Metadata["machine_type"])
	// gcp_instance_id is the numeric ID SCC's resourceName carries for this
	// instance (jobs.gceIDResolver's join key) — distinct from the human name
	// the asset ID itself is built from. Without it, an SCC finding on this
	// instance could never be matched to it at all.
	require.Equal(t, "5001234567890123456", web.Metadata["gcp_instance_id"])
	// The instance's service account is captured as the executes_as target node ID
	// (gcp_service_account assets are keyed "serviceAccount:<email>").
	require.Equal(t, "serviceAccount:compute@proj-1.iam.gserviceaccount.com", web.Metadata["exec_role"])
	require.Equal(t, "prod", web.Tags["env"])

	require.Contains(t, byID, "proj-1/network/default")
	require.Equal(t, "vpc_network", byID["proj-1/network/default"].Type)

	// Both instances get a runs_in edge; the network asset is deduped to one.
	require.Len(t, res.Edges, 2)
	for _, e := range res.Edges {
		require.Equal(t, "runs_in", e.EdgeType)
		require.Equal(t, "proj-1/network/default", e.DstID)
	}
}

// Instance names are unique per zone only: two "web" instances in different
// zones are two assets, each joined to its own OS Config inventory by numeric ID.
func TestCollect_SameNameTwoZones(t *testing.T) {
	fake := &fakeCompute{instances: []gceInstance{
		{Name: "web", NumericID: 1, Zone: "europe-west4-a", Status: "RUNNING"},
		{Name: "web", NumericID: 2, Zone: "us-central1-b", Status: "RUNNING"},
	}}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	ids := map[string]string{}
	for _, a := range res.Assets {
		ids[a.ID] = a.Metadata["gcp_instance_id"]
	}
	require.Equal(t, map[string]string{"proj-1/europe-west4-a/web": "1", "proj-1/us-central1-b/web": "2"}, ids)
}

func TestCollect_InstanceWithoutNetwork_NoEdge(t *testing.T) {
	fake := &fakeCompute{instances: []gceInstance{{Name: "lonely", Zone: "z", Status: "TERMINATED"}}}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, res.Assets, 1)
	require.Empty(t, res.Edges)
}

func TestCollect_NoInstances(t *testing.T) {
	res, err := withFake(&fakeCompute{}).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, res.Assets)
}

func TestCollect_ListError_IsBestEffort(t *testing.T) {
	// A Compute Engine list failure (e.g. the API is disabled on a function-only
	// project — a meaningful share of GCP projects) must NOT abort the whole collect: the other
	// families (IAM, secrets, GCS, …) still run. The result is flagged partial so
	// sync skips deletion reconciliation, but no hard error is returned.
	res, err := withFake(&fakeCompute{err: errors.New("permission denied")}).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, res.Partial, "a compute list failure marks the sweep partial")
	require.Empty(t, res.Assets, "no instances collected when the list errors")
}

func TestCollect_ClientBuildError(t *testing.T) {
	c := &Collector{newClient: func(context.Context, map[string]string) (computeAPI, string, error) {
		return nil, "", errors.New("project_id is required")
	}}
	_, err := c.Collect(context.Background(), nil)
	require.ErrorContains(t, err, "required")
}

func TestDefaultClient_RequiresProjectID(t *testing.T) {
	_, _, err := defaultClient(context.Background(), map[string]string{})
	require.ErrorContains(t, err, "project_id is required")
}

func TestBestEffort_ErrorFlagsPartial(t *testing.T) {
	var res collect.Result
	bestEffort(context.Background(), &res, "gcp test", func() error {
		return errors.New("throttled")
	})
	require.True(t, res.Partial,
		"a best-effort skip marks the result partial so sync skips deletion reconciliation")
}

func TestBestEffort_SuccessIsNotPartial(t *testing.T) {
	var res collect.Result
	bestEffort(context.Background(), &res, "gcp test", func() error { return nil })
	require.False(t, res.Partial, "a fully successful family is not partial")
}

// TestBestEffort_ServiceDisabledIsNotPartial is the guard: a
// project that has never enabled the API being called (a meaningful share of
// GCP projects — function-only/storage-only/data projects) is a permanent,
// stable fact, not an incomplete sweep. Treating it like a transient failure
// would permanently starve
// connector.PartialStreak into staleness AND permanently disable deletion
// reconciliation for every scope in that project.
func TestBestEffort_ServiceDisabledIsNotPartial(t *testing.T) {
	var res collect.Result
	bestEffort(context.Background(), &res, "gcp compute", func() error {
		return &googleapi.Error{Code: 403, Message: "Compute Engine API has not been used in project example-admin-workspace before or it is disabled.",
			Errors: []googleapi.ErrorItem{{Reason: "SERVICE_DISABLED", Message: "Compute Engine API has not been used in project example-admin-workspace before or it is disabled."}}}
	})
	require.False(t, res.Partial, "a permanently disabled API must not mark the sweep partial")
}

// TestBestEffort_OtherFourOhThreeStillPartial guards the other side of the
// same fix: a 403 that is NOT the SERVICE_DISABLED shape (e.g. a permission
// actually missing on the service account) must still flag Partial — this
// fix narrows the exception to the one permanent, stable condition, it does
// not widen bestEffort into swallowing every 403.
func TestBestEffort_OtherFourOhThreeStillPartial(t *testing.T) {
	var res collect.Result
	bestEffort(context.Background(), &res, "gcp iam", func() error {
		return &googleapi.Error{Code: 403, Message: "The caller does not have permission"}
	})
	require.True(t, res.Partial, "a genuine permission-denied 403 is still a partial sweep")
}

func TestServiceDisabledErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"not a googleapi.Error", errors.New("boom"), false},
		{"403 with ErrorItem reason", &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "SERVICE_DISABLED"}}}, true},
		{"403 with Details reason", &googleapi.Error{Code: 403, Details: []any{map[string]any{"reason": "SERVICE_DISABLED"}}}, true},
		{"403 with the stable message, no structured reason", &googleapi.Error{Code: 403, Message: "Compute Engine API has not been used in project x before or it is disabled."}, true},
		{"403 permission denied", &googleapi.Error{Code: 403, Message: "The caller does not have permission"}, false},
		{"404", &googleapi.Error{Code: 404, Message: "not found"}, false},
		{"429 quota", &googleapi.Error{Code: 429, Message: "Quota exceeded"}, false},
		{"wrapped", fmt.Errorf("ListInstances: %w", &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "SERVICE_DISABLED"}}}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, serviceDisabledErr(context.Background(), tt.err))
		})
	}
}

// An API disabled on the caller's quota project fails every call with the
// same SERVICE_DISABLED shape; only one naming the swept project is the
// stable "never enabled here" fact.
func TestServiceDisabledErr_ChecksTheNamedProject(t *testing.T) {
	ctx := withTargetProject(context.Background(), "prod-app", "111")
	byInfo := func(consumer string) error {
		return &googleapi.Error{Code: 403, Details: []any{map[string]any{
			"reason": "SERVICE_DISABLED", "metadata": map[string]any{"consumer": consumer}}}}
	}
	require.True(t, serviceDisabledErr(ctx, byInfo("projects/111")))
	require.False(t, serviceDisabledErr(ctx, byInfo("projects/999")), "the collector's own quota project")
	require.True(t, serviceDisabledErr(ctx, &googleapi.Error{Code: 403, Message: "Cloud KMS API has not been used in project prod-app before or it is disabled."}))
	require.False(t, serviceDisabledErr(ctx, &googleapi.Error{Code: 403, Message: "Cloud KMS API has not been used in project 999 before or it is disabled."}))
	require.True(t, serviceDisabledErr(ctx, &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "SERVICE_DISABLED"}}}),
		"no project named: assumed the swept one")

	var res collect.Result
	bestEffort(ctx, &res, "gcp kms", func() error { return byInfo("projects/999") })
	require.True(t, res.Partial, "an API disabled on the caller's project is a failed sweep")
}

// Optional (organization, folder, cross-project) reads drop permission
// denied without flagging partial; other failures are kept.
func TestOptionalRead(t *testing.T) {
	ctx := context.Background()
	var errs []error
	optionalRead(ctx, "org sinks", &googleapi.Error{Code: 403, Message: "The caller does not have permission"}, &errs)
	optionalRead(ctx, "org sinks", &googleapi.Error{Code: 401}, &errs)
	optionalRead(ctx, "org sinks", nil, &errs)
	require.Empty(t, errs)
	optionalRead(ctx, "org sinks", &googleapi.Error{Code: 503}, &errs)
	optionalRead(ctx, "org sinks", errors.New("timeout"), &errs)
	require.Len(t, errs, 2)
}

// completedScopes indexes a result's proven-complete enumerations by scope key.
func completedScopes(res collect.Result) map[string]collect.ScopeEnumeration {
	out := map[string]collect.ScopeEnumeration{}
	for _, se := range res.CompletedEnumerations {
		out[se.Scope] = se
	}
	return out
}

// A clean aggregated list is the one case where GCE instance absence is real
// evidence: every zone answered, so an instance the sweep did not return is
// gone rather than un-fetched.
func TestCollect_CleanInstanceListDeclaresScopeComplete(t *testing.T) {
	fake := &fakeCompute{instances: []gceInstance{
		{Name: "web", Zone: "europe-west4-a", Network: "default"},
		{Name: "db", Zone: "europe-west4-b", Network: "default"},
	}}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	scope, ok := completedScopes(res)["global/compute.instances"]
	require.True(t, ok, "a fully-reachable aggregated list must declare its scope complete")
	require.Equal(t, []string{"gce_instance"}, scope.Types,
		"vpc_network is INFERRED from the instances, so a network with no instances would read as deleted")
	require.Equal(t, 2, scope.Count)
}

// The failure this signal exists to avoid: compute.instances.aggregatedList
// reports unreachable zones INSIDE a successful response, so a nil error is not
// a completeness guarantee. Declaring the scope complete here would make every
// instance in an unreachable zone a deletion candidate.
func TestCollect_UnreachableZoneIsPartialAndNotComplete(t *testing.T) {
	fake := &fakeCompute{
		instances:   []gceInstance{{Name: "web", Zone: "europe-west4-a", Network: "default"}},
		unreachable: []string{"zones/us-central1-a"},
	}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err, "an unreachable zone is not a hard failure")
	require.True(t, res.Partial, "an unreachable zone must flag the sweep partial")
	require.NotContains(t, completedScopes(res), "global/compute.instances",
		"a listing that did not reach every zone must declare nothing complete")
	require.Len(t, res.Assets, 2, "the zones that DID answer are still collected (instance + its inferred network)")
}

func TestCollect_ListErrorDeclaresNothingComplete(t *testing.T) {
	res, err := withFake(&fakeCompute{err: errors.New("permission denied")}).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, res.CompletedEnumerations,
		"a failed listing must never leave a completeness claim behind")
}

// Project-level commonInstanceMetadata is where enable-oslogin is normally set
// (GCP projects commonly set it there). Instances inherit it, so an
// instance that sets nothing must report the project's value, not a blank.
func TestCollect_ProjectMetadataIsInherited(t *testing.T) {
	fake := &fakeCompute{
		instances: []gceInstance{
			{Name: "inherits", Zone: "z"},
			{Name: "overrides", Zone: "z", Controls: map[string]string{"enable-oslogin": "FALSE"}},
		},
		projControls: map[string]string{"enable-oslogin": "TRUE"},
	}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, 1, fake.projCalls, "project metadata is fetched once per project, never per instance")

	byID := map[string]asset.Asset{}
	for _, a := range res.Assets {
		byID[a.ID] = a
	}
	require.Equal(t, "true", byID["proj-1/z/inherits"].Metadata["oslogin"])
	// The instance value wins over the project value — GCP's own resolution order.
	require.Equal(t, "false", byID["proj-1/z/overrides"].Metadata["oslogin"])
	// Read successfully and unset anywhere = observed off, not unknown.
	require.Equal(t, "false", byID["proj-1/z/inherits"].Metadata["serial_port_enabled"])
	require.Equal(t, "false", byID["proj-1/z/inherits"].Metadata["project_ssh_keys_blocked"])
}

// When project metadata cannot be read the control is UNKNOWN. The key must be
// omitted: writing "" or "false" would make the checks fire on every instance
// whose metadata could not be read.
func TestCollect_ProjectMetadataError_OmitsUnknownControls(t *testing.T) {
	fake := &fakeCompute{
		instances: []gceInstance{
			{Name: "unknown", Zone: "z"},
			{Name: "explicit", Zone: "z", Controls: map[string]string{"serial-port-enable": "1"}},
		},
		projErr: errors.New("compute.projects.get: 403"),
	}
	res, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	byID := map[string]asset.Asset{}
	for _, a := range res.Assets {
		byID[a.ID] = a
	}
	for _, k := range []string{"oslogin", "serial_port_enabled", "project_ssh_keys_blocked"} {
		require.NotContains(t, byID["proj-1/z/unknown"].Metadata, k,
			"unknown controls are omitted, never written as a negative")
	}
	// An instance-level value needs no project read, so it survives the failure.
	require.Equal(t, "true", byID["proj-1/z/explicit"].Metadata["serial_port_enabled"])
	require.NotContains(t, byID["proj-1/z/explicit"].Metadata, "oslogin")
}

// No instances means nothing to apply project metadata to — do not spend the call.
func TestCollect_NoInstances_SkipsProjectMetadata(t *testing.T) {
	fake := &fakeCompute{}
	_, err := withFake(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.Zero(t, fake.projCalls)
}

func TestResolveGCEControl(t *testing.T) {
	cases := []struct {
		name      string
		inst      map[string]string
		proj      map[string]string
		projKnown bool
		want      string
		wantOK    bool
	}{
		{"instance TRUE wins", map[string]string{"enable-oslogin": "TRUE"}, map[string]string{"enable-oslogin": "FALSE"}, true, "true", true},
		{"instance FALSE wins", map[string]string{"enable-oslogin": "FALSE"}, map[string]string{"enable-oslogin": "TRUE"}, true, "false", true},
		{"instance lowercase true", map[string]string{"enable-oslogin": "true"}, nil, true, "true", true},
		{"instance numeric 1", map[string]string{"enable-oslogin": "1"}, nil, true, "true", true},
		{"inherits project", nil, map[string]string{"enable-oslogin": "TRUE"}, true, "true", true},
		{"project read, key unset = off", nil, map[string]string{}, true, "false", true},
		{"project unreadable = unknown", nil, nil, false, "", false},
		{"instance set, project unreadable", map[string]string{"enable-oslogin": "TRUE"}, nil, false, "true", true},
		{"garbage value is not truthy", map[string]string{"enable-oslogin": "yes"}, nil, true, "false", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveGCEControl(tc.inst, tc.proj, tc.projKnown, "enable-oslogin")
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.want, got)
		})
	}
}

// commonInstanceMetadata carries ssh-keys and startup scripts; only the three
// security-control keys may ever be lifted onto an asset.
func TestControlMetadata_KeepsOnlyControlKeys(t *testing.T) {
	val := func(s string) *string { return &s }
	got := controlMetadata([]*compute.MetadataItems{
		{Key: "enable-oslogin", Value: val("TRUE")},
		{Key: "ssh-keys", Value: val("alice:ssh-rsa AAAA...")},
		{Key: "startup-script", Value: val("#!/bin/sh\ncurl secrets")},
		nil,
		{Key: "serial-port-enable", Value: nil},
	})
	require.Equal(t, map[string]string{"enable-oslogin": "TRUE", "serial-port-enable": ""}, got)
}

func TestLastSegment(t *testing.T) {
	cases := map[string]string{
		"https://www.googleapis.com/compute/v1/projects/p/zones/europe-west4-a": "europe-west4-a",
		"default": "default",
		"":        "",
	}
	for in, want := range cases {
		require.Equal(t, want, lastSegment(in))
	}
}
