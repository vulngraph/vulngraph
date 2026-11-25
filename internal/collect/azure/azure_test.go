package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

// execRoleTargets feeds collectIdentities the exec_role references from THIS
// sweep's VM/webapp assets, so a managed identity with zero role assignments
// still gets an asset (see iam.go's collectIdentities doc comment).
func TestExecRoleTargets_DedupesAndSkipsEmpty(t *testing.T) {
	assets := []asset.Asset{
		{ID: "vm-1", Metadata: map[string]string{"exec_role": "azure_managed_identity:a"}},
		{ID: "webapp-1", Metadata: map[string]string{"exec_role": "azure_managed_identity:a"}}, // duplicate
		{ID: "webapp-2", Metadata: map[string]string{"exec_role": "azure_managed_identity:b"}},
		{ID: "webapp-3", Metadata: map[string]string{}},            // no exec_role at all
		{ID: "vm-2", Metadata: map[string]string{"exec_role": ""}}, // empty exec_role
	}
	got := execRoleTargets(assets)
	require.ElementsMatch(t, []string{"azure_managed_identity:a", "azure_managed_identity:b"}, got)
}

func TestResourceGroup(t *testing.T) {
	id := "/subscriptions/sub123/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm"
	require.Equal(t, "my-rg", resourceGroup(id))
}

func TestNicName(t *testing.T) {
	id := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/my-nic"
	require.Equal(t, "my-nic", nicName(id))
}

func TestPortRange(t *testing.T) {
	from, to := portRange("80")
	require.Equal(t, int32(80), from)
	require.Equal(t, int32(80), to)

	from, to = portRange("443-8443")
	require.Equal(t, int32(443), from)
	require.Equal(t, int32(8443), to)

	from, to = portRange("*")
	require.Equal(t, int32(0), from)
	require.Equal(t, int32(65535), to)
}

func TestHTTPSURL(t *testing.T) {
	require.Equal(t, "https://myapp.azurewebsites.net", httpsURL("myapp.azurewebsites.net"))
	require.Equal(t, "", httpsURL(""))
}

// TestAppendOrLog_ErrorFlagsPartial mirrors gcp's TestBestEffort_ErrorFlagsPartial,
// and closes a wrongful-deletion landmine rather than a cosmetic inconsistency.
//
// SyncWorker treats !res.Partial as proof that the collector enumerated everything,
// and on that basis prunes the connector's asset hashes and RESOLVES THE FINDINGS of
// every asset the sweep did not return (internal/jobs/sync.go, "absent≠deleted").
// appendOrLog skipped a failed service family without flagging the result,
// so an Azure permission gap or transient error would have been reported as "these
// resources are gone" and auto-resolved live findings on storage accounts, web apps,
// SQL servers, disks and managed identities.
//
// AWS (skip) and GCP (bestEffort) both flag partial; Azure alone did not.
func TestAppendOrLog_ErrorFlagsPartial(t *testing.T) {
	var res collect.Result
	gotOK, gotAssets := appendOrLog(context.Background(), &res, "azure storage", func() ([]asset.Asset, []asset.Edge, error) {
		return nil, nil, errors.New("AuthorizationFailed")
	})
	require.True(t, res.Partial,
		"a skipped azure service family must mark the sweep partial, or sync reads the "+
			"absent assets as deleted and resolves their findings")
	require.Empty(t, res.Assets, "nothing is collected when the family errors")
	require.False(t, gotOK, "a failed listing must report false so callers don't claim completeness")
	require.Nil(t, gotAssets)

	// The success path must NOT flag partial, or reconciliation never runs for Azure.
	var ok collect.Result
	gotOK, gotAssets = appendOrLog(context.Background(), &ok, "azure storage", func() ([]asset.Asset, []asset.Edge, error) {
		return []asset.Asset{{ID: "sa-1"}}, nil, nil
	})
	require.False(t, ok.Partial, "a successful family must leave the sweep complete")
	require.Len(t, ok.Assets, 1)
	require.True(t, gotOK, "a successful listing must report true so the caller can claim completeness")
	require.Equal(t, []asset.Asset{{ID: "sa-1"}}, gotAssets)
}

// countTypes sizes a MarkComplete call from a slice already known (by the
// caller's own success check) to be a complete enumeration — one scope can
// bundle several asset types (e.g. vnets+subnets from one ARM listing), and
// this must count only the requested types, not every asset in the slice.
func TestCountTypes(t *testing.T) {
	assets := []asset.Asset{
		{ID: "1", Type: "azure_vnet"},
		{ID: "2", Type: "azure_subnet"},
		{ID: "3", Type: "azure_subnet"},
		{ID: "4", Type: "security_group"}, // a sibling type in the same result, must not be counted
	}
	require.Equal(t, 3, countTypes(assets, "azure_vnet", "azure_subnet"))
	require.Equal(t, 1, countTypes(assets, "security_group"))
	require.Equal(t, 0, countTypes(assets, "azure_public_ip"))
}

// TestAppendOrLogPattern_SiblingClaimSurvivesAFailure exercises the exact
// composition collectAll uses for every best-effort family: MarkComplete is
// called only when appendOrLog reports success, using the assets it just
// returned. It pins two things the strict MarkComplete contract requires:
// a failed family makes NO claim for its own scope, and does not suppress a
// sibling family's valid claim, even though both share one aggregate
// result.Partial flag.
func TestAppendOrLogPattern_SiblingClaimSurvivesAFailure(t *testing.T) {
	var res collect.Result

	if ok, assets := appendOrLog(context.Background(), &res, "storage", func() ([]asset.Asset, []asset.Edge, error) {
		return []asset.Asset{{ID: "sa-1", Type: "azure_storage_account"}}, nil, nil
	}); ok {
		res.MarkComplete("sub/storage:accounts", []string{"azure_storage_account"}, len(assets))
	}

	if ok, assets := appendOrLog(context.Background(), &res, "sql", func() ([]asset.Asset, []asset.Edge, error) {
		return nil, nil, errors.New("AuthorizationFailed")
	}); ok {
		res.MarkComplete("sub/sql:servers", []string{"azure_sql_server"}, len(assets))
	}

	require.True(t, res.Partial, "the sql failure must still flag the sweep partial")

	byScope := map[string]collect.ScopeEnumeration{}
	for _, se := range res.CompletedEnumerations {
		byScope[se.Scope] = se
	}
	_, gotSQLClaim := byScope["sub/sql:servers"]
	require.False(t, gotSQLClaim, "the failed sql family must not claim completeness")

	storageClaim, gotStorageClaim := byScope["sub/storage:accounts"]
	require.True(t, gotStorageClaim, "the sibling storage family's valid claim must survive the sql failure")
	require.Equal(t, 1, storageClaim.Count)
}
