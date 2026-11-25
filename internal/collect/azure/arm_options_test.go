package azure

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v8"
	aksfake "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v8/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks"
	dbxfake "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	netfake "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	storagefake "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/fake"
	"github.com/stretchr/testify/require"
)

const unregisteredCode = "MissingSubscriptionRegistration"

// recordingTransport records every request the SDK pipeline sends, so a test
// can prove no write (the provider-registration POST) ever leaves it.
type recordingTransport struct {
	next policy.Transporter
	mu   sync.Mutex
	sent []string
}

func (r *recordingTransport) Do(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.sent = append(r.sent, req.Method+" "+req.URL.Path)
	r.mu.Unlock()
	return r.next.Do(req)
}

func (r *recordingTransport) requireReadOnly(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.NotEmpty(t, r.sent)
	for _, s := range r.sent {
		require.Regexp(t, `^GET `, s, "a read-only collector sent a write")
	}
}

// fakeOpts is readOnlyARM over a fake server transport, without retries so an
// injected error is seen once.
func fakeOpts(next policy.Transporter) (*arm.ClientOptions, *recordingTransport) {
	rec := &recordingTransport{next: next}
	opts := readOnlyARM()
	opts.Transport = rec
	opts.Retry = policy.RetryOptions{MaxRetries: -1}
	return opts, rec
}

var fakeCredential = &azfake.TokenCredential{}

func TestReadOnlyARM_DisablesProviderRegistration(t *testing.T) {
	require.True(t, readOnlyARM().DisableRPRegistration,
		"the SDK otherwise answers MissingSubscriptionRegistration by POSTing providers/{ns}/register — a write")
}

func TestUnregisteredProvider_IsAnEmptyListing(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	t.Run("aks", func(t *testing.T) {
		srv := aksfake.ManagedClustersServer{NewListPager: func(*armcontainerservice.ManagedClustersClientListOptions) (resp azfake.PagerResponder[armcontainerservice.ManagedClustersClientListResponse]) {
			resp.AddResponseError(http.StatusConflict, unregisteredCode)
			return
		}}
		opts, rec := fakeOpts(aksfake.NewManagedClustersServerTransport(&srv))
		assets, err := collectAKS(ctx, fakeCredential, "sub", now, opts)
		require.NoError(t, err, "an unregisteredCode provider holds no clusters; that is an observation")
		require.Empty(t, assets)
		rec.requireReadOnly(t)
	})

	t.Run("aks denied is still a failure", func(t *testing.T) {
		srv := aksfake.ManagedClustersServer{NewListPager: func(*armcontainerservice.ManagedClustersClientListOptions) (resp azfake.PagerResponder[armcontainerservice.ManagedClustersClientListResponse]) {
			resp.AddResponseError(http.StatusForbidden, "AuthorizationFailed")
			return
		}}
		opts, _ := fakeOpts(aksfake.NewManagedClustersServerTransport(&srv))
		_, err := collectAKS(ctx, fakeCredential, "sub", now, opts)
		require.Error(t, err, "a denied listing is unknown, never empty")
	})

	t.Run("databricks", func(t *testing.T) {
		srv := dbxfake.WorkspacesServer{NewListBySubscriptionPager: func(*armdatabricks.WorkspacesClientListBySubscriptionOptions) (resp azfake.PagerResponder[armdatabricks.WorkspacesClientListBySubscriptionResponse]) {
			resp.AddResponseError(http.StatusConflict, unregisteredCode)
			return
		}}
		opts, rec := fakeOpts(dbxfake.NewWorkspacesServerTransport(&srv))
		assets, err := collectDatabricks(ctx, fakeCredential, "sub", now, opts)
		require.NoError(t, err)
		require.Empty(t, assets)
		rec.requireReadOnly(t)
	})

	t.Run("databricks mid-listing is a failure", func(t *testing.T) {
		srv := dbxfake.WorkspacesServer{NewListBySubscriptionPager: func(*armdatabricks.WorkspacesClientListBySubscriptionOptions) (resp azfake.PagerResponder[armdatabricks.WorkspacesClientListBySubscriptionResponse]) {
			resp.AddPage(http.StatusOK, armdatabricks.WorkspacesClientListBySubscriptionResponse{WorkspaceListResult: armdatabricks.WorkspaceListResult{
				Value: []*armdatabricks.Workspace{{ID: to.Ptr("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Databricks/workspaces/w1")}}}}, nil)
			resp.AddResponseError(http.StatusConflict, unregisteredCode)
			return
		}}
		opts, _ := fakeOpts(dbxfake.NewWorkspacesServerTransport(&srv))
		_, err := collectDatabricks(ctx, fakeCredential, "sub", now, opts)
		require.Error(t, err, "only a first-page answer means the provider was never registered")
	})

	t.Run("network watchers and bastion", func(t *testing.T) {
		srv := netfake.ServerFactory{
			WatchersServer: netfake.WatchersServer{NewListAllPager: func(*armnetwork.WatchersClientListAllOptions) (resp azfake.PagerResponder[armnetwork.WatchersClientListAllResponse]) {
				resp.AddResponseError(http.StatusConflict, unregisteredCode)
				return
			}},
			BastionHostsServer: netfake.BastionHostsServer{NewListPager: func(*armnetwork.BastionHostsClientListOptions) (resp azfake.PagerResponder[armnetwork.BastionHostsClientListResponse]) {
				resp.AddResponseError(http.StatusConflict, unregisteredCode)
				return
			}},
		}
		opts, rec := fakeOpts(netfake.NewServerFactoryTransport(&srv))
		nw, err := readNetworkWatchers(ctx, fakeCredential, "sub", opts)
		require.NoError(t, err)
		require.Empty(t, nw.regions)
		require.NotNil(t, nw.flowLogs, "an empty estate is still a usable answer")
		n, err := countBastionHosts(ctx, fakeCredential, "sub", opts)
		require.NoError(t, err)
		require.Zero(t, n)
		rec.requireReadOnly(t)
	})
}

func flowLogPage(target string) armnetwork.FlowLogsClientListResponse {
	return armnetwork.FlowLogsClientListResponse{FlowLogListResult: armnetwork.FlowLogListResult{Value: []*armnetwork.FlowLog{{
		Properties: &armnetwork.FlowLogPropertiesFormat{TargetResourceID: to.Ptr(target), Enabled: to.Ptr(true)},
	}}}}
}

func watcherServers(flowLogs func() azfake.PagerResponder[armnetwork.FlowLogsClientListResponse]) *netfake.ServerFactory {
	return &netfake.ServerFactory{
		WatchersServer: netfake.WatchersServer{NewListAllPager: func(*armnetwork.WatchersClientListAllOptions) (resp azfake.PagerResponder[armnetwork.WatchersClientListAllResponse]) {
			resp.AddPage(http.StatusOK, armnetwork.WatchersClientListAllResponse{WatcherListResult: armnetwork.WatcherListResult{Value: []*armnetwork.Watcher{{
				ID:       to.Ptr("/subscriptions/sub/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus"),
				Name:     to.Ptr("NetworkWatcher_eastus"),
				Location: to.Ptr("eastus"),
			}}}}, nil)
			return
		}},
		FlowLogsServer: netfake.FlowLogsServer{NewListPager: func(string, string, *armnetwork.FlowLogsClientListOptions) azfake.PagerResponder[armnetwork.FlowLogsClientListResponse] {
			return flowLogs()
		}},
	}
}

// Every flow-log page must be read: a listing that stopped at a failed page
// would leave the VNets on the missing pages reading as unlogged.
func TestReadNetworkWatchers_FlowLogPaging(t *testing.T) {
	ctx := context.Background()

	opts, rec := fakeOpts(netfake.NewServerFactoryTransport(watcherServers(func() (resp azfake.PagerResponder[armnetwork.FlowLogsClientListResponse]) {
		resp.AddPage(http.StatusOK, flowLogPage("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/a"), nil)
		resp.AddPage(http.StatusOK, flowLogPage("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/b"), nil)
		return
	})))
	nw, err := readNetworkWatchers(ctx, fakeCredential, "sub", opts)
	require.NoError(t, err)
	require.True(t, nw.regions["eastus"])
	require.Len(t, nw.flowLogs, 2, "both pages are read")
	rec.requireReadOnly(t)

	opts, _ = fakeOpts(netfake.NewServerFactoryTransport(watcherServers(func() (resp azfake.PagerResponder[armnetwork.FlowLogsClientListResponse]) {
		resp.AddPage(http.StatusOK, flowLogPage("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/a"), nil)
		resp.AddResponseError(http.StatusInternalServerError, "InternalServerError")
		return
	})))
	_, err = readNetworkWatchers(ctx, fakeCredential, "sub", opts)
	require.Error(t, err, "a failed flow-log page fails the whole read rather than returning a short list")
}

// The share listing pages past NFS shares to find an SMB one, and a failed
// page is a failed read, not "no SMB shares".
func TestFileShares_ProtocolsAndPaging(t *testing.T) {
	ctx := context.Background()
	page := func(protos ...armstorage.EnabledProtocols) armstorage.FileSharesClientListResponse {
		var items []*armstorage.FileShareItem
		for _, p := range protos {
			items = append(items, &armstorage.FileShareItem{Properties: &armstorage.FileShareProperties{EnabledProtocols: to.Ptr(p)}})
		}
		return armstorage.FileSharesClientListResponse{FileShareItems: armstorage.FileShareItems{Value: items}}
	}
	run := func(fill func(*azfake.PagerResponder[armstorage.FileSharesClientListResponse])) (shareKinds, *recordingTransport, error) {
		srv := storagefake.FileSharesServer{NewListPager: func(string, string, *armstorage.FileSharesClientListOptions) (resp azfake.PagerResponder[armstorage.FileSharesClientListResponse]) {
			fill(&resp)
			return
		}}
		opts, rec := fakeOpts(storagefake.NewFileSharesServerTransport(&srv))
		svc, err := newARMStorageServices("sub", fakeCredential, opts)
		require.NoError(t, err)
		k, err := svc.fileShares(ctx, "rg", "acct")
		return k, rec, err
	}

	k, rec, err := run(func(r *azfake.PagerResponder[armstorage.FileSharesClientListResponse]) {
		r.AddPage(http.StatusOK, page(armstorage.EnabledProtocolsNFS), nil)
		r.AddPage(http.StatusOK, page(armstorage.EnabledProtocolsSMB), nil)
	})
	require.NoError(t, err)
	require.Equal(t, shareKinds{any: true, smb: true}, k)
	rec.requireReadOnly(t)

	k, _, err = run(func(r *azfake.PagerResponder[armstorage.FileSharesClientListResponse]) {
		r.AddPage(http.StatusOK, page(armstorage.EnabledProtocolsNFS, armstorage.EnabledProtocolsNFS), nil)
	})
	require.NoError(t, err)
	require.Equal(t, shareKinds{any: true}, k, "NFS-only")

	_, _, err = run(func(r *azfake.PagerResponder[armstorage.FileSharesClientListResponse]) {
		r.AddPage(http.StatusOK, page(armstorage.EnabledProtocolsNFS), nil)
		r.AddResponseError(http.StatusInternalServerError, "InternalServerError")
	})
	require.Error(t, err)
}
