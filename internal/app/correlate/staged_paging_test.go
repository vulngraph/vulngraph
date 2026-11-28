package correlate

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestStagedReplayDoesNotCopyTheRowIndex(t *testing.T) {
	s := &stagedFile{groups: map[string]map[string][]stagedInputRef{"ec2_instance": {}}}
	const rows = 200000
	for i := range rows {
		account := fmt.Sprint(i % 4)
		s.groups["ec2_instance"][account] = append(s.groups["ec2_instance"][account], stagedInputRef{stagedRef: stagedRef{offset: int64(i), size: 1}, charge: 1})
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	queue := s.refsFor([]string{"ec2_instance"}, nil)
	for i := range rows {
		ref := queue.pop()
		if ref.offset != int64(i) {
			t.Fatalf("source order at %d: %d", i, ref.offset)
		}
	}
	runtime.ReadMemStats(&after)
	require.Empty(t, queue)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(64<<10), "replay must not copy 200k references before delivering a page")
}

func TestStagedDNSPreservesGlobalTargetsAcrossAccountsAndPages(t *testing.T) {
	for _, unsupported := range []bool{false, true} {
		t.Run(fmt.Sprintf("unsupported_targets=%v", unsupported), func(t *testing.T) {
			rows := []asset.Asset{
				{ID: "record-a", Type: "dns_record", AccountID: "dns-account", Metadata: map[string]string{"values": "203.0.113.9, app.example.,203.0.113.9"}},
				{ID: "record-b", Type: "dns_record", AccountID: "second-account", Metadata: map[string]string{"values": "APP.EXAMPLE.,203.0.113.9"}},
			}
			// Descending input order puts the globally preferred IDs on later
			// pages. Multiple IPs and duplicate values retain existing semantics.
			for i := 69; i >= 0; i-- {
				kind := "ec2_instance"
				if unsupported && i < 30 {
					kind = "s3_bucket"
				}
				rows = append(rows, asset.Asset{ID: fmt.Sprintf("target-%03d", i), Type: kind, AccountID: fmt.Sprint(i % 4), PublicIP: "203.0.113.9, 203.0.113.10", Domain: "App.Example."})
			}
			want := dedupe((DNSPointsTo{}).Correlate(NewGraph(rows)))
			for _, pageRows := range []int{1, 7, 29} {
				limits := DefaultStagedViewLimits()
				limits.PageRows = pageRows
				writer := &fakeWriter{}
				loader := &stagedFakeLoader{fakeLoader: fakeLoader{assets: rows}}
				_, err := NewService(loader, writer, []Rule{DNSPointsTo{}}).WithStagedViews(limits).Correlate(context.Background())
				require.NoError(t, err)
				require.ElementsMatch(t, want, writer.got)
				require.Equal(t, 3, loader.snapshot.Stats().ReplayPasses, "DNS scans targets once, not once per record page")
			}
		})
	}
}

func TestStagedDNSIndexBudgetFailsBeforePublication(t *testing.T) {
	rows := []asset.Asset{{ID: "record", Type: "dns_record", Metadata: map[string]string{"values": "a.example,b.example,c.example"}}}
	limits := DefaultStagedViewLimits()
	limits.ContextBytes = 128
	writer := &fakeWriter{}
	_, err := NewService(&stagedFakeLoader{fakeLoader: fakeLoader{assets: rows}}, writer, []Rule{DNSPointsTo{}}).WithStagedViews(limits).Correlate(context.Background())
	require.ErrorIs(t, err, ErrStagedBudget)
	require.Empty(t, writer.got)
}

func TestStagedDecodeBufferDoesNotAliasRetainedRows(t *testing.T) {
	s, err := newStagedFile(DefaultStagedViewLimits())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	want := []asset.Asset{
		{ID: "first", Type: "ec2_instance", Metadata: map[string]string{"name": "quoted\"value"}},
		{ID: "second", Type: "ec2_instance", Metadata: map[string]string{"name": "new-value"}},
	}
	for _, row := range want {
		require.NoError(t, s.appendInput(s.input, row))
	}
	var got []asset.Asset
	require.NoError(t, s.Read(context.Background(), []string{"ec2_instance"}, nil, 1, 1<<20, func(page []asset.Asset) error {
		got = append(got, page...)
		return nil
	}))
	require.Equal(t, want, got)
	require.Equal(t, int64(1), s.stats.SpoolReadCalls, "adjacent frames share a bounded read")
}

func TestStagedReadCacheHandlesFileSwitchesAndGrowingOutput(t *testing.T) {
	s, err := newStagedFile(DefaultStagedViewLimits())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	row := asset.Asset{ID: "row", Type: "ec2_instance"}
	require.NoError(t, s.appendInput(s.input, row))
	input := s.groups[row.Type][""][0].stagedRef
	var first asset.Asset
	data, err := s.readFrame(s.input, input)
	require.NoError(t, err)
	require.NoError(t, decodeStagedSourceFrame(data, &first))
	for i := range 3 {
		want := asset.Edge{SrcID: fmt.Sprint(i), DstID: "dst"}
		ref, err := s.appendOutput(want)
		require.NoError(t, err)
		var got asset.Edge
		require.NoError(t, s.readJSON(s.output, ref, &got))
		require.Equal(t, want, got, "new output appended after cached EOF")
	}
	var again asset.Asset
	data, err = s.readFrame(s.input, input)
	require.NoError(t, err)
	require.NoError(t, decodeStagedSourceFrame(data, &again))
	require.Equal(t, row, again)
	_, err = s.readFrame(s.input, stagedRef{offset: input.offset, size: input.size + 1})
	require.Error(t, err)
}

func TestStagedPrincipalsKeepCompleteOrganizationContext(t *testing.T) {
	rows := []asset.Asset{scpSetAsset("blocked", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`)}
	for i := range 31 {
		for _, account := range []string{"allowed", "blocked"} {
			rows = append(rows, principalWithPolicy(fmt.Sprintf("%s-role-%02d", account, i), "iam_role", account,
				`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`))
		}
	}
	assertStagedPageParity(t, rows, IAMEffectivePermissions{})
}

func TestStagedK8sExposureWinnerSpansPages(t *testing.T) {
	rows := []asset.Asset{
		{ID: "cluster/service/prod/z", Type: "k8s_service", PublicIP: "203.0.113.2", Metadata: map[string]string{"namespace": "prod", "type": "LoadBalancer", "selector": "app=web"}},
		{ID: "cluster/service/prod/a", Type: "k8s_service", PublicIP: "203.0.113.3", Metadata: map[string]string{"namespace": "prod", "type": "LoadBalancer", "selector": "app=web"}},
	}
	for i := 30; i >= 0; i-- {
		rows = append(rows, asset.Asset{ID: fmt.Sprintf("cluster/pod/prod/web-%02d", i), Type: "k8s_pod", Region: "cluster",
			Metadata: map[string]string{"namespace": "prod", "owner_kind": "Deployment", "owner_name": "web"}, Tags: map[string]string{"app": "web"}})
	}
	// A direct owner match wins over an inherited via_pod edge at equal tier.
	rows = append(rows, asset.Asset{ID: "cluster/deployment/prod/web", Type: "k8s_deployment",
		Metadata: map[string]string{"namespace": "prod"}, Tags: map[string]string{"app": "web"}})
	assertStagedPageParity(t, rows, K8sServiceTargets{})
}

func TestStagedSharedSecurityGroupRetainsExistenceAcrossPages(t *testing.T) {
	rows := []asset.Asset{{ID: "sg-present", Type: "security_group"}, {ID: "sg-polluted", Type: "ec2_instance"}}
	for i := range 31 {
		rows = append(rows, asset.Asset{ID: fmt.Sprintf("vm-%02d", i), Type: "ec2_instance",
			Metadata: map[string]string{"security_groups": "sg-present,sg-polluted,sg-missing"}})
	}
	assertStagedPageParity(t, rows, SharedSecurityGroup{})
}

func TestStagedMetadataDrivenIndexesRetainFullViewInputs(t *testing.T) {
	rows := []asset.Asset{
		{ID: "nsg", Type: "security_group"},
		{ID: "/subscriptions/s/managedidentity/id", Type: "azure_managed_identity"},
		{ID: "azure-vm", Type: "azure_vm", Metadata: map[string]string{"exec_role": "/subscriptions/s/managedidentity/id", "nsg_ids": "nsg"}},
		// Full-sweep metadata indexes also accept types not currently listed
		// for partial activation. Paging must not change that legacy behavior.
		{ID: "custom-bucket", Type: "gcs_bucket", Metadata: map[string]string{"exec_role": "/subscriptions/s/managedidentity/id", "security_groups": "nsg"}},
	}
	assertStagedPageParity(t, rows, SharedSecurityGroup{})
	assertStagedPageParity(t, rows, ExecutesAs{})
}

func assertStagedPageParity(t *testing.T, rows []asset.Asset, rule Rule) {
	t.Helper()
	want := dedupe(rule.Correlate(NewGraph(rows)))
	require.NotEmpty(t, want)
	for _, size := range []int{1, 7, 29} {
		limits := DefaultStagedViewLimits()
		limits.PageRows = size
		writer := &fakeWriter{}
		_, err := NewService(&stagedFakeLoader{fakeLoader: fakeLoader{assets: rows}}, writer, []Rule{rule}).WithStagedViews(limits).Correlate(t.Context())
		require.NoError(t, err)
		require.ElementsMatch(t, want, writer.got, "page size %d", size)
	}
}
