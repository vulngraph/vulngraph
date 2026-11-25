package azuredisk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

const diskID = "/subscriptions/sub/resourceGroups/rg-a/providers/Microsoft.Compute/disks/osdisk"

type fakeLister struct {
	pages  map[string][][]*armcompute.Snapshot
	failAt map[string]int // page index that errors, per resource group
	asked  []string
}

func (f *fakeLister) NewListByResourceGroupPager(rg string, _ *armcompute.SnapshotsClientListByResourceGroupOptions) *runtime.Pager[armcompute.SnapshotsClientListByResourceGroupResponse] {
	f.asked = append(f.asked, rg)
	pages := f.pages[rg]
	next := 0
	return runtime.NewPager(runtime.PagingHandler[armcompute.SnapshotsClientListByResourceGroupResponse]{
		More: func(r armcompute.SnapshotsClientListByResourceGroupResponse) bool { return r.NextLink != nil },
		Fetcher: func(context.Context, *armcompute.SnapshotsClientListByResourceGroupResponse) (armcompute.SnapshotsClientListByResourceGroupResponse, error) {
			idx := next
			next++
			if at, ok := f.failAt[rg]; ok && at == idx {
				return armcompute.SnapshotsClientListByResourceGroupResponse{}, errors.New("boom")
			}
			var resp armcompute.SnapshotsClientListByResourceGroupResponse
			if idx < len(pages) {
				resp.Value = pages[idx]
			}
			if idx+1 < len(pages) {
				resp.NextLink = new("next")
			}
			return resp, nil
		},
	})
}

type fakeDisks struct {
	ade bool
	err error
}

func (f fakeDisks) Get(context.Context, string, string, *armcompute.DisksClientGetOptions) (armcompute.DisksClientGetResponse, error) {
	if f.err != nil {
		return armcompute.DisksClientGetResponse{}, f.err
	}
	return armcompute.DisksClientGetResponse{Disk: armcompute.Disk{Properties: &armcompute.DiskProperties{
		EncryptionSettingsCollection: &armcompute.EncryptionSettingsCollection{Enabled: &f.ade},
	}}}, nil
}

func snapOf(name, source string, age time.Duration, mut func(*armcompute.Snapshot)) *armcompute.Snapshot {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(-age)
	s := &armcompute.Snapshot{
		ID:       new("/subscriptions/sub/resourceGroups/rg-a/providers/Microsoft.Compute/snapshots/" + name),
		Location: new("westeurope"),
		Properties: &armcompute.SnapshotProperties{
			CreationData:      &armcompute.CreationData{SourceResourceID: &source},
			ProvisioningState: new("Succeeded"),
			DiskSizeBytes:     new(int64(1 << 30)),
			TimeCreated:       &created,
		},
	}
	if mut != nil {
		mut(s)
	}
	return s
}

func TestListReusable(t *testing.T) {
	lister := &fakeLister{pages: map[string][][]*armcompute.Snapshot{"rg-a": {
		{
			snapOf("old", diskID, 48*time.Hour, nil),
			snapOf("other-disk", diskID+"2", time.Hour, nil),
			snapOf("pending", diskID, time.Hour, func(s *armcompute.Snapshot) { s.Properties.ProvisioningState = new("Creating") }),
			nil,
		},
		{
			snapOf("ours", diskID, time.Minute, func(s *armcompute.Snapshot) { s.Tags = map[string]*string{diskscan.TagKey: new("run")} }),
			snapOf("new", "/SUBSCRIPTIONS/SUB/RESOURCEGROUPS/RG-A/PROVIDERS/MICROSOFT.COMPUTE/DISKS/OSDISK", 24*time.Hour, nil),
			snapOf("nosource", diskID, time.Hour, func(s *armcompute.Snapshot) { s.Properties.CreationData = nil }),
		},
	}}}
	p := New(lister, fakeDisks{}, Config{})

	got, err := p.ListReusable(context.Background(), diskscan.VolumeRef{Provider: "azure", VolumeID: diskID})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "new", got[0].ID[len(got[0].ID)-3:], "newest first")
	assert.Contains(t, got[1].ID, "/old")
	assert.Equal(t, diskscan.Snapshot{
		ID: got[1].ID, Provider: "azure", Region: "westeurope", VolumeID: diskID,
		SizeBytes: 1 << 30, CreatedAt: got[1].CreatedAt,
	}, got[1])
	assert.Equal(t, []string{"rg-a"}, lister.asked, "defaults to the disk's own group")
}

func TestListReusable_ConfiguredGroupsAndEncryption(t *testing.T) {
	lister := &fakeLister{pages: map[string][][]*armcompute.Snapshot{
		"snaps-1": {{snapOf("a", diskID, time.Hour, nil)}},
		"snaps-2": {{snapOf("b", diskID, 2*time.Hour, nil)}},
	}}
	p := New(lister, fakeDisks{ade: true}, Config{ResourceGroups: []string{"snaps-1", "snaps-2"}})
	got, err := p.ListReusable(context.Background(), diskscan.VolumeRef{VolumeID: diskID})
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, s := range got {
		assert.True(t, s.Encrypted, "a disk under Azure Disk Encryption yields encrypted snapshots")
	}

	snapADE := snapOf("c", diskID, time.Hour, func(s *armcompute.Snapshot) {
		s.Properties.EncryptionSettingsCollection = &armcompute.EncryptionSettingsCollection{Enabled: new(true)}
	})
	lister = &fakeLister{pages: map[string][][]*armcompute.Snapshot{"rg-a": {{snapADE}}}}
	got, err = New(lister, fakeDisks{}, Config{}).ListReusable(context.Background(), diskscan.VolumeRef{VolumeID: diskID})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.True(t, got[0].Encrypted)
}

func TestListReusable_Errors(t *testing.T) {
	cases := []struct {
		name   string
		vol    string
		disks  DiskGetter
		failAt map[string]int
	}{
		{"unparseable volume id", "not-an-arm-id", fakeDisks{}, nil},
		{"disk unreadable", diskID, fakeDisks{err: errors.New("denied")}, nil},
		{"first page fails", diskID, fakeDisks{}, map[string]int{"rg-a": 0}},
		{"second page fails", diskID, fakeDisks{}, map[string]int{"rg-a": 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lister := &fakeLister{failAt: tc.failAt, pages: map[string][][]*armcompute.Snapshot{"rg-a": {
				{snapOf("a", diskID, time.Hour, nil)}, {snapOf("b", diskID, time.Hour, nil)},
			}}}
			got, err := New(lister, tc.disks, Config{}).ListReusable(context.Background(), diskscan.VolumeRef{VolumeID: tc.vol})
			require.Error(t, err)
			assert.Nil(t, got, "a failed listing must not look like a partial result")
		})
	}
}

type fakeDiffer struct {
	extents       []diskscan.Extent
	err           error
	nextURL, base string
	calls         int
}

func (f *fakeDiffer) changedRanges(_ context.Context, nextURL, baseURL string) ([]diskscan.Extent, error) {
	f.calls++
	f.nextURL, f.base = nextURL, baseURL
	return f.extents, f.err
}

func TestChanged(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := diskscan.Snapshot{ID: "base", VolumeID: diskID, CreatedAt: t0}
	next := diskscan.Snapshot{ID: "next", VolumeID: diskID, CreatedAt: t0.Add(time.Hour)}
	access := ReadAccessFunc(func(_ context.Context, s diskscan.Snapshot) (string, error) { return "https://sas/" + s.ID, nil })
	want := []diskscan.Extent{{Offset: 0, Length: 512}}

	cases := []struct {
		name       string
		base, next diskscan.Snapshot
		differ     *fakeDiffer
		access     ReadAccess
		wantErr    error
		wantAnyErr bool
		wantCalls  int
	}{
		{"ok", base, next, &fakeDiffer{extents: want}, access, nil, false, 1},
		{"different disks", base, diskscan.Snapshot{ID: "n", VolumeID: diskID + "x", CreatedAt: next.CreatedAt}, &fakeDiffer{}, access, diskscan.ErrNoDiff, false, 0},
		{"reversed order", next, base, &fakeDiffer{}, access, diskscan.ErrNoDiff, false, 0},
		{"missing id", diskscan.Snapshot{VolumeID: diskID, CreatedAt: t0}, next, &fakeDiffer{}, access, diskscan.ErrNoDiff, false, 0},
		{"service refuses diff", base, next, &fakeDiffer{err: fmt.Errorf("x: %w", diskscan.ErrNoDiff)}, access, diskscan.ErrNoDiff, false, 1},
		{"service error", base, next, &fakeDiffer{err: errors.New("boom")}, access, nil, true, 1},
		{"no access configured", base, next, &fakeDiffer{}, nil, nil, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(nil, nil, Config{Access: tc.access, HTTP: loopbackClient(t)})
			p.differ = tc.differ
			got, err := p.Changed(context.Background(), tc.base, tc.next)
			assert.Equal(t, tc.wantCalls, tc.differ.calls)
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
			case tc.wantAnyErr:
				require.Error(t, err)
				assert.NotErrorIs(t, err, diskscan.ErrNoDiff)
			default:
				require.NoError(t, err)
				assert.Equal(t, want, got)
				assert.Equal(t, "https://sas/next", tc.differ.nextURL)
				assert.Equal(t, "https://sas/base", tc.differ.base)
			}
		})
	}
}

const pageDiffXML = `<?xml version="1.0" encoding="utf-8"?>
<PageList>%s</PageList>`

func TestBlobDiffer(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		want       []diskscan.Extent
		wantNoDiff bool
		wantErr    bool
	}{
		{
			name: "page and clear ranges become extents", status: http.StatusOK,
			body: `<PageRange><Start>0</Start><End>511</End></PageRange><ClearRange><Start>1024</Start><End>2047</End></ClearRange>`,
			want: []diskscan.Extent{{Offset: 0, Length: 512}, {Offset: 1024, Length: 1024}},
		},
		{name: "no changes", status: http.StatusOK, body: ``},
		{name: "bad request means no diff", status: http.StatusBadRequest, wantNoDiff: true},
		{name: "conflict means no diff", status: http.StatusConflict, wantNoDiff: true},
		{name: "forbidden is a plain error", status: http.StatusForbidden, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var prev string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				prev = r.Header.Get("x-ms-previous-snapshot-url")
				if tc.status != http.StatusOK {
					w.Header().Set("x-ms-error-code", "Err")
					w.WriteHeader(tc.status)
					return
				}
				w.Header().Set("Content-Type", "application/xml")
				_, _ = fmt.Fprintf(w, pageDiffXML, tc.body)
			}))
			t.Cleanup(ts.Close)

			got, err := blobDiffer{client: loopbackClient(t)}.changedRanges(context.Background(), ts.URL+"/d?sig=SECRET", "https://base/d?sig=B")
			switch {
			case tc.wantNoDiff:
				require.ErrorIs(t, err, diskscan.ErrNoDiff)
			case tc.wantErr:
				require.Error(t, err)
				assert.NotErrorIs(t, err, diskscan.ErrNoDiff)
				assert.NotContains(t, err.Error(), "SECRET")
			default:
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
				assert.Equal(t, "https://base/d?sig=B", prev)
			}
		})
	}
}
