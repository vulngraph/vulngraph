package asset

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// countingRepo counts LivePackageIDs reads, so a test can prove the live set
// is read once per pass rather than once per page.
type countingRepo struct {
	*fakeRepo
	liveReads int
	pageErrAt int // fail the Nth page read (1-based); 0 never
	pages     int
}

func (c *countingRepo) LivePackageIDs(ctx context.Context) (map[string]bool, error) {
	c.liveReads++
	return c.fakeRepo.LivePackageIDs(ctx)
}

func (c *countingRepo) PackageCoordsAfter(ctx context.Context, after string) ([]PackageCoord, string, error) {
	c.pages++
	if c.pages == c.pageErrAt {
		return nil, "", errors.New("clickhouse: timeout")
	}
	return c.fakeRepo.PackageCoordsAfter(ctx, after)
}

func packageRepo(n, live, pageSize int) *countingRepo {
	f := &fakeRepo{assets: map[string]Asset{}, livePackages: map[string]bool{}, packagePageSize: pageSize}
	for i := range n {
		id := fmt.Sprintf("pkg:npm/p%03d@1.0.0", i)
		f.assets[id] = Asset{ID: id, Type: "package", Metadata: map[string]string{"ecosystem": "npm"}}
		if i < live {
			f.livePackages[id] = true
		}
	}
	f.assets["i-1"] = Asset{ID: "i-1", Type: "ec2_instance"}
	return &countingRepo{fakeRepo: f}
}

func TestScanLivePackages_ReadsLiveSetOnceAndWalksEveryPage(t *testing.T) {
	repo := packageRepo(25, 20, 4)
	var got []string
	scan, err := NewService(repo).ScanLivePackages(context.Background(), func(page []PackageCoord) error {
		for _, c := range page {
			got = append(got, c.ID)
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, repo.liveReads, "the live set is read once per pass, never per page")
	require.Equal(t, 20, len(scan.LiveIDs))
	require.False(t, scan.ListedAt.IsZero())
	require.Len(t, got, 20, "every live package is listed exactly once; dead rows are dropped")
	seen := map[string]bool{}
	for _, id := range got {
		require.False(t, seen[id], "listed twice: %s", id)
		seen[id] = true
		require.True(t, repo.livePackages[id])
	}
}

func TestScanLivePackages_PageErrorAbortsPass(t *testing.T) {
	repo := packageRepo(25, 25, 4)
	repo.pageErrAt = 3
	_, err := NewService(repo).ScanLivePackages(context.Background(), func([]PackageCoord) error { return nil })
	require.Error(t, err, "a partial walk must fail the pass, never read as a complete smaller inventory")
}

func TestScanLivePackages_EmptyLiveSetListsNothing(t *testing.T) {
	repo := packageRepo(5, 0, 4)
	calls := 0
	scan, err := NewService(repo).ScanLivePackages(context.Background(), func([]PackageCoord) error { calls++; return nil })
	require.NoError(t, err)
	require.Zero(t, len(scan.LiveIDs))
	require.Zero(t, calls)
}
