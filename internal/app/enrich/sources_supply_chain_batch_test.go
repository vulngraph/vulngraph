package enrich

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type countedLineage struct {
	fakeLineage
	imageReads int
	imageIDs   int
	err        error
}

func (f *countedLineage) LineageSources(ctx context.Context, ids []string, typ string, limit int) ([]asset.Edge, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	if typ == "runs_image" {
		f.imageReads++
		f.imageIDs += len(ids)
	}
	return f.fakeLineage.LineageSources(ctx, ids, typ, limit)
}

func TestSupplyChainBatchesImagesAndDeduplicatesWorkloads(t *testing.T) {
	g := &countedLineage{fakeLineage: fakeLineage{into: map[string][]asset.Edge{}, from: map[string][]asset.Edge{}}}
	pkg := pkgFinding().ResourceID
	for i := range maxSupplyChainImages {
		img := fmt.Sprintf("image-%03d", i)
		g.into[pkg] = append(g.into[pkg], asset.Edge{SrcID: img, SrcType: "container_image", DstID: pkg, EdgeType: "runs_package"})
		g.into[img] = []asset.Edge{{SrcID: "shared-pod", DstID: img, EdgeType: "runs_image"}}
		if i == maxSupplyChainImages-1 {
			g.into[img] = append(g.into[img], asset.Edge{SrcID: "public-pod", DstID: img, EdgeType: "runs_image"})
		}
	}
	g.from["public-pod"] = []asset.Edge{{SrcID: "public-pod", DstID: "internet", EdgeType: "exposed_to_internet"}}
	deployed, exposed, truncated, err := (SupplyChainExposure{Graph: g}).PackageDeployExposure(context.Background(), pkg)
	require.NoError(t, err)
	require.True(t, deployed)
	require.True(t, exposed, "the last image's distinct workload must be visited")
	require.False(t, truncated, "duplicate shared workloads must not consume the cap")
	require.Equal(t, 1, g.imageReads)
	require.Equal(t, maxSupplyChainImages, g.imageIDs)
	g.err = context.DeadlineExceeded
	_, _, _, err = (SupplyChainExposure{Graph: g}).PackageDeployExposure(context.Background(), pkg)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestSupplyChainPossibleExposureIsNotConfirmed(t *testing.T) {
	g := fakeLineage{from: map[string][]asset.Edge{"vm": {{SrcID: "vm", DstID: "internet", EdgeType: "exposed_to_internet", Properties: map[string]string{asset.EdgePropPublicAccess: asset.PublicAccessPossible}}}}}
	exposed, unknown, err := (SupplyChainExposure{Graph: g}).workloadExposure(context.Background(), []string{"vm"})
	require.NoError(t, err)
	require.False(t, exposed)
	require.True(t, unknown)
}

func TestTruncatedRunnersCannotSuppressPackageAlert(t *testing.T) {
	pkg := pkgFinding()
	g := manyVMs(pkg.ResourceID, maxSupplyChainImages+maxSupplyChainVMs+1)
	s := SupplyChainExposure{Graph: g, Fleets: fakeFleetLister{}}
	r, err := s.runnersOf(context.Background(), pkg.ResourceID)
	require.NoError(t, err)
	require.True(t, r.truncated)
	canonical, _, err := s.fleetCovers(context.Background(), pkg, r)
	require.NoError(t, err)
	require.False(t, canonical)
	carrier, err := s.AlertCarrier(context.Background(), pkg, BandPage)
	require.NoError(t, err)
	require.Empty(t, carrier)
}
