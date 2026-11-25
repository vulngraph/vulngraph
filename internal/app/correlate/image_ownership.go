package correlate

import (
	"sort"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// ImageOwnership joins declared_image_build intermediates (private-registry
// image paths harvested from repo text by the GitHub collector) to the LIVE
// container_image assets running in the clusters, and emits
// (container_image)-[:defined_in]->(github_repo).
//
// This closes a break in the supply-chain chain. A pod's packages are
// reachable — k8s_pod -runs_image-> container_image -runs_package-> package —
// and a repo's dependencies are reachable — github_repo -depends_on-> package —
// but the two package sets do not intersect: image scanning yields OS packages
// (deb/apk) while SBOMs yield language packages (npm/golang/pypi/gem). With this
// edge the chain joins up at the image instead:
//
//	k8s_pod -runs_image-> container_image -defined_in-> github_repo -depends_on-> package
//
// The join is a text-harvested reference rather than something stronger because
// OCI labels, registry build provenance, and name equality are all unreliable
// in practice; what IS reliable is that the repo names the image it pushes — in
// helm values.yaml, .gitlab-ci.yml, or workflow YAML — and those files are
// already fetched by the repo harvest, so this edge costs no additional GitHub
// API call.
//
// Confidence records the ambiguity honestly: "high" when exactly one repo in the
// whole graph declares that image path, "medium" when several do (a shared
// deploy-config repo also naming it).
type ImageOwnership struct{}

func (ImageOwnership) Name() string { return "image_ownership" }

func (ImageOwnership) InterestedIn() []string {
	return []string{"declared_image_build", "container_image"}
}

func (ImageOwnership) Correlate(g Graph) []asset.Edge {
	// declarers[image] = repo asset IDs declaring it, deduped and sorted so the
	// confidence verdict and the edge order are the same on every rebuild.
	declarers := map[string]map[string]bool{}
	for _, d := range g.DeclaredImageBuilds() {
		img := asset.NormalizeImageRef(d.Metadata["image"])
		repoID := d.Metadata["repo"]
		if img == "" || repoID == "" {
			continue
		}
		if declarers[img] == nil {
			declarers[img] = map[string]bool{}
		}
		declarers[img][repoID] = true
	}

	var edges []asset.Edge
	for _, d := range g.DeclaredImageBuilds() {
		img := asset.NormalizeImageRef(d.Metadata["image"])
		if img == "" {
			continue
		}
		images := g.ContainerImagesByPath(img)
		if len(images) == 0 {
			// Declared but not running: no live node to anchor the edge to.
			continue
		}
		repo, ok := g.RepoByFullName(d.Metadata["repo"])
		if !ok {
			continue
		}
		confidence := "high"
		if len(declarers[img]) > 1 {
			confidence = "medium"
		}
		for _, live := range images {
			edges = append(edges, asset.Edge{
				SrcID: live.ID, SrcType: "container_image",
				DstID: repo.ID, DstType: "github_repo",
				EdgeType: EdgeDefinedIn,
				Properties: map[string]string{
					"origin":     edgeOrigin,
					"rule":       "image_ownership",
					"confidence": confidence,
					"provenance": "image_ref",
					"path":       d.Metadata["path"],
					"image":      img,
				},
			})
		}
	}

	// One declaration per (repo, image) already, but two repos declaring the
	// same image legitimately produce two edges into the same live image — sort
	// so the emitted order is stable regardless of asset scan order.
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].SrcID != edges[j].SrcID {
			return edges[i].SrcID < edges[j].SrcID
		}
		return edges[i].DstID < edges[j].DstID
	})
	return edges
}
