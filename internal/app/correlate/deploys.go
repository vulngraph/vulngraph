package correlate

import (
	"iter"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// DeploysTo links a github_repo to the k8s workloads it ships, the supply-chain
// lineage that lets the reasoner say "this workload came from org/payments-api,
// an owned prod repo" rather than treating it as origin-less. Two
// match strengths, recorded on the edge so the reasoner can weigh them:
//
//   - high   — a container image is ghcr.io/<org>/<repo>..., which IS the repo's
//     full name; an exact identity match, not a guess.
//   - medium — the workload's app.kubernetes.io/name or part-of label matches a
//     repo's short name; a strong convention, but names can collide.
//
// Cloud-registry images (ECR/GCR) are not matched here — their repo name rarely
// equals the GitHub repo, so a name match would be low-confidence noise. They
// land if/when an image→repo mapping exists.
type DeploysTo struct{}

func (DeploysTo) Name() string { return "deploys_to" }

func (DeploysTo) InterestedIn() []string {
	return []string{
		"github_repo",
		"k8s_pod", "k8s_deployment",
		"ecs_service", "lambda_function", "cloud_function",
		"cloudrun_service", "azure_webapp", "azure_function",
	}
}

func (r DeploysTo) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (DeploysTo) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {

		for _, w := range g.Workloads() {
			// One repo links to a workload at most once, and a high-confidence image
			// match wins over a medium-confidence label match for the same repo.
			seen := map[string]bool{}

			for _, img := range splitValues(w.Metadata["images"]) {
				// High confidence: ghcr.io/org/repo — namespace IS the GitHub full name.
				if full, ok := ghcrRepo(img); ok {
					if repo, ok := g.RepoByFullName(full); ok && !seen[repo.ID] {
						seen[repo.ID] = true
						if !yield(deploysEdge(repo, w, "ghcr_image", "high")) {
							return
						}
					}
					continue
				}
				// Medium confidence: GCR/ECR — extract the image name (last path segment
				// before the tag/digest) and match it against known repo short names.
				// Covers eu.gcr.io/<project>/<service>[:tag] where <service> == repo short name.
				if name := cloudImageName(img); name != "" {
					for _, repo := range g.ReposByName(name) {
						if seen[repo.ID] {
							continue
						}
						seen[repo.ID] = true
						if !yield(deploysEdge(repo, w, imageMatchVia(repo, name), "medium")) {
							return
						}
					}
				}
			}

			// Medium confidence: standard k8s app labels. Add your own org's service-
			// registry label here too if you have one (e.g. "example.com/service-name") —
			// it's an additional signal alongside these, not a replacement for them.
			for _, label := range []string{
				"app.kubernetes.io/name",
				"app.kubernetes.io/part-of",
			} {
				name := w.Tags[label]
				if name == "" {
					continue
				}
				for _, repo := range g.ReposByName(name) {
					if seen[repo.ID] {
						continue
					}
					seen[repo.ID] = true
					if !yield(deploysEdge(repo, w, "label", "medium")) {
						return
					}
				}
			}
		}
		// Compute services (ECS, Lambda, Cloud Run, Azure Web Apps):
		// match by service/function name = repo short name. No image metadata
		// available for most; name is the only reliable signal.
		for _, svc := range g.ComputeServices() {
			seen := map[string]bool{}
			for _, repo := range g.ReposByName(svc.Name) {
				if seen[repo.ID] {
					continue
				}
				seen[repo.ID] = true
				if !yield(deploysEdge(repo, svc, "service_name", "medium")) {
					return
				}
			}
		}

	}
}

// imageMatchVia records HOW a cloud-registry image name matched a repo, so the
// reasoner can tell an exact short-name hit from one that only landed after the
// "<domain>_" ownership prefix was stripped (see
// correlate.repoNameWithoutDomainPrefix). Both are medium confidence — a name
// match is a convention either way — but they are not the same evidence, and
// flattening them would hide which convention the estate actually follows.
func imageMatchVia(repo asset.Asset, matchedName string) string {
	if strings.EqualFold(repoShortName(repo.ID), matchedName) {
		return "gcr_image"
	}
	return "gcr_image_domain_prefix"
}

func deploysEdge(repo, workload asset.Asset, via, confidence string) asset.Edge {
	return asset.Edge{
		SrcID: repo.ID, SrcType: "github_repo",
		DstID: workload.ID, DstType: workload.Type,
		EdgeType: EdgeDeploysTo,
		Properties: map[string]string{
			"origin":      edgeOrigin,
			"rule":        "deploys_to",
			"matched_via": via,
			"confidence":  confidence,
		},
	}
}

// cloudImageName extracts the service name from a cloud registry image
// (eu.gcr.io/<project>/<service>[:tag], ECR, etc.) as the last non-empty path
// segment before any tag or digest. Returns "" for GHCR images (handled by
// ghcrRepo) or images with no recognisable service segment.
func cloudImageName(image string) string {
	// Skip GHCR — handled by ghcrRepo with higher confidence.
	if strings.HasPrefix(image, "ghcr.io/") {
		return ""
	}
	// Must look like a registry reference (contains at least one /).
	if !strings.Contains(image, "/") {
		return ""
	}
	// Strip digest first, then tag.
	ref := image
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndexByte(ref, ':'); i >= 0 {
		// Only strip the tag if it's in the last segment (not a host:port).
		if strings.LastIndexByte(ref[:i], '/') >= 0 {
			ref = ref[:i]
		}
	}
	segs := strings.Split(ref, "/")
	// Last segment is the image/service name; must be non-empty.
	name := segs[len(segs)-1]
	if name == "" || name == "." {
		return ""
	}
	return name
}

// ghcrRepo extracts the "org/repo" GitHub full name from a GitHub Container
// Registry image reference (ghcr.io/org/repo[/path][:tag|@digest]), if it is
// one. ghcr images are namespaced by the owning org/repo, so the first two path
// segments are exactly the repo's full name.
func ghcrRepo(image string) (string, bool) {
	const prefix = "ghcr.io/"
	if !strings.HasPrefix(image, prefix) {
		return "", false
	}
	path := image[len(prefix):]
	if i := strings.IndexByte(path, '@'); i >= 0 {
		path = path[:i]
	}
	if i := strings.IndexByte(path, ':'); i >= 0 {
		path = path[:i]
	}
	segs := strings.Split(path, "/")
	if len(segs) < 2 || segs[0] == "" || segs[1] == "" {
		return "", false
	}
	return segs[0] + "/" + segs[1], true
}
