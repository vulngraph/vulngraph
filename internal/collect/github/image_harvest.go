package github

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// harvestMaxImagesPerRepo bounds how many distinct image paths one repo may
// contribute. A repo that references more than this is a registry mirror
// manifest or a generated lock file, not a service that ships an image.
const harvestMaxImagesPerRepo = 100

// privateRegistryImageRE matches a container image reference on a registry that
// only an owner can push to — GCR, Artifact Registry, GHCR, ECR, ACR. Public
// registries (docker.io, quay.io, k8s.gcr.io) are deliberately absent: a repo
// naming docker.io/library/redis says nothing about who built it.
//
// The path class stops at ':' and '@', so the tag/digest is never part of the
// match and the result is already the tag-free image path. The deployed
// image ref is typically written verbatim in the building repo's own files
// (Helm values files, CI config, Dockerfile), and resolves to exactly one repo.
var privateRegistryImageRE = regexp.MustCompile(`(?i)\b(?:` +
	`(?:[a-z0-9-]+\.)?gcr\.io` + // gcr.io, eu.gcr.io, asia.gcr.io
	`|[a-z0-9-]+-docker\.pkg\.dev` + // europe-docker.pkg.dev
	`|ghcr\.io` +
	`|[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com` +
	`|[a-z0-9]+\.azurecr\.io` +
	`)(?:/[a-z0-9._-]+)+`)

// HarvestImageRefs returns the distinct private-registry image paths written in
// one file's bytes, lowercased and tag-free.
//
// It answers the question no other signal in the graph could: which repo
// built the image a pod is running. Images carry no reliable build
// provenance to join on (org.opencontainers.image.source/.revision are
// rarely set by first-party builds, and there's no build-occurrence record) —
// what IS reliable is that the repo names the image it pushes.
func HarvestImageRefs(content []byte) []string {
	matches := privateRegistryImageRE.FindAll(content, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		img := asset.NormalizeImageRef(string(m))
		// One path segment after the host is a registry root or a truncated
		// template ("eu.gcr.io/{{ .Values.project }}/x" matches only the head),
		// never a real image.
		if strings.Count(img, "/") < 2 || seen[img] {
			continue
		}
		seen[img] = true
		out = append(out, img)
	}
	sort.Strings(out)
	return out
}

// projectDeclaredImageBuilds turns the image paths harvested from one repo into
// declared_image_build assets. Emits NO edges: the join to the live
// container_image happens in the ImageOwnership correlate rule, the same
// collector-supplies / correlate-joins split every other IaC slice uses.
//
// Deduped by image, not by (image, path): one repo often writes the same image
// ref in several per-environment values files, and one evidence row per file
// would multiply the asset count for a "which file" answer that carries no
// extra signal here. The first path in sorted order is kept as the evidence.
func projectDeclaredImageBuilds(byImage map[string]string, repo string, now time.Time) []asset.Asset {
	if len(byImage) == 0 {
		return nil
	}
	images := make([]string, 0, len(byImage))
	for img := range byImage {
		images = append(images, img)
	}
	sort.Strings(images)
	if len(images) > harvestMaxImagesPerRepo {
		images = images[:harvestMaxImagesPerRepo]
	}

	assets := make([]asset.Asset, 0, len(images))
	for _, img := range images {
		assets = append(assets, asset.Asset{
			ID:           "declared_image_build:" + repo + ":" + img,
			Name:         img,
			Type:         "declared_image_build",
			DiscoveredAt: now,
			LastSeen:     now,
			Metadata: map[string]string{
				"repo":  repo,
				"path":  byImage[img],
				"image": img,
			},
		})
	}
	return assets
}
