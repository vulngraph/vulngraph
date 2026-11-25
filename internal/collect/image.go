package collect

import (
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// RunningImage is one resolved container image a workload is running: the
// registry/repo reference it was pulled from (tag kept, digest stripped) and
// the content digest ("sha256:<hex>") it resolved to.
type RunningImage struct {
	Ref    string
	Digest string
}

// ImageAssetID is the container_image asset id for a digest. Every collector
// that sees a running image MUST key it here, so the same digest run by a k8s
// pod, an ECS task and a Cloud Run revision is ONE node — the imagevuln sweep
// scans it once and its runs_package edges reach every workload running it.
func ImageAssetID(digest string) string {
	return "image/" + digest
}

// ParseImageDigest splits an image reference that may carry a digest
// ("registry/repo[:tag]@sha256:<hex>") into the pull reference and digest.
// fallbackRef supplies the reference when s is a bare digest ("sha256:<hex>"),
// as the ECS and Cloud Run APIs report it. ok is false when no sha256 digest
// is present at all: a tag alone is mutable and is not an image identity.
func ParseImageDigest(s, fallbackRef string) (RunningImage, bool) {
	s = strings.TrimSpace(s)
	at := strings.LastIndex(s, "@sha256:")
	switch {
	case at >= 0:
		ref := s[:at]
		// The digest-carrying form never repeats the tag; keep the declared tag
		// when the fallback names the same repo, so the display name stays useful.
		if tag := imageTag(fallbackRef); tag != "" && asset.NormalizeImageRef(fallbackRef) == strings.ToLower(ref) {
			ref += ":" + tag
		}
		return RunningImage{Ref: ref, Digest: s[at+1:]}, true
	case strings.HasPrefix(s, "sha256:"):
		ref := strings.TrimSpace(fallbackRef)
		if i := strings.Index(ref, "@"); i >= 0 {
			ref = ref[:i]
		}
		return RunningImage{Ref: ref, Digest: s}, true
	}
	return RunningImage{}, false
}

// imageTag returns the tag of ref ("registry[:port]/repo:tag"), or "" — a colon
// is a tag separator only after the last '/'.
func imageTag(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[colon+1:]
	}
	return ""
}

// ImageAsset builds the container_image asset for img. image_ref and image_id
// are the two keys the imagevuln sweep reads to pull and scan the image.
func ImageAsset(img RunningImage, provider asset.Provider, region, accountID string, now time.Time) asset.Asset {
	name := img.Ref
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
	return asset.Asset{
		ID:        ImageAssetID(img.Digest),
		Name:      name,
		Type:      "container_image",
		Provider:  provider,
		Region:    region,
		AccountID: accountID,
		Metadata: map[string]string{
			"image_ref": img.Ref,
			"image_id":  img.Digest,
		},
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// RunsImageEdge is the workload → container_image edge the supply-chain chain
// walks (package ← runs_package ← container_image ← runs_image ← workload).
func RunsImageEdge(srcID, srcType string, img RunningImage) asset.Edge {
	return asset.Edge{
		SrcID: srcID, SrcType: srcType,
		DstID:      ImageAssetID(img.Digest),
		DstType:    "container_image",
		EdgeType:   "runs_image",
		Properties: map[string]string{"image_ref": img.Ref},
	}
}
