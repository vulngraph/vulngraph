package demo

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

const (
	gatewayImage  = accountID + ".dkr.ecr." + region + ".amazonaws.com/ai-gateway:2.4.1"
	gatewayDigest = "sha256:9f2b6c1d0e7a43b8a5c2d1f0e9b8a7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0"
	botImage      = accountID + ".dkr.ecr." + region + ".amazonaws.com/support-bot:1.9.0"
	botDigest     = "sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
	repoName      = "acme-corp/ai-gateway"
)

func pypi(name, version string) pkginventory.InstalledPackage {
	return pkginventory.InstalledPackage{Ecosystem: "PyPI", Name: name, Version: version}
}

// litellmVersion is inside the range OSV lists for CVE-2026-40217 (1.81.8 up to,
// not including, 1.83.10), a remote code execution in LiteLLM that CISA lists as
// exploited. Both services pin it; only the gateway faces the internet.
const litellmVersion = "1.83.0"

// services adds the two containerised services, the images they run and the
// repository the gateway is built from. Both run the same LiteLLM; only the
// gateway faces the internet.
func (b *builder) services() {
	b.add(asset.Asset{
		ID: repoName, Name: repoName, Type: "github_repo", Provider: asset.ProviderGitHub, Region: "global",
		Metadata: map[string]string{"full_name": repoName, "visibility": "private", "default_branch": "main"},
	})
	b.service("ai-gateway", roleGateway, gatewayImage, gatewayDigest, true,
		[]pkginventory.InstalledPackage{pypi("litellm", litellmVersion)})
	b.service("support-bot", roleSupportBot, botImage, botDigest, false,
		[]pkginventory.InstalledPackage{pypi("litellm", litellmVersion)})
}

func (b *builder) service(name, role, ref, digest string, public bool, pkgs []pkginventory.InstalledPackage) {
	id := arn("ecs", "service/acme-prod/"+name)
	meta := map[string]string{
		"cluster": "acme-prod", "exec_role": role, "images": ref, "launch_type": "FARGATE",
		"desired_count": "2", "network_mode": "awsvpc",
	}
	if public {
		meta["public"] = "true"
	}
	b.add(asset.Asset{ID: id, Name: name, Type: "ecs_service", Provider: asset.ProviderAWS, Region: region, Metadata: meta})

	img := collect.RunningImage{Ref: ref, Digest: digest}
	b.add(collect.ImageAsset(img, asset.ProviderAWS, region, accountID, b.now))
	b.edges = append(b.edges, collect.RunsImageEdge(id, "ecs_service", img))
	pkgAssets, pkgEdges := pkginventory.InventoryGraph(collect.ImageAssetID(digest), "container_image", pkgs, b.now)
	b.assets = append(b.assets, pkgAssets...)
	b.edges = append(b.edges, pkgEdges...)
}
