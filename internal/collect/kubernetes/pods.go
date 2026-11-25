package kubernetes

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

// This file holds the Pod-level asset mapping: podAsset (with its
// security-context aggregation and the container/container_image assets it
// derives from a single Pod) plus the two small helpers it depends on,
// imageTag and podOwner. workloads.go next to it covers the
// four controller kinds (Deployment/StatefulSet/DaemonSet/Job), so this file
// is the pod/container/image half of the same "map a k8s object to assets"
// family.

func podAsset(pod corev1.Pod, cluster string, now time.Time) (asset.Asset, []asset.Asset, []asset.Edge) {
	id := fmt.Sprintf("%s/pod/%s/%s", cluster, pod.Namespace, pod.Name)
	var images []string
	for _, c := range pod.Spec.Containers {
		images = append(images, c.Image)
	}
	// Security context signals for RBAC/privilege checks.
	privileged := false
	hostNetwork := false
	hostPID := false

	// runAsRoot: true when any container has no runAsNonRoot enforcement and
	// no explicit non-zero UID — i.e. could run as root by default.
	runAsRoot := false
	// allowPrivEsc: true when any container allows privilege escalation.
	// K8s default is true when allowPrivilegeEscalation is unset.
	allowPrivEsc := false
	// hasResourceLimits: false when any container lacks cpu OR memory limits.
	// OOMKilled containers and runaway CPU consumers both stem from missing limits.
	hasResourceLimits := true

	psc := pod.Spec.SecurityContext
	hostNetwork = pod.Spec.HostNetwork
	hostPID = pod.Spec.HostPID

	// Init containers run BEFORE the app containers and are routinely the most
	// privileged thing in the pod (sysctl tuning, volume chown, CNI setup), so
	// excluding them from the security-context signals below would be a false
	// negative across the privileged / run_as_root / allow_priv_escalation
	// / dangerous_capabilities checks. They are part of the same pod, run with
	// the same service account on the same node, so they aggregate identically.
	//
	// Only the security-context aggregation folds them in: images and resource
	// limits stay app-container-only, since init containers are short-lived and
	// their images are not what the pod is running when a finding lands.
	securityContexts := make([]corev1.Container, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	securityContexts = append(securityContexts, pod.Spec.InitContainers...)
	securityContexts = append(securityContexts, pod.Spec.Containers...)

	for _, c := range securityContexts {
		csc := c.SecurityContext

		if csc != nil {
			if csc.Privileged != nil && *csc.Privileged {
				privileged = true
			}
		}

		// runAsNonRoot: check pod-level then container-level (container wins)
		runAsNonRoot := false
		if psc != nil && psc.RunAsNonRoot != nil {
			runAsNonRoot = *psc.RunAsNonRoot
		}
		if csc != nil && csc.RunAsNonRoot != nil {
			runAsNonRoot = *csc.RunAsNonRoot
		}
		// runAsUser: 0 or unset → could be root
		runAsUser := int64(-1)
		if psc != nil && psc.RunAsUser != nil {
			runAsUser = *psc.RunAsUser
		}
		if csc != nil && csc.RunAsUser != nil {
			runAsUser = *csc.RunAsUser
		}
		if !runAsNonRoot && (runAsUser < 0 || runAsUser == 0) {
			runAsRoot = true
		}

		// allowPrivilegeEscalation defaults to true when unset
		ape := true
		if csc != nil && csc.AllowPrivilegeEscalation != nil {
			ape = *csc.AllowPrivilegeEscalation
		}
		if ape {
			allowPrivEsc = true
		}
	}

	// Resource limits: missing cpu OR memory limit = flag the whole pod. App
	// containers only — an init container runs to completion in seconds and its
	// limits are not what causes a steady-state OOMKill or CPU runaway.
	for _, c := range pod.Spec.Containers {
		lim := c.Resources.Limits
		if lim.Cpu().IsZero() || lim.Memory().IsZero() {
			hasResourceLimits = false
		}
	}

	// IRSA (IAM Roles for Service Accounts): the pod annotation carries the AWS
	// IAM role ARN the workload runs as. Set exec_role so the ExecutesAs correlate
	// rule creates the pod→IAM_role edge, enabling blast radius through the role.
	// GKE Workload Identity uses a different annotation but the same principle.
	irsaRole := pod.Annotations["eks.amazonaws.com/role-arn"] // AWS EKS IRSA
	if irsaRole == "" {
		irsaRole = pod.Annotations["iam.gke.io/service-account"] // GKE Workload Identity
	}

	meta := map[string]string{
		"namespace":             pod.Namespace,
		"phase":                 string(pod.Status.Phase),
		"node":                  pod.Spec.NodeName,
		"images":                strings.Join(images, ","),
		"service_account":       pod.Spec.ServiceAccountName,
		"privileged":            fmt.Sprintf("%t", privileged),
		"host_network":          fmt.Sprintf("%t", hostNetwork),
		"host_pid":              fmt.Sprintf("%t", hostPID),
		"run_as_root":           fmt.Sprintf("%t", runAsRoot),
		"allow_priv_escalation": fmt.Sprintf("%t", allowPrivEsc),
		"has_resource_limits":   fmt.Sprintf("%t", hasResourceLimits),
		// Whether the pod spec itself decides token automounting. When it does
		// not, the ServiceAccount's own setting does, which podAsset cannot see:
		// the collector resolves automount_sa_token from it (resolveAutomount).
		"automount_sa_token_set_on_pod": fmt.Sprintf("%t", pod.Spec.AutomountServiceAccountToken != nil),
	}
	if pod.Spec.AutomountServiceAccountToken != nil {
		meta["automount_sa_token"] = fmt.Sprintf("%t", *pod.Spec.AutomountServiceAccountToken)
	}
	maps.Copy(meta, podHardeningSignals(pod))
	if irsaRole != "" {
		meta["exec_role"] = irsaRole // triggers ExecutesAs edge in correlate
	}
	// Owner workload identity: pods are ephemeral replicas, so per-pod findings
	// aggregate to the owning workload (checks.Registry collapses on these keys).
	if kind, name, ok := podOwner(pod); ok {
		meta["owner_kind"] = kind
		meta["owner_name"] = name
	}

	a := asset.Asset{
		ID:           id,
		Name:         pod.Name,
		Type:         "k8s_pod",
		Provider:     asset.ProviderKubernetes,
		Region:       cluster,
		Tags:         pod.Labels,
		Metadata:     meta,
		DiscoveredAt: now, LastSeen: now,
	}
	edges := []asset.Edge{{
		SrcID: id, SrcType: "k8s_pod",
		DstID:    fmt.Sprintf("%s/namespace/%s", cluster, pod.Namespace),
		DstType:  "k8s_namespace",
		EdgeType: "runs_in",
	}}

	// Emit a container asset + runs_container edge per pod.Spec.Containers entry.
	// spec.containers[] is already fetched as part of the pod object (no extra
	// API call), it's just not promoted to a graph node today — so a GuardDuty
	// container-level finding (ContainerDetails) can never join to an asset and
	// gets zero graph context (attack-path scoring, must-fix, reachability,
	// lifecycle sweep all skip it). ID keys on container NAME (stable across pod
	// restarts within the same spec), not the ephemeral runtime container ID.
	var containerAssets []asset.Asset
	for _, c := range pod.Spec.Containers {
		containerID := fmt.Sprintf("%s/container/%s", id, c.Name)
		containerAssets = append(containerAssets, asset.Asset{
			ID:       containerID,
			Name:     c.Name,
			Type:     "container",
			Provider: asset.ProviderKubernetes,
			Region:   cluster,
			Metadata: map[string]string{
				"namespace": pod.Namespace,
				"pod":       pod.Name,
				"image":     c.Image,
			},
			DiscoveredAt: now, LastSeen: now,
		})
		edges = append(edges, asset.Edge{
			SrcID: id, SrcType: "k8s_pod",
			DstID:    containerID,
			DstType:  "container",
			EdgeType: "runs_container",
		})
	}

	// Emit container_image assets and pod→image edges.
	// ContainerStatuses carries the resolved ImageID (sha256 digest) — stable
	// across restarts and uniquely identifies the exact image layer.
	var imageAssets []asset.Asset
	imageIDs := make(map[string]string) // sha256 digest → image ref
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.ImageID == "" {
			continue
		}
		// ImageID formats: "docker-pullable://registry/repo@sha256:hex" (docker),
		// "registry/repo@sha256:hex" (containerd, no docker-pullable:// prefix),
		// or bare "sha256:hex". The first two carry the registry/repo the image
		// actually resolved to; cs.Image (the pod-spec string) is sometimes
		// already bare — no registry host — because that's how the workload was
		// written. imagevuln's pullReference builds repo+"@"+digest straight from
		// this ref, so a bare ref there resolves against the wrong default
		// registry (Docker Hub) instead of wherever the image actually runs, not
		// merely a cosmetic gap. Prefer ImageID's registry/repo when it has one —
		// but SPLICE it onto cs.Image's tag, don't replace wholesale: ImageID's
		// own repo is always bare (it's paired with a digest, never a tag), so a
		// naive replacement silently drops the tag from every image that has one.
		imgID := cs.ImageID
		ref := cs.Image
		if at := strings.LastIndex(imgID, "@sha256:"); at >= 0 {
			if repo := strings.TrimPrefix(imgID[:at], "docker-pullable://"); repo != "" {
				ref = repo
				if tag := imageTag(cs.Image); tag != "" {
					ref += ":" + tag
				}
			}
			imgID = imgID[at+1:] // "sha256:hex"
		} else if idx := strings.LastIndex(imgID, "sha256:"); idx >= 0 {
			imgID = imgID[idx:]
		}
		if imgID != "" {
			imageIDs[imgID] = ref
		}
	}
	for imgID, imgRef := range imageIDs {
		imageAssetID := collect.ImageAssetID(imgID)
		displayName := imgRef
		if at := strings.Index(displayName, "@"); at >= 0 {
			displayName = displayName[:at]
		}
		edges = append(edges, asset.Edge{
			SrcID: id, SrcType: "k8s_pod",
			DstID:      imageAssetID,
			DstType:    "container_image",
			EdgeType:   "runs_image",
			Properties: map[string]string{"image_ref": imgRef},
		})
		imageAssets = append(imageAssets, asset.Asset{
			ID:       imageAssetID,
			Name:     displayName,
			Type:     "container_image",
			Provider: asset.ProviderKubernetes,
			Region:   cluster,
			Metadata: map[string]string{
				"image_ref": imgRef,
				"image_id":  imgID,
				"cluster":   cluster,
			},
			DiscoveredAt: now, LastSeen: now,
		})
	}
	// Persist image digests on the pod for CSPM checks.
	if len(imageIDs) > 0 {
		digests := slices.Sorted(maps.Keys(imageIDs))
		// Sorted, not map order: this is a SET serialised into one string, so map
		// iteration order re-serialised the same set differently on every sweep
		// and the diff engine logged a change each time.
		meta["image_ids"] = strings.Join(digests, ",")
		a.Metadata = meta
	}
	extraAssets := append(containerAssets, imageAssets...)
	return a, extraAssets, edges
}

// imageTag extracts the tag from an image reference ("registry[:port]/repo:tag"),
// or "" if ref has no tag — a bare digest, a bare repo with no tag at all, or a
// host with a port but no tag ("registry:5000/repo"). Standard Docker-reference
// convention: a colon is a tag separator only when it comes after the last '/'
// (a colon before the last '/' is a registry port, not a tag).
func imageTag(ref string) string {
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[colon+1:]
	}
	return ""
}

// podOwner resolves the workload that manages a pod from its ownerReferences.
// A ReplicaSet is an implementation detail of a Deployment: its name is
// "<deployment>-<pod-template-hash>" and the hash is stamped on the pod's
// labels, so the Deployment resolves without listing ReplicaSets. StatefulSet,
// DaemonSet, and Job own their pods directly. Bare pods return ok=false.
func podOwner(pod corev1.Pod) (kind, name string, ok bool) {
	for _, ref := range pod.OwnerReferences {
		switch ref.Kind {
		case "ReplicaSet":
			if hash := pod.Labels["pod-template-hash"]; hash != "" && strings.HasSuffix(ref.Name, "-"+hash) {
				return "Deployment", strings.TrimSuffix(ref.Name, "-"+hash), true
			}
			return "ReplicaSet", ref.Name, true
		case "StatefulSet", "DaemonSet", "Job":
			return ref.Kind, ref.Name, true
		}
	}
	return "", "", false
}
