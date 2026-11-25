package kubernetes

import (
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// This file maps the four Kubernetes workload controller kinds — Deployment,
// StatefulSet, DaemonSet, Job — to asset.Asset. All four share one ID scheme,
// "<cluster>/<lowercase kind>/<namespace>/<name>", which is NOT incidental:
// checks.go's workloadAggregator builds the same string from a pod's
// owner_kind/owner_name metadata to re-address an aggregated per-pod finding
// at its owning workload. Changing this scheme for one kind without changing
// the other breaks that resolution silently (findings with no matching asset).

func deploymentAsset(dep appsv1.Deployment, cluster string, now time.Time) asset.Asset {
	return asset.Asset{
		ID:       fmt.Sprintf("%s/deployment/%s/%s", cluster, dep.Namespace, dep.Name),
		Name:     dep.Name,
		Type:     "k8s_deployment",
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		Tags:     dep.Labels,
		Metadata: map[string]string{
			"namespace":          dep.Namespace,
			"replicas":           fmt.Sprintf("%d", derefInt32(dep.Spec.Replicas)),
			"available_replicas": fmt.Sprintf("%d", dep.Status.AvailableReplicas),
		},
		DiscoveredAt: now, LastSeen: now,
	}
}

// statefulSetAsset maps a StatefulSet the same way deploymentAsset maps a
// Deployment: ID scheme "<cluster>/statefulset/<ns>/<name>" matches the
// workloadAggregator's ownerID (checks.go) so per-pod findings on
// StatefulSet-owned pods resolve to this asset.
func statefulSetAsset(sts appsv1.StatefulSet, cluster string, now time.Time) asset.Asset {
	return asset.Asset{
		ID:       fmt.Sprintf("%s/statefulset/%s/%s", cluster, sts.Namespace, sts.Name),
		Name:     sts.Name,
		Type:     "k8s_statefulset",
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		Tags:     sts.Labels,
		Metadata: map[string]string{
			"namespace":          sts.Namespace,
			"replicas":           fmt.Sprintf("%d", derefInt32(sts.Spec.Replicas)),
			"available_replicas": fmt.Sprintf("%d", sts.Status.AvailableReplicas),
		},
		DiscoveredAt: now, LastSeen: now,
	}
}

// daemonSetAsset maps a DaemonSet; ID scheme mirrors statefulSetAsset/
// deploymentAsset. DaemonSets have no desired replica count (one pod per
// eligible node) so DesiredNumberScheduled/NumberAvailable are used instead.
func daemonSetAsset(ds appsv1.DaemonSet, cluster string, now time.Time) asset.Asset {
	return asset.Asset{
		ID:       fmt.Sprintf("%s/daemonset/%s/%s", cluster, ds.Namespace, ds.Name),
		Name:     ds.Name,
		Type:     "k8s_daemonset",
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		Tags:     ds.Labels,
		Metadata: map[string]string{
			"namespace":          ds.Namespace,
			"desired_scheduled":  fmt.Sprintf("%d", ds.Status.DesiredNumberScheduled),
			"available_replicas": fmt.Sprintf("%d", ds.Status.NumberAvailable),
		},
		DiscoveredAt: now, LastSeen: now,
	}
}

// jobAsset maps a Job; ID scheme mirrors statefulSetAsset/deploymentAsset.
// Jobs run to completion rather than maintaining replicas, so status is
// captured via active/succeeded/failed pod counts instead of "available".
func jobAsset(job batchv1.Job, cluster string, now time.Time) asset.Asset {
	return asset.Asset{
		ID:       fmt.Sprintf("%s/job/%s/%s", cluster, job.Namespace, job.Name),
		Name:     job.Name,
		Type:     "k8s_job",
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		Tags:     job.Labels,
		Metadata: map[string]string{
			"namespace": job.Namespace,
			"active":    fmt.Sprintf("%d", job.Status.Active),
			"succeeded": fmt.Sprintf("%d", job.Status.Succeeded),
			"failed":    fmt.Sprintf("%d", job.Status.Failed),
		},
		DiscoveredAt: now, LastSeen: now,
	}
}

func derefInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}
