package gcp

import (
	"context"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

// collectPosture runs the CIS posture families — each its own best-effort
// read — and returns the project-wide settings destined for the project's
// cloud_account asset (applied by applyPostureJoins once every family has
// run). It must run after the GKE family: the Binary Authorization policy is
// read only for a project with clusters that enforce it.
func collectPosture(ctx context.Context, projectID string, now time.Time, result *collect.Result) postureSettings {
	settings := postureSettings{project: map[string]string{}, org: orgSettings{md: map[string]string{}}}
	// keep appends a family's assets even beside an error: a partial read
	// returns what it saw, and the error flags the sweep.
	keep := func(assets []asset.Asset, err error) error {
		result.Assets = append(result.Assets, assets...)
		return err
	}
	bestEffort(ctx, result, "gcp network", func() error {
		c, err := newNetworkClient(ctx)
		if err != nil {
			return err
		}
		return keep(collectNetworks(ctx, c, projectID, now))
	})
	bestEffort(ctx, result, "gcp load balancing", func() error {
		c, err := newLBClient(ctx)
		if err != nil {
			return err
		}
		return keep(collectLoadBalancing(ctx, c, projectID, now))
	})
	bestEffort(ctx, result, "gcp kms", func() error {
		c, err := newKMSClient(ctx)
		if err != nil {
			return err
		}
		return keep(collectKMS(ctx, c, projectID, now))
	})
	bestEffort(ctx, result, "gcp api keys", func() error {
		c, err := newAPIKeysClient(ctx)
		if err != nil {
			return err
		}
		return keep(collectAPIKeys(ctx, c, projectID, now))
	})
	bestEffort(ctx, result, "gcp bigquery", func() error {
		c, err := newBigQueryClient(ctx)
		if err != nil {
			return err
		}
		return keep(collectBigQuery(ctx, c, projectID, now))
	})
	bestEffort(ctx, result, "gcp dataproc", func() error {
		c, err := newDataprocClient(ctx)
		if err != nil {
			return err
		}
		return keep(collectDataproc(ctx, c, projectID, now))
	})
	bestEffort(ctx, result, "gcp appengine", func() error {
		c, err := newAppEngineClient(ctx)
		if err != nil {
			return err
		}
		return keep(collectAppEngine(ctx, c, projectID, now))
	})
	bestEffort(ctx, result, "gcp artifact registry", func() error {
		c, err := newArtifactRegistryClient(ctx)
		if err != nil {
			return err
		}
		return keep(collectArtifactRegistry(ctx, c, projectID, now))
	})
	bestEffort(ctx, result, "gcp logging settings", func() error {
		c, err := newLoggingClient(ctx)
		if err != nil {
			return err
		}
		md, org, err := collectLoggingSettings(ctx, c, projectID)
		settings.add(md, org)
		return err
	})
	bestEffort(ctx, result, "gcp project services", func() error {
		c, err := newProjectServicesClient(ctx)
		if err != nil {
			return err
		}
		md, org, err := collectProjectServices(ctx, c, projectID)
		settings.add(md, org)
		if err != nil {
			return err
		}
		return annotateBinAuthz(ctx, c, projectID, result.Assets)
	})
	return settings
}

// annotateBinAuthz stamps, on each cluster that enforces Binary
// Authorization, the project-policy rule that applies to it (CIS GKE 5.1.3).
// The policy is read only when such a cluster exists.
func annotateBinAuthz(ctx context.Context, client projectServicesAPI, projectID string, assets []asset.Asset) error {
	var enforcing []int
	for i, a := range assets {
		if a.Type == "gke_cluster" && a.Metadata["binary_authorization"] != "" && a.Metadata["binary_authorization"] != "DISABLED" {
			enforcing = append(enforcing, i)
		}
	}
	if len(enforcing) == 0 {
		return nil
	}
	policy, err := client.BinAuthzPolicy(ctx, projectID)
	if err != nil {
		return err
	}
	for _, i := range enforcing {
		mode, allowsAll := binAuthzRule(policy, assets[i].Region, assets[i].Name)
		assets[i].Metadata["binauthz_policy_rule"] = mode
		assets[i].Metadata["binauthz_policy_allows_all"] = strconv.FormatBool(allowsAll)
	}
	return nil
}

// orgSettings are organization-wide settings read for the project's
// organization (org is "organizations/<n>"), destined for ONE organization
// settings asset rather than one finding per project.
type orgSettings struct {
	org string
	md  map[string]string
}

// postureSettings are the project-wide and organization-wide settings the
// posture families read.
type postureSettings struct {
	project map[string]string
	org     orgSettings
}

func (s *postureSettings) add(project map[string]string, org orgSettings) {
	maps.Copy(s.project, project)
	if org.org == "" {
		return
	}
	if s.org.org == "" {
		s.org.org = org.org
	}
	if s.org.org == org.org {
		maps.Copy(s.org.md, org.md)
	}
}

// joinInputs says which listings a join may treat as complete.
type joinInputs struct {
	firewalls, instances, gke bool
}

// applyPostureJoins runs the cross-family joins and lands the settings on
// the project's cloud_account asset and the organization settings asset.
func applyPostureJoins(result *collect.Result, projectID string, settings postureSettings, known joinInputs, now time.Time) {
	annotateGKENodeSAs(result.Assets)
	annotateProxyCerts(result.Assets)
	annotateIAPBypass(result.Assets, known.firewalls)
	annotateGKENodes(result.Assets, known.gke)
	if known.instances {
		if v, ok := vmsWithoutCSEK(result.Assets); ok {
			settings.project["vms_without_csek"] = v
		}
	}
	result.Assets = mergeProjectSettings(result.Assets, projectID, settings.project, now)
	if settings.org.org != "" && len(settings.org.md) > 0 {
		result.Assets = append(result.Assets, orgSettingsAsset(settings.org, now))
	}
}

// orgSettingsAsset is the organization's one settings asset. Every project
// sweep under the organization emits it with the same ID, so it is one
// asset (and one finding per control) however many projects are connected.
func orgSettingsAsset(o orgSettings, now time.Time) asset.Asset {
	id := strings.TrimPrefix(o.org, "organizations/")
	md := map[string]string{"organization_id": id, "provider": "gcp"}
	maps.Copy(md, o.md)
	return asset.Asset{
		ID: "gcp-org:" + id, Name: o.org, Type: "gcp_organization", Provider: asset.ProviderGCP, Region: "global",
		AccountID: id, Metadata: md, DiscoveredAt: now, LastSeen: now,
	}
}

// vmsWithoutCSEK names the project's instances with any disk not encrypted
// by a customer-supplied key (CIS GCP 4.7), as one project-wide list: CSEK
// is a per-workload choice for critical VMs, so a finding per VM would
// report every stock instance. GKE nodes, whose disks GKE manages, are left
// out. Unknown when any instance's disks were not read.
func vmsWithoutCSEK(assets []asset.Asset) (string, bool) {
	var names []string
	graded := 0
	for _, a := range assets {
		if a.Type != "gce_instance" {
			continue
		}
		if _, gke := a.Tags["goog-gke-node"]; gke {
			continue
		}
		v, ok := a.Metadata["disks_without_csek"]
		if !ok {
			return "", false
		}
		graded++
		if v != "" {
			names = append(names, a.Name)
		}
	}
	// A project with no VMs has nothing to grade.
	return strings.Join(names, ","), graded > 0
}
