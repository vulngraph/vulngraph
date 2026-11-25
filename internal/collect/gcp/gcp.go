// Package gcp collects Compute Engine inventory from a GCP project. Instances
// become assets; their network attachment becomes a "runs_in" edge to the
// network. Authentication is OIDC-only via Application Default Credentials —
// the pod's Workload-Identity service account in GKE, gcloud ADC in
// local dev; no key is stored on the connector.
package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// gceInstance is a provider-neutral view of a Compute Engine instance, so the
// asset-mapping logic is independent of the GCP SDK's awkward shapes.
type gceInstance struct {
	Name string
	// NumericID is compute.Instance.Id — the identifier Security Command Center
	// resource names carry for a compute instance (.../instances/{numeric_id}),
	// NOT the human-readable Name our asset ID is built from.
	// internal/intel/scc.parseSCCResource extracts this numeric segment,
	// gceMetadata stamps it onto the asset as gcp_instance_id, and SCCWorker
	// (jobs/scc.go) resolves one to the other before persisting a finding —
	// without it, an SCC finding could never join to its asset.
	NumericID      uint64
	Zone           string
	Machine        string
	Status         string
	Network        string
	PrivateIP      string
	PublicIP       string
	Labels         map[string]string
	NetworkTags    []string // GCE network tags — firewalls target instances by these
	ServiceAccount string   // the SA email the instance runs as (executes_as edge)
	// Controls holds the raw instance-level values of the security metadata keys
	// in gceControlKeys, and ONLY those — commonInstanceMetadata and per-instance
	// metadata routinely carry SSH keys and startup scripts that must never be
	// copied into an asset. A key absent here means the instance does not set it
	// and therefore inherits the project's value.
	Controls map[string]string
	// InstanceGroup is the managing instance group's name, from the "created-by"
	// metadata item GCE sets on every MIG member; empty for a standalone VM.
	InstanceGroup string
	// CanIPForward lets the instance send and receive packets for addresses
	// other than its own.
	CanIPForward bool
	// Shielded is the Shielded VM configuration, nil when the API returned none.
	Shielded *gceShielded
	// ConfidentialCompute is confidentialInstanceConfig.enableConfidentialCompute.
	ConfidentialCompute bool
	// FullAPIScope records that the primary service account was granted the
	// cloud-platform OAuth scope, i.e. every API its IAM roles permit.
	FullAPIScope bool
	// ExternalIPConfigured: any NIC carries an IPv4 or IPv6 access config.
	// PublicIP is the first resolved external IPv4 address for display. The
	// per-interface evidence below is authoritative for reachability.
	ExternalIPConfigured bool
	NetworkInterfaces    []gceNetworkInterface
	// DisksWithoutCSEK names the attached disks not encrypted with a
	// customer-supplied key (diskEncryptionKey.sha256 unset).
	DisksWithoutCSEK []string
}

// gceShielded is an instance's Shielded VM configuration.
type gceShielded struct {
	SecureBoot, VTPM, IntegrityMonitoring bool
}

// cloudPlatformScope is the OAuth scope granting access to every Google Cloud
// API the attached service account's roles allow (CIS GCP 4.2).
const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// gceControlKeys maps a GCE metadata key to the asset metadata key it lands on.
// GCP resolves each of these instance-first, project-second (the project's
// commonInstanceMetadata), and every one defaults to off when neither sets it.
var gceControlKeys = map[string]string{
	"enable-oslogin":         "oslogin",
	"serial-port-enable":     "serial_port_enabled",
	"block-project-ssh-keys": "project_ssh_keys_blocked",
}

// computeAPI is the slice of GCP the collector needs — small enough to fake.
type computeAPI interface {
	// ListInstances returns the project's instances and the zones the
	// aggregated listing could NOT reach. A nil error alone is not a
	// completeness guarantee here: compute.instances.aggregatedList reports
	// per-scope failures in the response body (InstanceAggregatedList
	// .Unreachables, plus a per-zone Warning), so a partial answer arrives as a
	// successful call. The caller declares its scope complete only when both
	// the error and the unreachable list are empty.
	ListInstances(ctx context.Context, projectID string) (instances []gceInstance, unreachable []string, err error)
	// ProjectMetadata returns the project's commonInstanceMetadata, filtered to
	// gceControlKeys. This is where enable-oslogin & friends are normally set;
	// without it every instance in the estate reported the control as absent.
	// One call per project per sweep — never per instance.
	ProjectMetadata(ctx context.Context, projectID string) (map[string]string, error)
}

// Collector implements collect.Collector for GCP. newClient is the seam: the
// default builds a real Compute client; tests inject a fake.
type Collector struct {
	newClient func(ctx context.Context, cfg map[string]string) (computeAPI, string, error)
	// auth caches Policy Analyzer last-authentication reads. It lives here, on
	// the collector registered once at worker startup, because the quota it
	// protects is charged to a single consumer project shared by every GCP
	// connector — a per-sweep cache would space nothing. See authcache.go.
	auth *authCache
	// newOSConfig reads GCE software inventory (osconfig.go). Nil skips it:
	// instances then carry no package_inventory key, which reads as unknown.
	newOSConfig func(ctx context.Context) (osConfigAPI, error)
	// advisory is the advisory sources this deployment queries: a VM whose
	// distribution's source is switched off is stamped unmatchable.
	advisory distro.Sources
}

// New builds the collector. advisory names the switched-on advisory feeds
// (jobs.Feeds.AdvisorySources).
func New(advisory distro.Sources) *Collector {
	return &Collector{newClient: defaultClient, auth: newAuthCache(), newOSConfig: defaultOSConfig, advisory: advisory}
}

// Collect lists instances in the project and maps them to assets + edges.
func (c *Collector) Collect(ctx context.Context, cfg map[string]string) (collect.Result, error) {
	client, projectID, err := c.newClient(ctx, cfg)
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: %w", err)
	}
	ctx = resolveTarget(ctx, projectID)

	now := time.Now()
	var result collect.Result
	seenNetworks := map[string]bool{}

	// Compute is best-effort too: a meaningful share of GCP projects have the Compute Engine API
	// disabled (function-only / storage-only / data projects), which returns a 403
	// on ListInstances. That must NOT abort the whole collect — those projects
	// still carry IAM service accounts, secrets, buckets, Cloud Run/Functions we
	// need. A hard return here would leave every such project with ZERO assets.
	var instances []gceInstance
	computeComplete := false
	bestEffort(ctx, &result, "gcp compute", func() error {
		list, unreachable, err := client.ListInstances(ctx, projectID)
		if err != nil {
			return err
		}
		instances = list
		if len(unreachable) > 0 {
			// Not an error — the call succeeded — but the enumeration did not
			// cover the project, so it must not be flagged partial-free AND must
			// not be declared complete. Partial is the honest aggregate here.
			log.FromContext(ctx).Warn().Strs("unreachable", unreachable).
				Msg("gcp compute: aggregated instance list did not reach every zone")
			result.Partial = true
			return nil
		}
		computeComplete = true
		return nil
	})

	// Every family below is best-effort: a connector with compute but not (say)
	// IAM access still yields its compute inventory rather than failing the
	// whole sync. bestEffort flags the result partial on any failure — including
	// a failed client build — so the sync worker skips deletion reconciliation
	// (an un-fetched asset is not a deleted one).

	// DNS records
	bestEffort(ctx, &result, "gcp dns", func() error {
		dnsClient, err := newDNSClient(ctx)
		if err != nil {
			return err
		}
		dnsAssets, dnsEdges, err := collectGCPDNS(ctx, dnsClient, projectID, now)
		if err != nil {
			return err
		}
		result.Assets = append(result.Assets, dnsAssets...)
		result.Edges = append(result.Edges, dnsEdges...)
		return nil
	})

	// IAM service accounts + effective permissions (for CIEM privesc checks).
	bestEffort(ctx, &result, "gcp iam", func() error {
		iamAssets, err := collectIAM(ctx, cfg, c.auth, now)
		if err != nil {
			return err
		}
		result.Assets = append(result.Assets, iamAssets...)
		return nil
	})

	// Cloud Storage buckets + public-exposure flag (parity with AWS S3).
	bestEffort(ctx, &result, "gcp gcs", func() error {
		gcsClient, err := newGCSClient(ctx)
		if err != nil {
			return err
		}
		gcsAssets, gcsEdges, err := collectGCS(ctx, gcsClient, projectID, now)
		if err != nil {
			return err
		}
		result.Assets = append(result.Assets, gcsAssets...)
		result.Edges = append(result.Edges, gcsEdges...)
		return nil
	})

	// Compute firewall rules + internet-open flag (real GCP exposure detection).
	firewallsKnown := false
	bestEffort(ctx, &result, "gcp firewall", func() error {
		fwClient, err := newFirewallClient(ctx)
		if err != nil {
			return err
		}
		fwAssets, err := collectFirewalls(ctx, fwClient, projectID, now)
		if err != nil {
			return err
		}
		result.Assets = append(result.Assets, fwAssets...)
		firewallsKnown = true
		return nil
	})

	// SSL certificates attached to load balancers (both managed and self-managed)
	// and public images / disk snapshots (data-exfil parity with AWS).
	gcpSvc, svcErr := compute.NewService(ctx)
	bestEffort(ctx, &result, "gcp ssl certificate", func() error {
		if svcErr != nil {
			return svcErr
		}
		sslAssets, err := collectGCPSSLCerts(ctx, gcpSvc, projectID, now)
		if err != nil {
			return err
		}
		result.Assets = append(result.Assets, sslAssets...)
		return nil
	})
	bestEffort(ctx, &result, "gcp image/snapshot", func() error {
		if svcErr != nil {
			return svcErr
		}
		exfilAssets, err := collectGCPImagesSnapshots(ctx, realComputeImageAPI{svc: gcpSvc}, projectID, now)
		if err != nil {
			return err
		}
		result.Assets = append(result.Assets, exfilAssets...)
		return nil
	})

	// GKE clusters — control-plane exposure, legacy ABAC, NetworkPolicy posture
	// (EKS/AKS parity).
	gkeComplete := false
	bestEffort(ctx, &result, "gke", func() error {
		gkeClient, err := newContainerClient(ctx)
		if err != nil {
			return err
		}
		// A partial listing (missing zones) returns the clusters it read
		// beside the error; keep them and let the error flag the sweep.
		gkeAssets, err := collectGKE(ctx, gkeClient, projectID, now)
		result.Assets = append(result.Assets, gkeAssets...)
		gkeComplete = err == nil
		return err
	})

	// Managed-service breadth: Cloud SQL, Secret
	// Manager, Cloud Run, Cloud Functions. Each is best-effort and independent —
	// a project the SA can't read one service in still yields the rest. Public
	// Cloud SQL / Cloud Run / Functions feed the InternetReachability rule.
	collectManaged(ctx, projectID, now, &result)
	// CIS posture families (posture.go); project-wide settings are applied
	// to the cloud_account asset once the instances below are in.
	settings := collectPosture(ctx, projectID, now, &result)
	// Listed networks carry their posture; the instance loop below must not
	// add a bare inferred copy of the same asset.
	for _, a := range result.Assets {
		if a.Type == "vpc_network" {
			seenNetworks[a.ID] = true
		}
	}

	// Project-level commonInstanceMetadata: the normal place to set enable-oslogin,
	// serial-port-enable and block-project-ssh-keys. Instances inherit it, so
	// without this read every instance would look like it had the control unset.
	// Fetched once per project, and only when there is an instance to apply it to.
	var projControls map[string]string
	projControlsKnown := false
	if len(instances) > 0 {
		bestEffort(ctx, &result, "gcp project metadata", func() error {
			m, err := client.ProjectMetadata(ctx, projectID)
			if err != nil {
				return err
			}
			projControls, projControlsKnown = m, true
			return nil
		})
	}

	instanceAssets := make([]asset.Asset, 0, len(instances))
	for _, in := range instances {
		id := gceInstanceID(projectID, in.Zone, in.Name)
		instanceAssets = append(instanceAssets, asset.Asset{
			ID:           id,
			Name:         in.Name,
			Type:         "gce_instance",
			Provider:     asset.ProviderGCP,
			Region:       in.Zone,
			AccountID:    projectID,
			PublicIP:     in.PublicIP,
			PrivateIP:    in.PrivateIP,
			Tags:         in.Labels,
			Metadata:     gceMetadata(in, projControls, projControlsKnown),
			DiscoveredAt: now,
			LastSeen:     now,
		})
		instanceAssets[len(instanceAssets)-1].Metadata["firewall_rules_complete"] = boolStr(firewallsKnown)
		result.Assets = append(result.Assets, instanceAssets[len(instanceAssets)-1])

		if in.Network == "" {
			continue
		}
		netID := vpcNetworkID(projectID, in.Network)
		if !seenNetworks[netID] {
			seenNetworks[netID] = true
			result.Assets = append(result.Assets, asset.Asset{
				ID: netID, Name: in.Network, Type: "vpc_network", Provider: asset.ProviderGCP,
				AccountID: projectID, DiscoveredAt: now, LastSeen: now,
			})
		}
		result.Edges = append(result.Edges, asset.Edge{
			SrcID: id, SrcType: "gce_instance",
			DstID: netID, DstType: "vpc_network", EdgeType: "runs_in",
		})
	}
	// Only gce_instance, never vpc_network: the networks above are INFERRED from
	// the instances attached to them, so a network with no instances is absent
	// from this sweep while still existing. Declaring vpc_network enumerated
	// here would make "no instance uses it" read as "it was deleted".
	if computeComplete {
		noteComplete(&result, "global/compute.instances", []string{"gce_instance"}, len(instances))
	}
	// Stamps instanceAssets' Metadata in place — the same maps result holds.
	pkgAssets, pkgEdges := c.inventoryInstances(ctx, projectID, instanceAssets, now)
	result.Assets = append(result.Assets, pkgAssets...)
	result.Edges = append(result.Edges, pkgEdges...)
	applyPostureJoins(&result, projectID, settings, joinInputs{firewalls: firewallsKnown, instances: computeComplete, gke: gkeComplete}, now)
	return result, nil
}

// gceInstanceID keys an instance by zone: instance names are unique per zone
// only, so "project/name" collapsed same-named instances in two zones into one
// asset (and attached both instances' OS Config packages to it). The zone is
// always present on an aggregated-list instance; an empty one keeps the
// zone-less form rather than inventing a zone. The project stays the first
// segment, which SCC's numeric-ID resolver (jobs/scc.go) relies on.
func gceInstanceID(projectID, zone, name string) string {
	if zone == "" {
		return projectID + "/" + name
	}
	return projectID + "/" + zone + "/" + name
}

// bestEffort runs one collection family, logging the skip AND flagging the
// result partial on error: an incomplete sweep means an absent asset may just
// be un-fetched, so the sync worker must not treat it as deleted and must not
// auto-resolve its findings via deletion reconciliation.
//
// serviceDisabledErr is the one exception: a project that has never enabled
// the API being called is not an incomplete sweep, it is a permanent, stable
// fact about that project — many GCP projects are function-only / storage-only
// and will never have Compute, GKE, etc. enabled. Folding that into Partial
// would permanently starve connector.PartialStreak into staleness and disable
// deletion reconciliation for every scope in that project.
func bestEffort(ctx context.Context, result *collect.Result, what string, fn func() error) {
	err := fn()
	if err == nil {
		return
	}
	if serviceDisabledErr(ctx, err) {
		log.FromContext(ctx).Info().Err(err).
			Msg(what + " collection skipped: API not enabled for this project — not counted as partial")
		return
	}
	log.FromContext(ctx).Warn().Err(err).Msg(what + " collection skipped")
	result.Partial = true
}

// serviceDisabledErr reports whether err is GCP's stable signal that the
// project has never enabled the API being called (SERVICE_DISABLED), as
// opposed to a transient failure that genuinely leaves this sweep incomplete.
// Checked structurally first (ErrorItem.Reason, then the newer
// google.rpc.ErrorInfo carried in Details), falling back to the human message
// GCP has used unchanged for years ("<API> has not been used in project <id>
// before or it is disabled") for older client responses that carry neither.
// The project the error names must be the swept one (target.go): an API
// disabled on the caller's own quota project is a failed sweep.
func serviceDisabledErr(ctx context.Context, err error) bool {
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != 403 {
		return false
	}
	return disabledSignal(apiErr) && targetMatches(ctx, namedProject(apiErr))
}

func disabledSignal(apiErr *googleapi.Error) bool {
	for _, item := range apiErr.Errors {
		if item.Reason == "SERVICE_DISABLED" {
			return true
		}
	}
	for _, d := range apiErr.Details {
		m, ok := d.(map[string]any)
		if !ok {
			continue
		}
		if reason, _ := m["reason"].(string); reason == "SERVICE_DISABLED" {
			return true
		}
	}
	return strings.Contains(apiErr.Message, "SERVICE_DISABLED") ||
		strings.Contains(apiErr.Message, "has not been used in project")
}

// noteComplete is bestEffort's counterpart, kept beside it on purpose: "this
// listing enumerated its whole scope" is a statement about the error handling
// above, and a caller that cannot see the failure path cannot make it. For GCP
// that means both bestEffort's error return AND the unreachable-scope list
// that can arrive inside a successful aggregated-list response (see
// computeAPI.ListInstances) must be clean.
func noteComplete(result *collect.Result, scope string, types []string, n int) {
	result.MarkComplete(scope, types, n)
}

// gceMetadata builds a GCE instance's asset metadata. exec_role, when present,
// holds the target IAM node ID (the gcp_service_account asset is keyed
// "serviceAccount:<email>"), so the executes_as correlate rule is provider-agnostic.
func gceMetadata(in gceInstance, projControls map[string]string, projKnown bool) map[string]string {
	m := map[string]string{
		"machine_type": in.Machine,
		"status":       in.Status,
		"network":      in.Network,
		"network_tags": strings.Join(in.NetworkTags, ","),
		// gcp_instance_id is the numeric ID Security Command Center's resource
		// names carry for this instance — see the NumericID field doc comment.
		// SCCWorker (jobs/scc.go) uses this to resolve a finding's ResourceID
		// (project/numeric_id) to this asset's real ID (gceInstanceID) before
		// persisting.
		"gcp_instance_id": strconv.FormatUint(in.NumericID, 10),
	}
	if in.NetworkInterfaces != nil {
		b, _ := json.Marshal(in.NetworkInterfaces)
		m["network_interfaces"] = string(b)
	}
	// The managed instance group that created it: the fleet key that groups a
	// package CVE across autoscaled instances (internal/jobs/vmvuln.go).
	if in.InstanceGroup != "" {
		m["instance_group"] = in.InstanceGroup
	}
	if in.ServiceAccount != "" {
		m["exec_role"] = "serviceAccount:" + in.ServiceAccount
		m["sa_cloud_platform_scope"] = boolStr(in.FullAPIScope)
	}
	// can_ip_forward and confidential_compute are plain booleans on an instance
	// the API returned: an omitted confidentialInstanceConfig is how GCE encodes
	// "not confidential", not an unread field. The Shielded VM settings live in
	// a sub-object, and are stamped only when it came back.
	m["can_ip_forward"] = boolStr(in.CanIPForward)
	m["confidential_compute"] = boolStr(in.ConfidentialCompute)
	if in.ExternalIPConfigured || gceExternalIPObserved(in.NetworkInterfaces) {
		m["external_ip_configured"] = boolStr(in.ExternalIPConfigured)
	}
	// nil only for an instance not built by toNeutral (tests): unknown.
	if in.DisksWithoutCSEK != nil {
		m["disks_without_csek"] = strings.Join(in.DisksWithoutCSEK, ",")
	}
	if in.Shielded != nil {
		m["shielded_secure_boot"] = boolStr(in.Shielded.SecureBoot)
		m["shielded_vtpm"] = boolStr(in.Shielded.VTPM)
		m["shielded_integrity_monitoring"] = boolStr(in.Shielded.IntegrityMonitoring)
	}
	for key, out := range gceControlKeys {
		if v, ok := resolveGCEControl(in.Controls, projControls, projKnown, key); ok {
			m[out] = v
		}
	}
	return m
}

// resolveGCEControl resolves one GCE metadata control the way GCP itself does:
// the instance value wins, otherwise the project's commonInstanceMetadata is
// inherited, otherwise the control is at its default (off).
//
// The bool result is false only when the value is genuinely UNKNOWN — the
// instance does not set the key and project metadata could not be read. The
// caller then omits the key entirely rather than writing "" or "false", either
// of which a check reads as a confirmed negative observation.
func resolveGCEControl(inst, proj map[string]string, projKnown bool, key string) (string, bool) {
	if v, ok := inst[key]; ok {
		return boolStr(gceTruthy(v)), true
	}
	if !projKnown {
		return "", false
	}
	if v, ok := proj[key]; ok {
		return boolStr(gceTruthy(v)), true
	}
	// Project metadata WAS read and does not set the key, so the control is
	// observed to be at its GCE default — off, not unknown.
	return "false", true
}

// gceTruthy applies GCE's metadata truthiness: the console writes "TRUE", the
// API accepts "true", and serial-port-enable is also commonly set to "1".
func gceTruthy(v string) bool {
	return strings.EqualFold(v, "true") || v == "1"
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// defaultClient builds a real Compute client. Authentication is OIDC-only:
// the client uses Application Default Credentials — on GKE that is
// the pod's Workload-Identity service account, and in local dev it is the
// developer's gcloud ADC. The connector stores only the target project_id, never
// a key. Cross-project reads rely on the workload SA holding IAM on project_id.
func defaultClient(ctx context.Context, cfg map[string]string) (computeAPI, string, error) {
	projectID := cfg["project_id"]
	if projectID == "" {
		return nil, "", fmt.Errorf("defaultClient: project_id is required")
	}
	svc, err := compute.NewService(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("defaultClient: %w", err)
	}
	return &realCompute{svc: svc}, projectID, nil
}

// realCompute flattens the GCP aggregated list into provider-neutral instances.
type realCompute struct {
	svc *compute.Service
}

func (r *realCompute) ListInstances(ctx context.Context, projectID string) ([]gceInstance, []string, error) {
	var out []gceInstance
	var unreachable []string
	err := r.svc.Instances.AggregatedList(projectID).Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		// Unreachable scopes are reported IN a successful response, not as an
		// error. Ignoring them is how a listing that saw half the project's
		// zones would still claim to have enumerated all of them.
		unreachable = append(unreachable, page.Unreachables...)
		for zone, scoped := range page.Items {
			// A per-zone warning is the other form of the same thing (GCP
			// reports e.g. an unreachable or unauthorized zone here rather than
			// failing the call).
			if scoped.Warning != nil && scoped.Warning.Code != "NO_RESULTS_ON_PAGE" {
				unreachable = append(unreachable, zone)
			}
			for _, in := range scoped.Instances {
				out = append(out, toNeutral(in))
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("ListInstances: %w", err)
	}
	return out, unreachable, nil
}

// ProjectMetadata reads the project's commonInstanceMetadata (compute.projects.get)
// and keeps only the security-control keys. Returning an empty map with a nil
// error means "read successfully, nothing set" — which is a real observation;
// an error means "unknown", and the caller must not write a value.
func (r *realCompute) ProjectMetadata(ctx context.Context, projectID string) (map[string]string, error) {
	p, err := r.svc.Projects.Get(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("ProjectMetadata: %w", err)
	}
	if p == nil || p.CommonInstanceMetadata == nil {
		return map[string]string{}, nil
	}
	return controlMetadata(p.CommonInstanceMetadata.Items), nil
}

// controlMetadata lifts only the gceControlKeys entries out of a GCE metadata
// item list. Everything else (ssh-keys, startup-script, …) is deliberately
// dropped — it is frequently secret material and no check consumes it.
func controlMetadata(items []*compute.MetadataItems) map[string]string {
	out := map[string]string{}
	for _, item := range items {
		if item == nil {
			continue
		}
		if _, want := gceControlKeys[item.Key]; !want {
			continue
		}
		if item.Value != nil {
			out[item.Key] = *item.Value
		} else {
			out[item.Key] = ""
		}
	}
	return out
}

// toNeutral maps a GCP SDK instance to the provider-neutral shape. The GCP API
// returns several fields as full resource URLs; we keep only the leaf name.
func toNeutral(in *compute.Instance) gceInstance {
	g := gceInstance{
		Name:      in.Name,
		NumericID: in.Id,
		Zone:      lastSegment(in.Zone),
		Machine:   lastSegment(in.MachineType),
		Status:    in.Status,
		Labels:    in.Labels,

		CanIPForward: in.CanIpForward,
	}
	if c := in.ConfidentialInstanceConfig; c != nil {
		g.ConfidentialCompute = c.EnableConfidentialCompute
	}
	if c := in.ShieldedInstanceConfig; c != nil {
		g.Shielded = &gceShielded{
			SecureBoot: c.EnableSecureBoot, VTPM: c.EnableVtpm, IntegrityMonitoring: c.EnableIntegrityMonitoring,
		}
	}
	if in.Tags != nil {
		g.NetworkTags = in.Tags.Items
	}
	// The instance runs as its first (primary) service account; default is the
	// project's Compute Engine default SA. Email is returned inline (no extra call).
	if len(in.ServiceAccounts) > 0 {
		g.ServiceAccount = in.ServiceAccounts[0].Email
		g.FullAPIScope = slices.Contains(in.ServiceAccounts[0].Scopes, cloudPlatformScope)
	}
	applyGCENetworkInterfaces(&g, in.NetworkInterfaces)
	g.DisksWithoutCSEK = []string{}
	for _, d := range in.Disks {
		if d != nil && (d.DiskEncryptionKey == nil || d.DiskEncryptionKey.Sha256 == "") {
			g.DisksWithoutCSEK = append(g.DisksWithoutCSEK, d.DeviceName)
		}
	}
	if in.Metadata != nil {
		g.Controls = controlMetadata(in.Metadata.Items)
		for _, item := range in.Metadata.Items {
			if item != nil && item.Key == "created-by" && item.Value != nil {
				g.InstanceGroup = lastSegment(*item.Value)
			}
		}
	}
	return g
}

// lastSegment returns the final path element of a GCP resource URL (GCP
// returns zone/machineType/network as full URLs; we keep only the leaf).
func lastSegment(url string) string {
	if url == "" {
		return ""
	}
	return path.Base(url)
}
