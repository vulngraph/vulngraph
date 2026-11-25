package gcp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	run "google.golang.org/api/run/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// cloudRunLocationLabel is the label Cloud Run stamps on every service and
// revision with the region it runs in.
const cloudRunLocationLabel = "cloud.googleapis.com/location"

// cloudRunListPageSize bounds one page of a project-wide listing.
const cloudRunListPageSize = 500

// cloudRunCallTimeout bounds one per-service call (a revision read, an IAM
// policy read), so one hung call costs that service's detail, not the sweep.
const cloudRunCallTimeout = 20 * time.Second

// cloudRunService is a provider-neutral view of a Cloud Run service. Ingress
// "all" means the service accepts traffic straight from the internet — a real
// public entry point the reachability rule treats as exposed.
type cloudRunService struct {
	Name                string
	Region              string
	URL                 string
	PublicNet           bool     // ingress allows all (internet), not internal-only
	ServiceAccountEmail string   // IAM SA the containers run as — becomes exec_role
	ServingRevisions    []string // revisions currently receiving traffic
	// TemplateRead records that the revision template came back, so SecretEnv
	// (plaintextSecretVars over its containers' literal env values) is whole.
	TemplateRead bool
	SecretEnv    []string
	// FunctionGen2: the service backs a 2nd-gen Cloud Function.
	FunctionGen2 bool
}

// revisionImages is what one revision says about the images it runs.
type revisionImages struct {
	Images []collect.RunningImage
	// Unresolved counts containers whose digest the API does not report: the
	// v1 revision status resolves only the ingress container's digest, so a
	// sidecar deployed by tag has no stable identity to scan.
	Unresolved int
}

// cloudRunAPI is the slice of the Cloud Run Admin API the collector needs.
//
// ListServices may return a partial listing together with an error (a
// location the global endpoint could not reach): what it did list is real and
// is kept, the error flags the sweep partial.
type cloudRunAPI interface {
	ListServices(ctx context.Context, projectID string) ([]cloudRunService, error)
	// RevisionImages reads one revision (by region, since revision names are
	// unique per region) and returns the images its containers resolved at
	// creation.
	RevisionImages(ctx context.Context, projectID, region, revision string) (revisionImages, error)
	// InvokerPublic reports whether roles/run.invoker is granted to allUsers or
	// allAuthenticatedUsers — what turns ingress=all into unauthenticated access.
	InvokerPublic(ctx context.Context, projectID, region, service string) (bool, error)
}

// cloudRunServiceID keys a service by region: service names are unique per
// region only, so "project/cloudrun/<name>" collapsed same-named services in
// two regions into one asset. A service with no location label (never seen in
// practice) keeps the region-less form rather than inventing a region.
func cloudRunServiceID(projectID, region, name string) string {
	if region == "" {
		return projectID + "/cloudrun/" + name
	}
	return projectID + "/cloudrun/" + region + "/" + name
}

// collectCloudRun maps Cloud Run services to assets, flagging internet-ingress
// services so reachability and posture checks can act on them, and links each
// service to the container images its traffic-serving revisions run
// (runs_image), so the imagevuln sweep scans them and an image CVE on an
// exposed service reaches must_fix through the same chain a k8s pod uses.
//
// Only the revisions receiving traffic are read, one Get each: a project-wide
// revision listing returned every retained revision of every service (up to a
// thousand per service) to use a handful. A failed revision read never
// discards the service: it is returned without that revision's image edges
// and the error flags the family partial.
func collectCloudRun(ctx context.Context, client cloudRunAPI, projectID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	services, listErr := client.ListServices(ctx, projectID)
	if listErr != nil && len(services) == 0 {
		return nil, nil, fmt.Errorf("collectCloudRun: %w", listErr)
	}

	var (
		assets     []asset.Asset
		edges      []asset.Edge
		revErrs    []error
		seenImages = map[string]bool{}
	)
	for _, s := range services {
		if s.Name == "" {
			continue
		}
		id := cloudRunServiceID(projectID, s.Region, s.Name)
		meta := cloudRunMetadata(ctx, client, projectID, s)
		svcEdges, svcImages, unresolved, err := serviceImages(ctx, client, projectID, id, s)
		if err != nil {
			revErrs = append(revErrs, err)
		} else if unresolved > 0 {
			// Written only when every serving revision was read: a container
			// running an image nothing scans, recorded rather than implied clean.
			meta["running_images_unresolved"] = strconv.Itoa(unresolved)
		}
		assets = append(assets, asset.Asset{
			ID:           id,
			Name:         s.Name,
			Type:         "cloudrun_service",
			Provider:     asset.ProviderGCP,
			Region:       s.Region,
			AccountID:    projectID,
			Endpoint:     s.URL,
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
		edges = append(edges, svcEdges...)
		for _, img := range svcImages {
			if !seenImages[img.Digest] {
				seenImages[img.Digest] = true
				assets = append(assets, collect.ImageAsset(img, asset.ProviderGCP, s.Region, projectID, now))
			}
		}
	}
	if err := errors.Join(append(revErrs, listErr)...); err != nil {
		return assets, edges, fmt.Errorf("collectCloudRun: %w", err)
	}
	return assets, edges, nil
}

// serviceImages reads each serving revision of s and returns the runs_image
// edges from the service (id), the images behind them, and how many
// containers ran an image with no resolved digest.
func serviceImages(ctx context.Context, client cloudRunAPI, projectID, id string, s cloudRunService) ([]asset.Edge, []collect.RunningImage, int, error) {
	if len(s.ServingRevisions) == 0 {
		return nil, nil, 0, nil
	}
	if s.Region == "" {
		return nil, nil, 0, fmt.Errorf("serviceImages %s: no location label; serving revisions unread", s.Name)
	}
	var (
		edges      []asset.Edge
		images     []collect.RunningImage
		unresolved int
		errs       []error
	)
	seen := map[string]bool{}
	for _, rev := range s.ServingRevisions {
		rctx, cancel := context.WithTimeout(ctx, cloudRunCallTimeout)
		got, err := client.RevisionImages(rctx, projectID, s.Region, rev)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("serviceImages %s/%s: %w", s.Region, rev, err))
			continue
		}
		unresolved += got.Unresolved
		for _, img := range got.Images {
			if seen[img.Digest] {
				continue
			}
			seen[img.Digest] = true
			images = append(images, img)
			edges = append(edges, collect.RunsImageEdge(id, "cloudrun_service", img))
		}
	}
	return edges, images, unresolved, errors.Join(errs...)
}

// cloudRunMetadata builds a service's metadata. Exposure has three states:
// internal ingress (public=false, IAM irrelevant — not internet-routable),
// ingress=all with a public invoker binding (confirmed), and ingress=all with
// the binding absent OR unreadable (possible). An unreadable IAM policy is
// unknown, so it must read neither as confirmed nor as safe: it keeps the
// network-level "possible" tier and records no invoker_public flag.
func cloudRunMetadata(ctx context.Context, client cloudRunAPI, projectID string, s cloudRunService) map[string]string {
	m := map[string]string{
		"public": fmt.Sprintf("%t", s.PublicNet),
		"url":    s.URL,
	}
	if s.PublicNet {
		m["public_access"] = asset.PublicAccessPossible
		if s.Region == "" {
			log.FromContext(ctx).Warn().Str("service", s.Name).
				Msg("cloudrun: service has no location label; invoker IAM unread, exposure stays possible")
		} else if public, err := invokerPublic(ctx, client, projectID, s); err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("service", s.Name).
				Msg("cloudrun: invoker IAM policy unreadable; exposure stays possible")
		} else {
			m["invoker_public"] = fmt.Sprintf("%t", public)
			if public {
				m["public_access"] = asset.PublicAccessConfirmed
			}
		}
	}
	if s.ServiceAccountEmail != "" {
		// exec_role is the canonical metadata key for the IAM identity a
		// workload runs as — the ExecutesAs correlator reads it to emit
		// executes_as edges (Cloud Run SA → graph attack paths).
		m["exec_role"] = "serviceAccount:" + s.ServiceAccountEmail
	}
	// Only when the template came back: its env list is then whole, and ""
	// is an observation of none. A 2nd-gen Cloud Function runs as a Cloud
	// Run service, so this is where its runtime variables are read.
	if s.TemplateRead {
		m["plaintext_secret_env"] = strings.Join(s.SecretEnv, ",")
		m["cloud_function_gen2"] = strconv.FormatBool(s.FunctionGen2)
	}
	return m
}

// invokerPublic is one bounded InvokerPublic call.
func invokerPublic(ctx context.Context, client cloudRunAPI, projectID string, s cloudRunService) (bool, error) {
	ictx, cancel := context.WithTimeout(ctx, cloudRunCallTimeout)
	defer cancel()
	public, err := client.InvokerPublic(ictx, projectID, s.Region, s.Name)
	if err != nil {
		return false, fmt.Errorf("invokerPublic: %w", err)
	}
	return public, nil
}

// newCloudRunClient builds a real Cloud Run-backed client via ADC.
func newCloudRunClient(ctx context.Context) (cloudRunAPI, error) {
	svc, err := run.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newCloudRunClient: %w", err)
	}
	return &realCloudRun{svc: svc}, nil
}

type realCloudRun struct {
	svc *run.APIService
}

// errUnreachable reports locations the global endpoint could not list — the
// listing is incomplete even though the call succeeded.
func errUnreachable(what string, locations []string) error {
	if len(locations) == 0 {
		return nil
	}
	return fmt.Errorf("%s: locations unreachable: %v", what, locations)
}

func (r *realCloudRun) ListServices(ctx context.Context, projectID string) ([]cloudRunService, error) {
	var (
		out         []cloudRunService
		unreachable []string
		token       string
	)
	for {
		call := r.svc.Namespaces.Services.List("namespaces/" + projectID).Limit(cloudRunListPageSize).Context(ctx)
		if token != "" {
			call = call.Continue(token)
		}
		resp, err := call.Do()
		if err != nil {
			return out, fmt.Errorf("ListServices: %w", err)
		}
		for _, s := range resp.Items {
			out = append(out, toCloudRunService(s))
		}
		unreachable = append(unreachable, resp.Unreachable...)
		if resp.Metadata == nil || resp.Metadata.Continue == "" {
			break
		}
		token = resp.Metadata.Continue
	}
	return out, errUnreachable("ListServices", unreachable)
}

func (r *realCloudRun) RevisionImages(ctx context.Context, projectID, region, revision string) (revisionImages, error) {
	name := fmt.Sprintf("projects/%s/locations/%s/revisions/%s", projectID, region, revision)
	rev, err := r.svc.Projects.Locations.Revisions.Get(name).Context(ctx).Do()
	if err != nil {
		return revisionImages{}, fmt.Errorf("RevisionImages: %w", err)
	}
	return revisionContainerImages(rev), nil
}

func (r *realCloudRun) InvokerPublic(ctx context.Context, projectID, region, service string) (bool, error) {
	resource := fmt.Sprintf("projects/%s/locations/%s/services/%s", projectID, region, service)
	policy, err := r.svc.Projects.Locations.Services.GetIamPolicy(resource).Context(ctx).Do()
	if err != nil {
		return false, fmt.Errorf("InvokerPublic: %w", err)
	}
	return invokerIsPublic(policy), nil
}

// invokerIsPublic reports whether policy grants roles/run.invoker to
// allUsers/allAuthenticatedUsers. A binding carrying an IAM Condition counts
// too, as the GCS and Artifact Registry grades count theirs: the condition is
// not evaluated here, and an unevaluated condition is no evidence that the
// grant is closed.
func invokerIsPublic(policy *run.Policy) bool {
	if policy == nil {
		return false
	}
	for _, b := range policy.Bindings {
		if b == nil || b.Role != "roles/run.invoker" {
			continue
		}
		for _, m := range b.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				return true
			}
		}
	}
	return false
}

// toCloudRunService maps the API's Service to the neutral view.
func toCloudRunService(s *run.Service) cloudRunService {
	c := cloudRunService{}
	if s == nil {
		return c
	}
	if s.Metadata != nil {
		c.Name = s.Metadata.Name
		c.Region = s.Metadata.Labels[cloudRunLocationLabel]
		// Default ingress is "all" (public) when the annotation is absent.
		ingress := s.Metadata.Annotations["run.googleapis.com/ingress"]
		c.PublicNet = ingress == "" || ingress == "all"
		c.FunctionGen2 = s.Metadata.Labels["goog-managed-by"] == "cloudfunctions"
	}
	if s.Spec != nil && s.Spec.Template != nil && s.Spec.Template.Spec != nil {
		c.ServiceAccountEmail = s.Spec.Template.Spec.ServiceAccountName
		c.TemplateRead = true
		env := map[string]string{}
		for _, ctr := range s.Spec.Template.Spec.Containers {
			if ctr == nil {
				continue
			}
			for _, e := range ctr.Env {
				// valueFrom references Secret Manager; only literals count.
				if e != nil && e.ValueFrom == nil {
					env[e.Name] = e.Value
				}
			}
		}
		c.SecretEnv = plaintextSecretVars(env)
	}
	if s.Status != nil {
		c.URL = s.Status.Url
		c.ServingRevisions = servingRevisions(s.Status)
	}
	return c
}

// servingRevisions lists the revisions receiving traffic. A traffic target
// pinned to "latest" may carry no revision name, in which case it is the
// latest ready revision; no traffic block at all also means latest-ready.
func servingRevisions(st *run.ServiceStatus) []string {
	if len(st.Traffic) == 0 {
		if st.LatestReadyRevisionName == "" {
			return nil
		}
		return []string{st.LatestReadyRevisionName}
	}
	var out []string
	seen := map[string]bool{}
	for _, t := range st.Traffic {
		if t == nil || t.Percent <= 0 {
			continue
		}
		name := t.RevisionName
		if name == "" && t.LatestRevision {
			name = st.LatestReadyRevisionName
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// revisionContainerImages extracts the images a revision's containers run.
// The v1 status resolves ONE digest (Status.ImageDigest), for the ingress
// container — the one serving the port, or the only one; each other container
// (a sidecar) has a stable identity only if its spec image is pinned by digest.
// A container with neither is counted unresolved rather than skipped silently:
// a tag is mutable and is not an image identity.
func revisionContainerImages(rev *run.Revision) revisionImages {
	var out revisionImages
	if rev == nil || rev.Spec == nil {
		return out
	}
	ingress := ingressContainer(rev.Spec.Containers)
	for i, c := range rev.Spec.Containers {
		if c == nil {
			continue
		}
		resolved := ""
		if i == ingress && rev.Status != nil {
			resolved = rev.Status.ImageDigest
		}
		img, ok := collect.ParseImageDigest(resolved, c.Image)
		if !ok || img.Ref == "" {
			img, ok = collect.ParseImageDigest(c.Image, "")
		}
		if !ok || img.Ref == "" {
			out.Unresolved++
			continue
		}
		out.Images = append(out.Images, img)
	}
	return out
}

// ingressContainer is the index of the container receiving traffic: the one
// declaring a port, else the first (a single-container revision needs none).
func ingressContainer(containers []*run.Container) int {
	for i, c := range containers {
		if c != nil && len(c.Ports) > 0 {
			return i
		}
	}
	return 0
}
