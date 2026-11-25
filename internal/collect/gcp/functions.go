package gcp

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	cloudfunctions "google.golang.org/api/cloudfunctions/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// cloudFunction is a provider-neutral view of a Cloud Function (gen 1). Ingress
// "ALLOW_ALL" with an HTTPS trigger is a public entry point.
type cloudFunction struct {
	Name                string
	Region              string
	URL                 string
	Runtime             string
	PublicNet           bool
	ServiceAccountEmail string // IAM SA the function runs as — becomes exec_role
	// SecretEnv names the runtime and build environment variables that look
	// like plaintext credentials (plaintextSecretVars); values are never kept.
	SecretEnv []string
}

// functionsAPI is the slice of the Cloud Functions API the collector needs.
type functionsAPI interface {
	ListFunctions(ctx context.Context, projectID string) ([]cloudFunction, error)
}

// collectFunctions maps Cloud Functions to assets, flagging internet-ingress
// HTTPS functions for reachability and posture checks.
func collectFunctions(ctx context.Context, client functionsAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	fns, err := client.ListFunctions(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectFunctions: %w", err)
	}
	var assets []asset.Asset
	for _, fn := range fns {
		if fn.Name == "" {
			continue
		}
		assets = append(assets, asset.Asset{
			ID:        projectID + "/function/" + fn.Name,
			Name:      fn.Name,
			Type:      "cloud_function",
			Provider:  asset.ProviderGCP,
			Region:    fn.Region,
			AccountID: projectID,
			Endpoint:  fn.URL,
			Metadata: func() map[string]string {
				m := map[string]string{
					"runtime": fn.Runtime,
					"public":  fmt.Sprintf("%t", fn.PublicNet),
					"url":     fn.URL,
					// The listing returns both variable maps whole, so "" is
					// an observation of none.
					"plaintext_secret_env": strings.Join(fn.SecretEnv, ","),
				}
				// ALLOW_ALL ingress is only the network path — invocation still
				// requires an allUsers invoker IAM binding (not collected), so
				// exposure is possible, not confirmed.
				if fn.PublicNet {
					m["public_access"] = asset.PublicAccessPossible
				}
				if fn.ServiceAccountEmail != "" {
					m["exec_role"] = "serviceAccount:" + fn.ServiceAccountEmail
				}
				return m
			}(),
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return assets, nil
}

// newFunctionsClient builds a real Cloud Functions-backed client via ADC.
func newFunctionsClient(ctx context.Context) (functionsAPI, error) {
	svc, err := cloudfunctions.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newFunctionsClient: %w", err)
	}
	return &realFunctions{svc: svc}, nil
}

type realFunctions struct {
	svc *cloudfunctions.Service
}

func (r *realFunctions) ListFunctions(ctx context.Context, projectID string) ([]cloudFunction, error) {
	var out []cloudFunction
	parent := "projects/" + projectID + "/locations/-"
	err := r.svc.Projects.Locations.Functions.List(parent).Pages(ctx, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range page.Functions {
			c := cloudFunction{
				Name:    path.Base(fn.Name),
				Region:  regionFromFunctionName(fn.Name),
				Runtime: fn.Runtime,
				// ALLOW_ALL (or unset, which defaults to ALLOW_ALL) ingress is only
				// a public entry point when the function actually has an HTTP(S)
				// trigger. Event-driven functions (Pub/Sub, GCS, Firestore, …) carry
				// EventTrigger instead and have no listener the internet can reach,
				// regardless of ingress setting.
				PublicNet:           (fn.IngressSettings == "" || fn.IngressSettings == "ALLOW_ALL") && fn.HttpsTrigger != nil,
				ServiceAccountEmail: fn.ServiceAccountEmail,
				SecretEnv:           functionSecretEnv(fn),
			}
			if fn.HttpsTrigger != nil {
				c.URL = fn.HttpsTrigger.Url
			}
			out = append(out, c)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ListFunctions: %w", err)
	}
	return out, nil
}

// functionSecretEnv scans a function's runtime and build environment; a
// build variable is prefixed "build:" so the evidence says where it lives.
func functionSecretEnv(fn *cloudfunctions.CloudFunction) []string {
	out := plaintextSecretVars(fn.EnvironmentVariables)
	for _, n := range plaintextSecretVars(fn.BuildEnvironmentVariables) {
		out = append(out, "build:"+n)
	}
	return out
}

// regionFromFunctionName pulls the location from a function resource name of the
// form projects/P/locations/L/functions/F.
func regionFromFunctionName(name string) string {
	parts := splitName(name)
	for i, p := range parts {
		if p == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func splitName(name string) []string {
	var out []string
	cur := ""
	for _, r := range name {
		if r == '/' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
