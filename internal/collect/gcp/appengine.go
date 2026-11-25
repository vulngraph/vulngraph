package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	appengine "google.golang.org/api/appengine/v1"
	"google.golang.org/api/googleapi"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// appEngineAPI is the slice of App Engine Admin the HTTPS posture needs
// (CIS GCP 4.10).
type appEngineAPI interface {
	// Services lists the app's services; a project without an App Engine
	// application returns none and a nil error.
	Services(ctx context.Context, projectID string) ([]*appengine.Service, error)
	Versions(ctx context.Context, projectID, service string) ([]*appengine.Version, error)
}

// collectAppEngine emits one asset per App Engine service, naming the
// serving versions whose URL handlers accept plain HTTP. Only versions that
// receive traffic are graded; flexible-environment versions have no
// handler-level HTTPS setting and are skipped.
func collectAppEngine(ctx context.Context, client appEngineAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	services, err := client.Services(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectAppEngine: %w", err)
	}
	var assets []asset.Asset
	var errs []error
	for _, s := range services {
		if s == nil || s.Id == "" {
			continue
		}
		versions, err := client.Versions(ctx, projectID, s.Id)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		assets = append(assets, asset.Asset{
			ID: projectID + "/appengine/" + s.Id, Name: s.Id, Type: "gcp_appengine_service", Provider: asset.ProviderGCP,
			Region: "global", AccountID: projectID,
			Metadata:     map[string]string{"http_allowed_versions": strings.Join(httpAllowedVersions(s, versions), ",")},
			DiscoveredAt: now, LastSeen: now,
		})
	}
	if err := errors.Join(errs...); err != nil {
		return assets, fmt.Errorf("collectAppEngine: %w", err)
	}
	return assets, nil
}

// httpAllowedVersions returns the serving standard-environment versions with
// any handler whose securityLevel is not SECURE_ALWAYS (an unset level is
// SECURE_OPTIONAL, which serves HTTP).
func httpAllowedVersions(s *appengine.Service, versions []*appengine.Version) []string {
	var out []string
	for _, v := range versions {
		if v == nil || v.Env == "flex" || v.Env == "flexible" || v.ServingStatus == "STOPPED" {
			continue
		}
		if s.Split == nil || s.Split.Allocations[v.Id] <= 0 {
			continue
		}
		for _, h := range v.Handlers {
			if h != nil && h.SecurityLevel != "SECURE_ALWAYS" {
				out = append(out, v.Id)
				break
			}
		}
	}
	return out
}

// newAppEngineClient builds the real appEngineAPI via ADC.
func newAppEngineClient(ctx context.Context) (appEngineAPI, error) {
	svc, err := appengine.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newAppEngineClient: %w", err)
	}
	return &realAppEngine{svc: svc}, nil
}

type realAppEngine struct{ svc *appengine.APIService }

func (r *realAppEngine) Services(ctx context.Context, projectID string) ([]*appengine.Service, error) {
	var out []*appengine.Service
	err := r.svc.Apps.Services.List(projectID).Pages(ctx, func(p *appengine.ListServicesResponse) error {
		out = append(out, p.Services...)
		return nil
	})
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) && apiErr.Code == http.StatusNotFound {
		return nil, nil // no App Engine application in the project
	}
	if err != nil {
		return nil, fmt.Errorf("Services: %w", err)
	}
	return out, nil
}

func (r *realAppEngine) Versions(ctx context.Context, projectID, service string) ([]*appengine.Version, error) {
	var out []*appengine.Version
	if err := r.svc.Apps.Services.Versions.List(projectID, service).View("FULL").
		Pages(ctx, func(p *appengine.ListVersionsResponse) error {
			out = append(out, p.Versions...)
			return nil
		}); err != nil {
		return nil, fmt.Errorf("Versions %s: %w", service, err)
	}
	return out, nil
}
