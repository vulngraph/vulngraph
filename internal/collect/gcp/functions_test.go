package gcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	cloudfunctions "google.golang.org/api/cloudfunctions/v1"
)

// TestListFunctions_PublicNet is the regression test for the exposure bug: a
// Cloud Function's ALLOW_ALL (or unset) ingress setting is only a real
// internet entry point when the function has an HTTP(S) trigger. An
// event-driven function (Pub/Sub, GCS, Firestore, …) has no listener the
// internet can reach no matter what its ingress setting says.
func TestListFunctions_PublicNet(t *testing.T) {
	cases := []struct {
		name    string
		fn      *cloudfunctions.CloudFunction
		wantPub bool
	}{
		{
			name: "ALLOW_ALL with HTTPS trigger is public",
			fn: &cloudfunctions.CloudFunction{
				Name:            "projects/p/locations/l/functions/http-fn",
				IngressSettings: "ALLOW_ALL",
				HttpsTrigger:    &cloudfunctions.HttpsTrigger{Url: "https://l-p.cloudfunctions.net/http-fn"},
			},
			wantPub: true,
		},
		{
			name: "ALLOW_ALL with event trigger (Pub/Sub) is NOT public",
			fn: &cloudfunctions.CloudFunction{
				Name:            "projects/p/locations/l/functions/pubsub-fn",
				IngressSettings: "ALLOW_ALL",
				EventTrigger:    &cloudfunctions.EventTrigger{EventType: "google.pubsub.topic.publish"},
			},
			wantPub: false,
		},
		{
			name: "unset ingress (defaults to ALLOW_ALL) with event trigger is NOT public",
			fn: &cloudfunctions.CloudFunction{
				Name:         "projects/p/locations/l/functions/gcs-fn",
				EventTrigger: &cloudfunctions.EventTrigger{EventType: "google.storage.object.finalize"},
			},
			wantPub: false,
		},
		{
			name: "internal-only ingress with HTTPS trigger is NOT public",
			fn: &cloudfunctions.CloudFunction{
				Name:            "projects/p/locations/l/functions/internal-http-fn",
				IngressSettings: "ALLOW_INTERNAL_ONLY",
				HttpsTrigger:    &cloudfunctions.HttpsTrigger{Url: "https://l-p.cloudfunctions.net/internal-http-fn"},
			},
			wantPub: false,
		},
		{
			name: "internal-and-gclb ingress with HTTPS trigger is NOT public",
			fn: &cloudfunctions.CloudFunction{
				Name:            "projects/p/locations/l/functions/gclb-fn",
				IngressSettings: "ALLOW_INTERNAL_AND_GCLB",
				HttpsTrigger:    &cloudfunctions.HttpsTrigger{Url: "https://l-p.cloudfunctions.net/gclb-fn"},
			},
			wantPub: false,
		},
		{
			name: "unset ingress (defaults to ALLOW_ALL) with HTTPS trigger is public",
			fn: &cloudfunctions.CloudFunction{
				Name:         "projects/p/locations/l/functions/unset-http-fn",
				HttpsTrigger: &cloudfunctions.HttpsTrigger{Url: "https://l-p.cloudfunctions.net/unset-http-fn"},
			},
			wantPub: true,
		},
		{
			name: "ALLOW_ALL with neither trigger set is NOT public",
			fn: &cloudfunctions.CloudFunction{
				Name:            "projects/p/locations/l/functions/no-trigger-fn",
				IngressSettings: "ALLOW_ALL",
			},
			wantPub: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cloudFunction{
				Name:      tc.fn.Name,
				Region:    regionFromFunctionName(tc.fn.Name),
				Runtime:   tc.fn.Runtime,
				PublicNet: (tc.fn.IngressSettings == "" || tc.fn.IngressSettings == "ALLOW_ALL") && tc.fn.HttpsTrigger != nil,
			}
			require.Equal(t, tc.wantPub, c.PublicNet)
		})
	}
}

// TestCollectFunctions_PublicNetFlowsToMetadata confirms the PublicNet flag
// (as computed above) is what actually reaches the asset metadata that
// reachability seeding reads (public_access=possible).
func TestCollectFunctions_PublicNetFlowsToMetadata(t *testing.T) {
	assets, err := collectFunctions(context.Background(), &fakeFunctions{items: []cloudFunction{
		{Name: "http-fn", PublicNet: true},
		{Name: "event-fn", PublicNet: false},
	}}, "proj", now)
	require.NoError(t, err)
	require.Len(t, assets, 2)

	md := map[string]map[string]string{}
	for _, a := range assets {
		md[a.Name] = a.Metadata
	}
	require.Equal(t, "true", md["http-fn"]["public"])
	require.Equal(t, "possible", md["http-fn"]["public_access"])

	require.Equal(t, "false", md["event-fn"]["public"])
	require.NotContains(t, md["event-fn"], "public_access", "an event-driven function must not seed an exposure edge")
}
