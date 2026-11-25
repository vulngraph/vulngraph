package gcp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
	storage "google.golang.org/api/storage/v1"

	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

func TestBucketToNeutral_EffectivePrevention(t *testing.T) {
	for _, tc := range []struct {
		name, bucket, inherited, effective string
		wantKnown, wantPublic, wantProbe   bool
	}{
		{"bucket enforcement", "enforced", "", "enforced", true, false, false},
		{"bucket overrides disabled ancestor", "enforced", "not_enforced", "enforced", true, false, false},
		{"inherited enforcement", "inherited", "enforced", "enforced", true, false, false},
		{"ancestor protects unread bucket setting", "", "enforced", "enforced", true, false, false},
		{"no effective prevention", "inherited", "not_enforced", "not_enforced", true, true, true},
		{"unknown inheritance", "inherited", "", "", false, false, false},
		{"unknown bucket setting", "", "not_enforced", "", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probed := false
			policyOf := func(context.Context, string) (*storage.Policy, error) {
				probed = true
				return &storage.Policy{Bindings: []*storage.PolicyBindings{{Members: []string{"allUsers"}, Role: "roles/storage.objectViewer"}}}, nil
			}
			b := &storage.Bucket{Name: "bucket", IamConfiguration: &storage.BucketIamConfiguration{PublicAccessPrevention: tc.bucket}}
			g := bucketToNeutral(context.Background(), b, policyOf, tc.inherited)
			require.Equal(t, tc.effective, g.EffectivePrevention)
			require.Equal(t, tc.wantKnown, g.PublicKnown)
			require.Equal(t, tc.wantPublic, g.Public)
			require.Equal(t, tc.wantProbe, probed)

			assets, edges, err := collectGCS(context.Background(), &fakeGCS{buckets: []gcsBucket{g}}, "project", gcsNow)
			require.NoError(t, err)
			require.Len(t, assets, 1)
			require.Equal(t, tc.wantPublic, len(edges) == 1)
			guardrail, ok := checks.Default().ByID("gcp-gcs-public-access-not-prevented")
			require.True(t, ok)
			require.Equal(t, tc.effective != "", guardrail.Evaluable(assets[0]))
			require.Equal(t, tc.effective == "not_enforced", guardrail.Violates(assets[0]))
			if !tc.wantKnown {
				require.NotContains(t, assets[0].Metadata, "public")
				require.Equal(t, publicAccessUnknown, assets[0].Metadata["public_access"])
			}
		})
	}
}

type gcsPreventionTransport func(*http.Request) (*http.Response, error)

func (f gcsPreventionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRealGCS_PreventionPolicyOncePerSweep(t *testing.T) {
	for _, tc := range []struct {
		name, response, want string
		status               int
	}{
		{"enforced", `{"spec":{"rules":[{"enforce":true}]}}`, "enforced", 200},
		{"not enforced", `{"spec":{"rules":[{"enforce":false}]}}`, "not_enforced", 200},
		{"unreadable", `{"error":{"code":403,"message":"denied"}}`, "", 403},
		{"not found is unknown", `{"error":{"code":404,"message":"not found"}}`, "", 404},
		{"empty response", `{}`, "", 200},
		{"empty rule", `{"spec":{"rules":[{}]}}`, "", 200},
		{"null enforcement", `{"spec":{"rules":[{"enforce":null}]}}`, "", 200},
		{"unknown rule variant", `{"spec":{"rules":[{"futureVariant":true}]}}`, "", 200},
		{"unknown modifier", `{"spec":{"rules":[{"enforce":false,"futureCondition":true}]}}`, "", 200},
		{"non boolean enforcement", `{"spec":{"rules":[{"enforce":"false"}]}}`, "", 200},
		{"dry run is not enforcement", `{"dryRunSpec":{"rules":[{"enforce":true}]}}`, "", 200},
		{"unevaluated condition", `{"spec":{"rules":[{"enforce":true,"condition":{"expression":"resource.hasTagKey('123/env')"}}]}}`, "", 200},
		{"conflicting rules", `{"spec":{"rules":[{"enforce":true},{"enforce":false}]}}`, "", 200},
		{"reset restores default", `{"spec":{"reset":true}}`, "not_enforced", 200},
		{"list policy is not boolean", `{"spec":{"rules":[{"allowAll":true}]}}`, "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policyReads, bucketReads := 0, 0
			client := safenet.NewInternal(time.Second)
			client.Transport = gcsPreventionTransport(func(req *http.Request) (*http.Response, error) {
				require.Equal(t, http.MethodGet, req.Method)
				status, body := 200, ""
				switch req.URL.Path {
				case "/storage/v1/b":
					bucketReads++
					if req.URL.Query().Get("pageToken") == "" {
						body = `{"nextPageToken":"next","items":[{"name":"one","iamConfiguration":{"publicAccessPrevention":"inherited"}}]}`
					} else {
						body = `{"items":[{"name":"two","iamConfiguration":{"publicAccessPrevention":"inherited"}}]}`
					}
				case "/v2/projects/project/policies/storage.publicAccessPrevention":
					policyReads++
					status, body = tc.status, tc.response
				case "/storage/v1/b/one/iam", "/storage/v1/b/two/iam":
					body = `{"bindings":[{"role":"roles/storage.objectViewer","members":["allUsers"]}]}`
				default:
					t.Fatalf("unexpected API request: %s", req.URL)
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			ctx := context.Background()
			svc, err := storage.NewService(ctx, option.WithHTTPClient(client))
			require.NoError(t, err)
			r := &realGCS{svc: svc, policies: client}
			for sweep := 1; sweep <= 2; sweep++ {
				buckets, err := r.ListBuckets(ctx, "project")
				require.NoError(t, err)
				require.Len(t, buckets, 2)
				require.Equal(t, sweep, policyReads, "resolve once across pages, refresh on the next sweep")
				require.Equal(t, sweep*2, bucketReads)
				for _, b := range buckets {
					require.Equal(t, "inherited", b.PublicAccessPrevention)
					require.Equal(t, tc.want, b.EffectivePrevention)
					require.Equal(t, tc.want != "", b.PublicKnown)
					require.Equal(t, tc.want == "not_enforced", b.Public)
				}
			}
		})
	}
}

func TestRealGCS_PreventionHierarchy(t *testing.T) {
	const enforced = `{"spec":{"rules":[{"enforce":true}]}}`
	const disabled = `{"spec":{"rules":[{"enforce":false}]}}`
	const conditional = `{"spec":{"rules":[{"enforce":true},{"enforce":false,"condition":{"expression":"resource.matchTag('123/environment', 'public')"}}]}}`
	const complete = `{"ancestor":[{"resourceId":{"type":"project","id":"1"}},{"resourceId":{"type":"folder","id":"2"}},{"resourceId":{"type":"organization","id":"3"}}]}`
	for _, tc := range []struct {
		name, project, folder, org, ancestry, want string
		folderStatus, orgStatus, ancestryStatus    int
		wantReads                                  []string
	}{
		{"project wins", disabled, enforced, enforced, complete, "not_enforced", 200, 200, 200, []string{"projects/project"}},
		{"project overrides conditional parent", disabled, conditional, enforced, complete, "not_enforced", 200, 200, 200, []string{"projects/project"}},
		{"folder enforcement", "", enforced, disabled, complete, "enforced", 200, 200, 200, []string{"projects/project", "folders/2"}},
		{"folder overrides org", "", disabled, enforced, complete, "not_enforced", 200, 200, 200, []string{"projects/project", "folders/2"}},
		{"organization enforcement", "", "", enforced, complete, "enforced", 404, 200, 200, []string{"projects/project", "folders/2", "organizations/3"}},
		{"multiple folders nearest first", "", enforced, disabled, `{"ancestor":[{"resourceId":{"type":"project","id":"1"}},{"resourceId":{"type":"folder","id":"4"}},{"resourceId":{"type":"folder","id":"2"}},{"resourceId":{"type":"organization","id":"3"}}]}`, "enforced", 200, 200, 200, []string{"projects/project", "folders/4", "folders/2"}},
		{"no ancestor policy", "", "", "", complete, "not_enforced", 404, 404, 200, []string{"projects/project", "folders/2", "organizations/3"}},
		{"unread folder", "", "", enforced, complete, "", 403, 200, 200, []string{"projects/project", "folders/2"}},
		{"unread organization", "", "", "", complete, "", 404, 403, 200, []string{"projects/project", "folders/2", "organizations/3"}},
		{"unread ancestry", "", enforced, enforced, "", "", 200, 200, 403, []string{"projects/project"}},
		{"bucket-tag condition", "", conditional, enforced, complete, "", 200, 200, 200, []string{"projects/project", "folders/2"}},
		{"empty ancestry", "", enforced, enforced, `{}`, "", 200, 200, 200, []string{"projects/project"}},
		{"incomplete ancestry", "", enforced, enforced, `{"ancestor":[{"resourceId":{"type":"project","id":"1"}},{"resourceId":{"type":"folder","id":"2"}}]}`, "", 200, 200, 200, []string{"projects/project"}},
		{"standalone project", "", "", "", `{"ancestor":[{"resourceId":{"type":"project","id":"1"}}]}`, "not_enforced", 404, 404, 200, []string{"projects/project"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads []string
			client := safenet.NewInternal(time.Second)
			client.Transport = gcsPreventionTransport(func(req *http.Request) (*http.Response, error) {
				status, body := 200, ""
				if req.URL.Path == "/v1/projects/project:getAncestry" {
					require.Equal(t, http.MethodPost, req.Method)
					status, body = tc.ancestryStatus, tc.ancestry
				} else {
					require.Equal(t, http.MethodGet, req.Method)
					resource := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/v2/"), "/policies/storage.publicAccessPrevention")
					reads = append(reads, resource)
					switch resource {
					case "projects/project":
						body = tc.project
						if body == "" {
							status = 404
						}
					case "folders/2":
						status, body = tc.folderStatus, tc.folder
					case "folders/4":
						status = 404
					case "organizations/3":
						status, body = tc.orgStatus, tc.org
					default:
						t.Fatalf("unexpected API request: %s", req.URL)
					}
				}
				if status != 200 {
					body = `{"error":{"message":"unavailable"}}`
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			ctx := context.Background()
			rm, err := cloudresourcemanager.NewService(ctx, option.WithHTTPClient(client))
			require.NoError(t, err)
			r := &realGCS{policies: client, rm: rm}
			require.Equal(t, tc.want, r.projectPublicAccessPrevention(ctx, "project"))
			require.Equal(t, tc.wantReads, reads)
		})
	}
}
