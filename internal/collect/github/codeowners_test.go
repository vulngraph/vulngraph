package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// coQueryRe pulls (alias, owner/name) pairs out of the generated query, so a
// change in the query shape shows up here rather than being replayed.
var coQueryRe = regexp.MustCompile(`(r\d+): repository\(owner:"([^"]+)", name:"([^"]+)"\)`)

// coServer answers the CODEOWNERS query from files (repo → location → text).
// forbidden repos answer with a per-alias error; reject answers every query
// with a query-level error.
func coServer(t *testing.T, files map[string]map[string]string, forbidden map[string]bool, reject bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /graphql", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Query string `json:"query"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		w.Header().Set("Content-Type", "application/json")
		if reject {
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"data": nil, "errors": []map[string]any{{"message": "complexity"}},
			}))
			return
		}
		require.Equal(t, 3*len(coQueryRe.FindAllString(in.Query, -1)), strings.Count(in.Query, "object(expression:"),
			"every repo asks for all three CODEOWNERS locations")
		data := map[string]any{}
		var errs []map[string]any
		for _, m := range coQueryRe.FindAllStringSubmatch(in.Query, -1) {
			alias, full := m[1], m[2]+"/"+m[3]
			if forbidden[full] {
				data[alias] = nil
				errs = append(errs, map[string]any{"path": []any{alias}, "type": "FORBIDDEN", "message": "no"})
				continue
			}
			blobs := map[string]any{}
			for j, loc := range codeownersLocations {
				if text, ok := files[full][loc]; ok {
					blobs["f"+string(rune('0'+j))] = map[string]any{"text": text, "byteSize": len(text), "isTruncated": false}
				} else {
					blobs["f"+string(rune('0'+j))] = nil
				}
			}
			data[alias] = blobs
		}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"data": data, "errors": errs}))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCollectCodeowners(t *testing.T) {
	files := map[string]map[string]string{
		"org/infra": {".github/CODEOWNERS": "# platform owns all\n* @org/platform\n\n/k8s/ @org/payments\n"},
		// GitHub uses the first location present: .github/ wins over root.
		"org/both": {".github/CODEOWNERS": "* @org/a", "CODEOWNERS": "* @org/b"},
		"org/docs": {"docs/CODEOWNERS": "* @org/docs"},
		"org/huge": {"CODEOWNERS": "* @org/x\n" + strings.Repeat("# pad\n", coMaxBytes/6+1)},
		"org/none": {},
	}
	srv := coServer(t, files, map[string]bool{"org/secret": true}, false)
	c := newTestCollector(srv)

	got, fileState := c.collectCodeowners(context.Background(), srv.URL, "tok",
		append(bpRepos("org/infra", "org/both", "org/docs", "org/huge", "org/none", "org/secret"),
			repo{FullName: "org/archived", DefaultBranch: "main", Archived: true}))

	require.Equal(t, map[string]string{
		"org/infra": "* @org/platform\n/k8s/ @org/payments",
		"org/both":  "* @org/a",
		"org/docs":  "* @org/docs",
	}, got, "oversized, absent, unreadable and archived repos carry no CODEOWNERS key")
	require.Equal(t, map[string]string{"org/infra": "present", "org/both": "present", "org/docs": "present", "org/none": "absent"}, fileState,
		"only repos read are stated: oversized, unreadable and archived repos are in neither")
}

func TestCollectCodeowners_RejectedQueryIsUnread(t *testing.T) {
	srv := coServer(t, nil, nil, true)
	c := newTestCollector(srv)
	rules, fileState := c.collectCodeowners(context.Background(), srv.URL, "tok", bpRepos("org/a"))
	require.Empty(t, rules)
	require.Empty(t, fileState, "a rejected query is unread, not absent")
}

// The repo asset row is rewritten whole each sweep, so a repo whose CODEOWNERS
// read failed must carry its stored rules forward; otherwise one rejected
// batch erased every repo's ownership routing until the next good sweep.
func TestCollectCodeowners_UnreadKeepsStoredRules(t *testing.T) {
	files := map[string]map[string]string{"org/fresh": {"CODEOWNERS": "* @org/new"}, "org/gone": {}}
	srv := coServer(t, files, map[string]bool{"org/secret": true}, false)
	c := newTestCollector(srv)
	var asked []string
	c.SetPriorRepoMetadata(func(_ context.Context, ids []string) (map[string]map[string]string, error) {
		asked = ids
		return map[string]map[string]string{
			"org/secret": {asset.MetaCodeowners: "* @org/old"},
			"org/gone":   {asset.MetaCodeowners: "* @org/stale"},
		}, nil
	})
	got, fileState := c.collectCodeowners(context.Background(), srv.URL, "tok", bpRepos("org/fresh", "org/gone", "org/secret"))
	require.Equal(t, map[string]string{
		"org/fresh":  "* @org/new",
		"org/secret": "* @org/old",
	}, got, "unread keeps stored rules; a file read as absent is dropped")
	require.Equal(t, map[string]string{"org/fresh": "present", "org/gone": "absent"}, fileState)
	require.Equal(t, []string{"org/secret"}, asked, "only unread repos are looked up")

	// A whole rejected batch is unread too.
	rejected := coServer(t, nil, nil, true)
	c = newTestCollector(rejected)
	c.SetPriorRepoMetadata(func(context.Context, []string) (map[string]map[string]string, error) {
		return map[string]map[string]string{"org/a": {asset.MetaCodeowners: "* @org/a"}}, nil
	})
	kept, _ := c.collectCodeowners(context.Background(), rejected.URL, "tok", bpRepos("org/a", "org/b"))
	require.Equal(t, map[string]string{"org/a": "* @org/a"}, kept)

	// A failed lookup keeps nothing rather than guessing.
	c.SetPriorRepoMetadata(func(context.Context, []string) (map[string]map[string]string, error) {
		return nil, errors.New("clickhouse down")
	})
	lost, _ := c.collectCodeowners(context.Background(), rejected.URL, "tok", bpRepos("org/a"))
	require.Empty(t, lost)
}
