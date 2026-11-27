package github

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepoEnumerationRejectsMalformedOrRepeatedInventory(t *testing.T) {
	for _, mode := range []string{"empty", "missing_list", "null_list", "missing_name", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "empty":
					fmt.Fprint(w, `{"repositories":[]}`)
				case "missing_list":
					fmt.Fprint(w, `{}`)
				case "null_list":
					fmt.Fprint(w, `{"repositories":null}`)
				case "missing_name":
					fmt.Fprint(w, `{"repositories":[{"name":"a"}]}`)
				case "duplicate":
					page, _ := strconv.Atoi(r.URL.Query().Get("page"))
					if page > 1 {
						fmt.Fprint(w, `{"repositories":[{"name":"r0","full_name":"org/r0"}]}`)
						return
					}
					fmt.Fprint(w, `{"repositories":[`)
					for i := range perPage {
						if i > 0 {
							fmt.Fprint(w, ",")
						}
						fmt.Fprintf(w, `{"name":"r%d","full_name":"org/r%d"}`, i, i)
					}
					fmt.Fprint(w, `]}`)
				}
			}))
			defer srv.Close()
			c := newTestCollector(srv)
			got, partial, err := c.listRepos(t.Context(), srv.URL, "fixture-token")
			if mode == "empty" {
				require.NoError(t, err)
				require.Empty(t, got)
				require.False(t, partial)
				return
			}
			if mode == "duplicate" {
				require.NoError(t, err)
				require.True(t, partial)
				require.Len(t, got, perPage)
				return
			}
			require.Error(t, err)
			require.Empty(t, got)
		})
	}
}
