package graphstore

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/explore"
)

func TestRequireRPCSecret(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	t.Run("empty secret disables enforcement", func(t *testing.T) {
		h := requireRPCSecret("", ok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/graph/cypher", nil))
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("readiness probe is exempt even when enforcing", func(t *testing.T) {
		h := requireRPCSecret("s3cr3t", ok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/graph/ready", nil))
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("missing header is rejected", func(t *testing.T) {
		h := requireRPCSecret("s3cr3t", ok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/graph/cypher", nil))
		require.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("wrong secret is rejected", func(t *testing.T) {
		h := requireRPCSecret("s3cr3t", ok)
		req := httptest.NewRequest(http.MethodPost, "/internal/graph/cypher", nil)
		req.Header.Set(explore.LadybugRPCAuthHeader, "wrong")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("correct secret passes", func(t *testing.T) {
		h := requireRPCSecret("s3cr3t", ok)
		req := httptest.NewRequest(http.MethodPost, "/internal/graph/cypher", nil)
		req.Header.Set(explore.LadybugRPCAuthHeader, "s3cr3t")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	})
}
