// Package web embeds the built frontend (frontend/ → web/dist via vite) and
// serves it as a single-page app: any non-API path that isn't a real asset
// falls back to index.html so client-side routing works. If the frontend has
// not been built (only .gitkeep present), it degrades to a clear message —
// `go build` always works, the API runs regardless.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Handler serves the embedded SPA. Mount it as the catch-all ("/").
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return notBuilt()
	}
	return spaHandler(sub)
}

// spaHandler serves the SPA rooted at sub, or the not-built 503 when sub has
// no index.html.
func spaHandler(sub fs.FS) http.Handler {
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return notBuilt()
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve the asset if it exists; otherwise hand index.html to the SPA
		// router (but never swallow API paths — those are routed before this).
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if _, err := fs.Stat(sub, path); err == nil {
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

func notBuilt() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("graph: frontend not built (run: cd frontend && bun run build)\n"))
	})
}
