package adminui

import (
	"embed"
	"net/http"
	"os"
	"path"
	"strings"
)

// EmbeddedFS bundles all compiled Admin Console assets into the Go binary.
//
//go:embed index.html login.html reset_confirm.html reset_request.html css dist images
var EmbeddedFS embed.FS

// FileSystem returns an http.FileSystem that prefers the local "web/admin" directory
// if present (allowing live editing during development), and falls back to EmbeddedFS
// for standalone, zero-dependency production binary deployments.
func FileSystem() (http.FileSystem, bool) {
	if info, err := os.Stat("web/admin/index.html"); err == nil && !info.IsDir() {
		return http.Dir("web/admin"), true
	}
	return http.FS(EmbeddedFS), false
}

// ServeAsset serves a specific file from the active FileSystem (disk or embedded).
func ServeAsset(w http.ResponseWriter, r *http.Request, filename string) {
	cleanName := strings.TrimPrefix(path.Clean(filename), "/")
	if cleanName == "" || cleanName == "." {
		cleanName = "index.html"
	}

	rootFS, _ := FileSystem()
	f, err := rootFS.Open(cleanName)
	if err != nil {
		// If requested file doesn't exist, fall back to index.html for SPA routing
		fallback, fallbackErr := rootFS.Open("index.html")
		if fallbackErr != nil {
			http.NotFound(w, r)
			return
		}
		defer fallback.Close()
		stat, err := fallback.Stat()
		if err != nil {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, "index.html", stat.ModTime(), fallback)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if stat.IsDir() && cleanName != "index.html" {
		ServeAsset(w, r, "index.html")
		return
	}

	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}
