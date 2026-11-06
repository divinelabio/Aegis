package adminui

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
)

//go:embed all:dist
var EmbeddedDist embed.FS

// FileSystem returns an http.FileSystem that prefers the local disk "./web/admin/dist"
// if present (for development), and falls back to EmbeddedDist for zero-dependency binary deployments.
func FileSystem() (http.FileSystem, bool) {
	if info, err := os.Stat("web/admin/dist/index.html"); err == nil && !info.IsDir() {
		return http.Dir("web/admin/dist"), true
	}
	sub, err := fs.Sub(EmbeddedDist, "dist")
	if err != nil {
		return http.FS(EmbeddedDist), false
	}
	return http.FS(sub), false
}
