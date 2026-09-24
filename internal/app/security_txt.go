package app

import (
	"fmt"
	"net/http"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/config"
)

// SecurityTXTHandler serves the installation-wide vulnerability disclosure
// contact on the standard public path.
func SecurityTXTHandler(w http.ResponseWriter, r *http.Request) {
	serveSecurityTXT(w, r, config.GetGlobalConfig(), time.Now().UTC())
}

func serveSecurityTXT(w http.ResponseWriter, r *http.Request, cfg *config.Config, now time.Time) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if cfg == nil {
		http.NotFound(w, r)
		return
	}
	contact, err := config.NormalizeSecurityTXTContact(cfg.SecurityTXT.Contact)
	if err != nil || contact == "" {
		http.NotFound(w, r)
		return
	}
	body := fmt.Sprintf("Contact: %s\nExpires: %s\nPreferred-Languages: en\n", contact, now.Add(365*24*time.Hour).Format(time.RFC3339))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(body))
	}
}
