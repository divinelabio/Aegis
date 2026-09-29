package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/divinelab-io/aegis/internal/maintenance"
	"go.uber.org/zap"
	"golang.org/x/mod/semver"
)

type UpdateStatusResponse struct {
	CurrentVersion    string   `json:"current_version"`
	LatestVersion     string   `json:"latest_version"`
	UpdateAvailable   bool     `json:"update_available"`
	Notify            bool     `json:"notify"`
	Severity          string   `json:"severity"` // "critical" | "recommended" | "info"
	ReleaseDate       string   `json:"release_date,omitempty"`
	Title             string   `json:"title,omitempty"`
	Highlights        []string `json:"highlights,omitempty"`
	DownloadURL       string   `json:"download_url,omitempty"`
	ChangelogURL      string   `json:"changelog_url,omitempty"`
	Channel           string   `json:"channel"` // "community", "professional", "enterprise"
	CheckedAt         string   `json:"checked_at"`
	UpdaterConfigured bool     `json:"updater_configured"`
	Error             string   `json:"error,omitempty"`
}

var (
	cachedUpdateMu   sync.RWMutex
	cachedUpdateResp *UpdateStatusResponse
	cachedUpdateAt   time.Time
)

const updateCacheTTL = 1 * time.Hour

func normalizeSemver(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "dev" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

// HandleSystemUpdateCheck inspects the current installation and checks whether a newer
// version is available (from the commercial licensing backend or community release catalog).
func (h *Handler) HandleSystemUpdateCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	force := r.URL.Query().Get("force") == "true"

	cachedUpdateMu.RLock()
	if !force && cachedUpdateResp != nil && time.Since(cachedUpdateAt) < updateCacheTTL {
		resp := *cachedUpdateResp
		cachedUpdateMu.RUnlock()
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	cachedUpdateMu.RUnlock()

	currentVer := strings.TrimSpace(Version)
	if currentVer == "" {
		currentVer = "1.0.0"
	}

	channel := "community"
	tierProvider := getLicenseTier()
	if tierProvider != "" {
		channel = strings.ToLower(tierProvider)
	}

	resp := UpdateStatusResponse{
		CurrentVersion:    currentVer,
		LatestVersion:     currentVer,
		UpdateAvailable:   false,
		Notify:            false,
		Severity:          "recommended",
		Channel:           channel,
		CheckedAt:         time.Now().UTC().Format(time.RFC3339),
		UpdaterConfigured: strings.TrimSpace(h.UpdaterSocket) != "",
	}

	// 1. Check Commercial upgrade if license manager is active
	if h.License != nil {
		snapshot := h.License.Snapshot()
		if snapshot.EffectiveTier != "" {
			resp.Channel = string(snapshot.EffectiveTier)
		}
		if snapshot.Upgrade.Required && snapshot.Upgrade.TargetVersion != "" {
			resp.LatestVersion = snapshot.Upgrade.TargetVersion
			resp.UpdateAvailable = true
			resp.Notify = true
			resp.Severity = "recommended"
			resp.Title = fmt.Sprintf("Aegis %s Upgrade", strings.Title(string(snapshot.Upgrade.TargetTier)))
			resp.Highlights = []string{
				fmt.Sprintf("Upgrade ready to unlock %s features and enhancements.", strings.Title(string(snapshot.Upgrade.TargetTier))),
				"Hot-applied without service disruption; configurations remain preserved.",
			}
			resp.ChangelogURL = "https://github.com/divinelab-io/aegis/releases"

			cachedUpdateMu.Lock()
			cachedUpdateResp = &resp
			cachedUpdateAt = time.Now()
			cachedUpdateMu.Unlock()

			_ = json.NewEncoder(w).Encode(resp)
			return
		}
	}

	// 2. Check Community releases
	// Query GitHub releases latest endpoint with a clean timeout
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	ghReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/divinelab-io/aegis/releases/latest", nil)
	if err == nil {
		ghReq.Header.Set("Accept", "application/vnd.github.v3+json")
		ghReq.Header.Set("User-Agent", "Aegis-Update-Checker/"+currentVer)

		client := &http.Client{Timeout: 4 * time.Second}
		ghResp, reqErr := client.Do(ghReq)
		if reqErr == nil && ghResp.StatusCode == http.StatusOK {
			var release struct {
				TagName     string    `json:"tag_name"`
				Name        string    `json:"name"`
				Body        string    `json:"body"`
				PublishedAt time.Time `json:"published_at"`
				HTMLURL     string    `json:"html_url"`
			}
			if err := json.NewDecoder(ghResp.Body).Decode(&release); err == nil && release.TagName != "" {
				_ = ghResp.Body.Close()
				latest := release.TagName
				cleanCurrent := normalizeSemver(currentVer)
				cleanLatest := normalizeSemver(latest)

				if cleanLatest != "" && cleanCurrent != "" && semver.Compare(cleanLatest, cleanCurrent) > 0 {
					resp.LatestVersion = latest
					resp.UpdateAvailable = true
					resp.Notify = true
					resp.ReleaseDate = release.PublishedAt.Format("2006-01-02")
					resp.Title = release.Name
					if resp.Title == "" {
						resp.Title = fmt.Sprintf("Aegis Release %s", latest)
					}
					resp.ChangelogURL = release.HTMLURL

					// Extract highlights (bullet points or first lines)
					bodyLines := strings.Split(release.Body, "\n")
					var bullets []string
					for _, line := range bodyLines {
						line = strings.TrimSpace(line)
						if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
							cleaned := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "- "), "* "))
							if cleaned != "" && len(bullets) < 5 {
								bullets = append(bullets, cleaned)
							}
						}
					}
					if len(bullets) > 0 {
						resp.Highlights = bullets
					} else {
						resp.Highlights = []string{
							"Security enhancements and engine stability improvements.",
							"Preserves all existing security rules, certificates, and settings.",
						}
					}

					// Detect severity tag if mentioned in release
					lowerBody := strings.ToLower(release.Body)
					if strings.Contains(lowerBody, "critical") || strings.Contains(lowerBody, "security hotfix") || strings.Contains(lowerBody, "cve-") {
						resp.Severity = "critical"
					}
				}
			} else {
				_ = ghResp.Body.Close()
			}
		} else if ghResp != nil {
			_ = ghResp.Body.Close()
		}
	}

	cachedUpdateMu.Lock()
	cachedUpdateResp = &resp
	cachedUpdateAt = time.Now()
	cachedUpdateMu.Unlock()

	_ = json.NewEncoder(w).Encode(resp)
}

// HandleSystemUpdateApply sends an upgrade instruction to the local aegis-updater daemon.
func (h *Handler) HandleSystemUpdateApply(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if strings.TrimSpace(h.UpdaterSocket) == "" {
		h.JSONError(w, "aegis-updater socket is not configured. In containerized or manual setups, pull the updated container image or update the binary.", http.StatusNotImplemented)
		return
	}

	var req struct {
		Version string `json:"version"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	// If a commercial license snapshot has upgrade details, pass them
	manifest := ""
	credential := ""
	if h.License != nil {
		snapshot := h.License.Snapshot()
		if snapshot.Upgrade.Required {
			manifest = snapshot.Upgrade.Manifest
			credential = snapshot.Upgrade.Credential
		}
	}

	resp, err := maintenance.CallUpdater(r.Context(), h.UpdaterSocket, maintenance.UpdaterRequest{
		Operation:  "upgrade",
		Manifest:   manifest,
		Credential: credential,
	})
	if err != nil {
		if h.Logger != nil {
			h.Logger.Error("System upgrade request to aegis-updater failed", zap.Error(err))
		}
		h.JSONError(w, "Upgrade failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "Update dispatched to aegis-updater. Aegis is restarting...",
		"status":  resp.Status,
	})
}
