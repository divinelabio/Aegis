package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/divinelabio/aegis/internal/maintenance"
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
	Channel           string   `json:"channel"`                   // Target tier: "community", "professional", "enterprise"
	CurrentChannel    string   `json:"current_channel,omitempty"` // Current running tier: "community", "professional", "enterprise"
	TargetTier        string   `json:"target_tier,omitempty"`
	IsTierUpgrade     bool     `json:"is_tier_upgrade"`
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

// InvalidateUpdateCache clears any cached system update checks so subsequent
// calls will re-evaluate against active licensing state and GitHub.
func InvalidateUpdateCache() {
	cachedUpdateMu.Lock()
	cachedUpdateResp = nil
	cachedUpdateAt = time.Time{}
	cachedUpdateMu.Unlock()
}

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
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.JSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	force := r.URL.Query().Get("force") == "true"
	if force && h.License != nil && h.License.Snapshot().ActivationID != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		err := h.License.Refresh(ctx)
		cancel()
		if err != nil && h.Logger != nil {
			h.Logger.Warn("Licence refresh during update check failed", zap.Error(err))
		}
	}

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
		currentVer = "1.0.1"
	}

	channel := "community"
	tierProvider := getLicenseTier()
	if tierProvider != "" {
		channel = strings.ToLower(tierProvider)
	}

	resp := UpdateStatusResponse{
		CurrentVersion:    currentVer,
		LatestVersion:     currentVer,
		CurrentChannel:    channel,
		Channel:           channel,
		UpdateAvailable:   false,
		Notify:            false,
		Severity:          "recommended",
		CheckedAt:         time.Now().UTC().Format(time.RFC3339),
		UpdaterConfigured: strings.TrimSpace(h.UpdaterSocket) != "",
	}
	if resp.UpdaterConfigured {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		_, err := maintenance.CallUpdater(ctx, h.UpdaterSocket, maintenance.UpdaterRequest{Operation: "status"})
		cancel()
		resp.UpdaterConfigured = err == nil
	}

	// 1. Check Commercial upgrade if license manager is active
	if h.License != nil {
		snapshot := h.License.Snapshot()
		if snapshot.BuildTier != "" {
			resp.CurrentChannel = string(snapshot.BuildTier)
			resp.Channel = string(snapshot.BuildTier)
		}

		isTierUpgrade := snapshot.Upgrade.TargetTier.Rank() > snapshot.BuildTier.Rank()
		isUpgradePending := snapshot.Upgrade.Required

		if isUpgradePending {
			targetTier := string(snapshot.Upgrade.TargetTier)
			if targetTier == "" {
				targetTier = string(snapshot.LicensedTier)
			}
			if targetTier == "" {
				targetTier = "professional"
			}
			resp.Channel = targetTier
			resp.TargetTier = targetTier
			resp.IsTierUpgrade = isTierUpgrade

			targetVer := strings.TrimSpace(snapshot.Upgrade.TargetVersion)
			if targetVer == "" {
				targetVer = currentVer
			}
			resp.LatestVersion = targetVer
			resp.UpdateAvailable = snapshot.Upgrade.Available
			resp.Notify = snapshot.Upgrade.Available
			resp.Error = snapshot.Upgrade.Reason
			resp.Severity = "recommended"

			if isTierUpgrade {
				resp.Title = fmt.Sprintf("Aegis %s Upgrade", strings.Title(targetTier))
				resp.Highlights = []string{
					fmt.Sprintf("Upgrade ready to unlock %s features and capabilities.", strings.Title(targetTier)),
					"Aegis restarts briefly during installation; configurations remain preserved.",
					"Custom WAF rules, SSL certificates, and threat data are preserved.",
				}
			} else {
				resp.Title = fmt.Sprintf("Aegis %s Update %s", strings.Title(string(snapshot.EffectiveTier)), targetVer)
				resp.Highlights = []string{
					fmt.Sprintf("Hot-patch release %s ready for Aegis %s.", targetVer, strings.Title(string(snapshot.EffectiveTier))),
					"Aegis restarts briefly during installation; configurations remain preserved.",
				}
			}
			resp.ChangelogURL = "https://github.com/divinelabio/aegis/releases"

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

	ghReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/divinelabio/aegis/releases/latest", nil)
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
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.JSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if strings.TrimSpace(h.UpdaterSocket) == "" {
		h.JSONError(w, "aegis-updater socket is not configured. In containerized or manual setups, pull the updated container image or update the binary.", http.StatusNotImplemented)
		return
	}

	if h.License == nil || h.License.Snapshot().ActivationID == "" {
		h.JSONError(w, "Activate a commercial licence before requesting a commercial release.", http.StatusConflict)
		return
	}
	// Always obtain the release from this installation's current entitlement.
	// Caller-supplied manifests cannot select a different paid edition.
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := h.License.Refresh(ctx); err != nil {
		h.writeLicenseManagerError(w, err)
		return
	}
	upgrade := h.License.Snapshot().Upgrade
	if !upgrade.Required || !upgrade.Available || upgrade.Manifest == "" {
		message := upgrade.Reason
		if message == "" {
			message = "No compatible commercial upgrade is pending for this installation."
		}
		h.JSONError(w, message, http.StatusConflict)
		return
	}

	resp, err := maintenance.CallUpdater(r.Context(), h.UpdaterSocket, maintenance.UpdaterRequest{
		Operation:  "upgrade",
		Manifest:   upgrade.Manifest,
		Credential: upgrade.Credential,
	})
	if err != nil {
		if h.Logger != nil {
			h.Logger.Error("System upgrade request to aegis-updater failed", zap.Error(err))
		}
		h.JSONError(w, "Upgrade failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "Upgrade queued. Follow the updater job for installation and restart progress.",
		"status":  resp.Status,
	})
}
