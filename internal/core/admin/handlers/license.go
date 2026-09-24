package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/divinelab-io/aegis/internal/edition"
	"github.com/divinelab-io/aegis/internal/licensing"
	"github.com/divinelab-io/aegis/internal/maintenance"
	"go.uber.org/zap"
)

const maxLicenseRequestBytes = 8 << 10

type licenseActivationRequest struct {
	Key string `json:"key"`
}

func (h *Handler) HandleLicense(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.JSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot := licensing.Snapshot{
		BuildTier:     edition.CommunityTier,
		LicensedTier:  edition.CommunityTier,
		EffectiveTier: edition.CommunityTier,
		Status:        licensing.StatusCommunity,
		Features:      edition.FeaturesForTier(edition.CommunityTier).Sorted(),
	}
	if h.License != nil {
		snapshot = h.License.Snapshot()
	}
	writeLicenseJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) HandleLicenseAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.JSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.License == nil {
		h.JSONError(w, "licence management is not available in this build", http.StatusServiceUnavailable)
		return
	}

	switch strings.TrimPrefix(r.URL.Path, "/api/license/") {
	case "activate":
		h.handleLicenseActivate(w, r)
	case "refresh":
		if err := h.License.Refresh(r.Context()); err != nil {
			h.writeLicenseManagerError(w, err)
			return
		}
		writeLicenseJSON(w, http.StatusOK, h.License.Snapshot())
	case "deactivate":
		if err := h.License.Deactivate(r.Context()); err != nil {
			h.writeLicenseManagerError(w, err)
			return
		}
		writeLicenseJSON(w, http.StatusOK, h.License.Snapshot())
	case "upgrade":
		h.handleLicenseUpgrade(w, r)
	case "updater-status":
		h.handleUpdaterStatus(w, r)
	default:
		h.JSONError(w, "licence action not found", http.StatusNotFound)
	}
}

func (h *Handler) handleLicenseUpgrade(w http.ResponseWriter, r *http.Request) {
	if h.License == nil {
		h.JSONError(w, "licence management is not available in this build", http.StatusServiceUnavailable)
		return
	}
	snapshot := h.License.Snapshot()
	upgrade := snapshot.Upgrade
	if !upgrade.Required {
		h.JSONError(w, "no commercial upgrade is pending for this installation", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(h.UpdaterSocket) == "" {
		h.JSONError(w, "aegis-updater socket is not configured. For container or manual environments, update the binary or container image.", http.StatusNotImplemented)
		return
	}
	resp, err := maintenance.CallUpdater(r.Context(), h.UpdaterSocket, maintenance.UpdaterRequest{
		Operation:  "upgrade",
		Manifest:   upgrade.Manifest,
		Credential: upgrade.Credential,
	})
	if err != nil {
		if h.Logger != nil {
			h.Logger.Error("Upgrade request to aegis-updater failed", zap.Error(err))
		}
		h.JSONError(w, "upgrade failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeLicenseJSON(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"message": "Upgrade dispatched to aegis-updater. Aegis is restarting...",
		"status":  resp.Status,
	})
}

func (h *Handler) handleUpdaterStatus(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(h.UpdaterSocket) == "" {
		writeLicenseJSON(w, http.StatusOK, map[string]interface{}{
			"available": false,
			"reason":    "updater socket is not configured",
		})
		return
	}
	resp, err := maintenance.CallUpdater(r.Context(), h.UpdaterSocket, maintenance.UpdaterRequest{
		Operation: "status",
	})
	if err != nil {
		writeLicenseJSON(w, http.StatusOK, map[string]interface{}{
			"available": false,
			"error":     err.Error(),
		})
		return
	}
	writeLicenseJSON(w, http.StatusOK, map[string]interface{}{
		"available": true,
		"status":    resp.Status,
	})
}

func (h *Handler) handleLicenseActivate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLicenseRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request licenseActivationRequest
	if err := decoder.Decode(&request); err != nil {
		h.JSONError(w, "invalid licence activation request", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		h.JSONError(w, "invalid licence activation request", http.StatusBadRequest)
		return
	}
	request.Key = strings.TrimSpace(request.Key)
	if request.Key == "" {
		h.JSONError(w, "licence key is required", http.StatusBadRequest)
		return
	}

	result, err := h.License.Activate(r.Context(), request.Key)
	if err != nil {
		h.writeLicenseManagerError(w, err)
		return
	}
	writeLicenseJSON(w, http.StatusOK, result)
}

func (h *Handler) writeLicenseManagerError(w http.ResponseWriter, err error) {
	if h.Logger != nil {
		h.Logger.Error("Licence operation failed", zap.Error(err))
	}
	h.JSONError(w, err.Error(), http.StatusBadGateway)
}

func writeLicenseJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
