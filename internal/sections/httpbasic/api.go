package httpbasic

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/divinelab-io/aegis/internal/sections"
)

func (s *Section) registerFunctionToggle(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(prefix+"/functions/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, prefix+"/functions/")
		parts := strings.Split(path, "/")
		if len(parts) < 1 || parts[0] == "" {
			writeAppSecurityError(w, http.StatusBadRequest, "missing_function_id", "", "Missing function id", "")
			return
		}

		funcID := parts[0]
		action := ""
		if len(parts) >= 2 {
			action = parts[1]
		}

		info, found := s.findFunctionInfo(funcID)
		if !found {
			writeAppSecurityError(w, http.StatusNotFound, "function_not_found", funcID, "Function not found", "")
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, info)
		case http.MethodPost, http.MethodPut:
			if action != "toggle" {
				writeAppSecurityError(w, http.StatusBadRequest, "invalid_function_action", funcID, "Use POST or PUT /functions/{id}/toggle", "")
				return
			}
			if info.Capability == nil || info.Capability.Status != appSecurityStatusAvailable || !info.Capability.ToggleSupported {
				writeFunctionCapabilityError(w, info)
				return
			}
			var body struct {
				Enabled bool `json:"enabled"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
				writeAppSecurityError(w, http.StatusBadRequest, "invalid_body", funcID, "Invalid toggle request body", "")
				return
			}
			if err := s.setFunctionEnabled(funcID, body.Enabled); err != nil {
				writeAppSecurityError(w, http.StatusServiceUnavailable, "persistence_unavailable", funcID, "The App Security configuration could not be saved; the current runtime configuration remains active.", "")
				return
			}
			writeJSON(w, map[string]interface{}{"id": funcID, "enabled": body.Enabled, "status": "updated"})
		default:
			appSecurityMethodNotAllowed(w)
		}
	})
}

func (s *Section) setFunctionEnabled(id string, enabled bool) error {
	s.mu.RLock()
	config := cloneCommunityConfig(s.config)
	s.mu.RUnlock()

	switch id {
	case "upload_limit":
		config.UploadLimit.Enabled = enabled
	case "extension_filter":
		config.ExtensionFilter.Enabled = enabled
	case "upload_protection":
		config.UploadProtection.Enabled = enabled
	case "method_enforcer":
		config.MethodEnforcer.Enabled = enabled
	case "host_validator":
		config.HostValidator.Enabled = enabled
	case "content_type_validator":
		config.ContentTypeValidator.Enabled = enabled
	case "request_size_guard":
		config.RequestSizeGuard.Enabled = enabled
	case "security_headers":
		config.SecurityHeaders.Enabled = enabled
	case "header_manager":
		config.HeaderManager.Enabled = enabled
	case "info_hiding":
		config.InfoHiding.Enabled = enabled
	case "cookie_hardener":
		config.CookieHardener.Enabled = enabled
	case "https_redirect":
		config.HTTPSRedirect.Enabled = enabled
	case "gzip":
		config.Gzip.Enabled = enabled
	default:
		return sections.ErrUnsupportedConfigKey
	}
	current := s.GetConfig()
	current.Settings = settingsFromConfig(config)
	return s.UpdateConfig(current)
}

func writeFunctionCapabilityError(w http.ResponseWriter, info sections.FunctionInfo) {
	if info.Capability != nil && info.Capability.Status == appSecurityStatusUpgrade {
		writeAppSecurityError(
			w,
			http.StatusForbidden,
			"feature_not_entitled",
			info.ID,
			info.Name+" requires App Security advanced features.",
			appSecurityUpgradeFeature,
		)
		return
	}
	if info.Capability != nil && info.Capability.Status == appSecurityStatusAvailable && !info.Capability.ToggleSupported {
		writeAppSecurityError(
			w,
			http.StatusNotImplemented,
			"feature_not_implemented",
			info.ID,
			info.Name+" does not support function toggles.",
			"",
		)
		return
	}
	writeAppSecurityError(
		w,
		http.StatusNotImplemented,
		"feature_not_implemented",
		info.ID,
		info.Name+" is not available in this App Security build.",
		"",
	)
}
