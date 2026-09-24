package httpbasic

import (
	"encoding/json"
	"net/http"
	"strings"

	infraConfig "github.com/divinelab-io/aegis/internal/infra/config"
)

func (s *Section) handleEffectiveState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		appSecurityMethodNotAllowed(w)
		return
	}
	s.mu.RLock()
	enabled := s.enabled
	uploadMode := s.config.UploadProtection.Mode
	s.mu.RUnlock()
	protected, total := 0, 0
	known := false
	if cfg := infraConfig.GetGlobalConfig(); cfg != nil {
		known = true
		for _, route := range cfg.Upstream.Rules {
			if !route.Enabled {
				continue
			}
			total++
			if enabled && (route.Security.HTTPSecurity == nil || *route.Security.HTTPSecurity) {
				protected++
			}
		}
		total += len(cfg.Upstream.Routes)
		if enabled {
			protected += len(cfg.Upstream.Routes)
		}
	}
	percentage := 0
	if total > 0 {
		percentage = protected * 100 / total
	}
	enforcing, monitoring := 0, 0
	effective, reason := "UNAVAILABLE", "No effective App Security controls are available."
	if !enabled {
		effective, reason = "DISABLED", "App Security is disabled globally."
	}
	functions := make([]map[string]interface{}, 0)
	for _, fn := range s.ListFunctions() {
		configured := "off"
		if fn.Enabled {
			configured = "enforce"
			if fn.ID == "upload_protection" {
				if strings.EqualFold(uploadMode, "detect") {
					configured = "monitor"
				} else if strings.EqualFold(uploadMode, "allow") {
					configured = "off"
				}
			}
		}
		status, effectiveMode, functionReason := "disabled", configured, "Control is disabled in configuration."
		if configured != "off" {
			status, functionReason = "active", ""
		}
		if fn.Capability == nil || fn.Capability.Status != appSecurityStatusAvailable || !fn.Capability.RuntimeImplemented {
			status, effectiveMode, functionReason = "unavailable", "off", "Capability is not available in this runtime."
		} else if !enabled {
			status, effectiveMode, functionReason = "disabled", "off", "App Security is disabled globally."
		} else if fn.Capability.Area == "optimization" || fn.ID == "security_txt" {
			status, functionReason = "excluded", "Utility and delivery controls are excluded from security coverage."
		} else if configured == "enforce" {
			enforcing++
		} else if configured == "monitor" {
			monitoring++
		}
		functions = append(functions, map[string]interface{}{"id": fn.ID, "configured_mode": configured, "effective_mode": effectiveMode, "status": status, "reason": functionReason})
	}
	if enabled {
		if known && total > 0 && protected == 0 {
			effective, reason = "NOT_ATTACHED", "App Security is not attached to any enabled route."
		} else {
			switch {
			case enforcing > 0 && monitoring > 0:
				effective, reason = "PARTIALLY_ENFORCED", "Some controls enforce while others only monitor."
			case enforcing > 0:
				effective, reason = "ENFORCING", "App Security controls are enforcing on attached routes."
			case monitoring > 0:
				effective, reason = "MONITORING", "App Security is inspecting traffic without blocking findings."
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"section_enabled":  enabled,
		"configured_state": map[bool]string{true: "ENFORCE", false: "OFF"}[enabled],
		"effective_state":  effective,
		"reason":           reason,
		"route_coverage":   map[string]interface{}{"protected": protected, "total": total, "percentage": percentage, "known": known},
		"functions":        functions,
		"runtime":          map[string]bool{"initialized": true, "middleware_installed": true, "runtime_only": s.persist == nil},
	}
	_ = json.NewEncoder(w).Encode(response)
}
