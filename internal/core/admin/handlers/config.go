package handlers

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/sections"
)

const incompleteControlPlaneArchiveMessage = "configuration archive omits active PostgreSQL control-plane documents; use a PostgreSQL-consistent backup and recovery procedure"

func (h *Handler) HandleConfig(w http.ResponseWriter, r *http.Request) {
	// GET: Return current config
	if r.Method == http.MethodGet {
		snapshot := sanitizedConfigSnapshot()
		var snapshotGroups []config.UpstreamGroup
		if current := config.GetGlobalConfig(); current != nil {
			snapshotGroups = current.Upstream.Groups
		}
		if h.ErrorPagesStore != nil {
			document, found, err := h.ErrorPagesStore.LoadErrorPages(r.Context())
			if err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to load Error Pages control-plane document", zap.Error(err))
				}
				http.Error(w, "Error Pages configuration is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			if !found {
				http.Error(w, "Error Pages configuration is unavailable", http.StatusServiceUnavailable)
				return
			}
			if err := overlayErrorPagesSnapshot(snapshot, document.Config); err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to render Error Pages control-plane document", zap.Error(err))
				}
				http.Error(w, "Failed to render Error Pages configuration", http.StatusInternalServerError)
				return
			}
		}
		if h.SecurityTXTStore != nil {
			document, found, err := h.SecurityTXTStore.LoadSecurityTXT(r.Context())
			if err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to load Security.txt control-plane document", zap.Error(err))
				}
				http.Error(w, "Security.txt configuration is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			if !found {
				http.Error(w, "Security.txt configuration is unavailable", http.StatusServiceUnavailable)
				return
			}
			if err := overlaySecurityTXTSnapshot(snapshot, document.Config); err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to render Security.txt control-plane document", zap.Error(err))
				}
				http.Error(w, "Failed to render Security.txt configuration", http.StatusInternalServerError)
				return
			}
		}
		if h.InfrastructureStore != nil {
			document, found, err := h.InfrastructureStore.LoadInfrastructure(r.Context())
			if err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to load infrastructure control-plane document", zap.Error(err))
				}
				http.Error(w, "Infrastructure configuration is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			if !found {
				http.Error(w, "Infrastructure configuration is unavailable", http.StatusServiceUnavailable)
				return
			}
			if err := overlayInfrastructureSnapshot(snapshot, document.Config); err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to render infrastructure control-plane document", zap.Error(err))
				}
				http.Error(w, "Failed to render Infrastructure configuration", http.StatusInternalServerError)
				return
			}
		}
		if h.UpstreamRuntimeStore != nil {
			document, found, err := h.UpstreamRuntimeStore.LoadUpstreamRuntime(r.Context())
			if err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to load upstream runtime control-plane document", zap.Error(err))
				}
				http.Error(w, "Upstream runtime configuration is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			if !found {
				http.Error(w, "Upstream runtime configuration is unavailable", http.StatusServiceUnavailable)
				return
			}
			if err := overlayUpstreamRuntimeSnapshot(snapshot, document.Settings); err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to render upstream runtime control-plane document", zap.Error(err))
				}
				http.Error(w, "Failed to render upstream runtime configuration", http.StatusInternalServerError)
				return
			}
		}
		if h.CircuitBreakerStore != nil {
			document, found, err := h.CircuitBreakerStore.LoadCircuitBreaker(r.Context())
			if err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to load circuit-breaker control-plane document", zap.Error(err))
				}
				http.Error(w, "Circuit-breaker configuration is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			if !found {
				http.Error(w, "Circuit-breaker configuration is unavailable", http.StatusServiceUnavailable)
				return
			}
			if err := overlayCircuitBreakerSnapshot(snapshot, document.Config); err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to render circuit-breaker control-plane document", zap.Error(err))
				}
				http.Error(w, "Failed to render circuit-breaker configuration", http.StatusInternalServerError)
				return
			}
		}
		if h.UpstreamGroupsStore != nil {
			document, found, err := h.UpstreamGroupsStore.LoadUpstreamGroups(r.Context())
			if err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to load upstream Origin-pool control-plane document", zap.Error(err))
				}
				http.Error(w, "Origin-pool configuration is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			if !found {
				http.Error(w, "Origin-pool configuration is unavailable", http.StatusServiceUnavailable)
				return
			}
			if err := overlayUpstreamGroupsSnapshot(snapshot, document.Groups); err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to render upstream Origin-pool control-plane document", zap.Error(err))
				}
				http.Error(w, "Failed to render Origin-pool configuration", http.StatusInternalServerError)
				return
			}
			snapshotGroups = document.Groups
		}
		if h.LegacyRoutesStore != nil {
			document, found, err := h.LegacyRoutesStore.LoadLegacyRoutes(r.Context())
			if err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to load legacy host-route control-plane document", zap.Error(err))
				}
				http.Error(w, "Legacy host-route configuration is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			if !found {
				http.Error(w, "Legacy host-route configuration is unavailable", http.StatusServiceUnavailable)
				return
			}
			if err := overlayLegacyRoutesSnapshot(snapshot, document.Routes, snapshotGroups); err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to render legacy host-route control-plane document", zap.Error(err))
				}
				http.Error(w, "Failed to render legacy host-route configuration", http.StatusInternalServerError)
				return
			}
		}
		if h.RouteRulesStore != nil {
			document, found, err := h.RouteRulesStore.LoadRouteRules(r.Context())
			if err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to load route-rule control-plane document", zap.Error(err))
				}
				http.Error(w, "Route-rule configuration is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			if !found {
				http.Error(w, "Route-rule configuration is unavailable", http.StatusServiceUnavailable)
				return
			}
			if err := overlayRouteRulesSnapshot(snapshot, document.Rules); err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to render route-rule control-plane document", zap.Error(err))
				}
				http.Error(w, "Failed to render route-rule configuration", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snapshot)
		return
	}

	// POST: Update config
	if r.Method == http.MethodPost {
		var updates map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if config.ContainsErrorPagesUpdate(updates) {
			if h.ErrorPagesStore == nil {
				http.Error(w, "Error Pages configuration persistence is unavailable", http.StatusServiceUnavailable)
				return
			}
			next, err := config.ErrorPagesConfigFromUpdates(updates)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			actor := "unknown"
			if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
				actor = authenticatedOperator
			}
			document, err := config.SaveErrorPagesControlPlane(r.Context(), h.ErrorPagesStore, next, actor, "admin_update")
			if err != nil {
				if errors.Is(err, config.ErrErrorPagesRevisionConflict) {
					http.Error(w, "Error Pages configuration changed on the server; reload before saving", http.StatusConflict)
					return
				}
				if h.Logger != nil {
					h.Logger.Error("Failed to save Error Pages control-plane document", zap.Error(err))
				}
				http.Error(w, "Failed to save Error Pages configuration", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "updated", "revision": document.Revision})
			return
		}
		if config.ContainsSecurityTXTUpdate(updates) {
			if h.SecurityTXTStore == nil {
				http.Error(w, "Security.txt configuration persistence is unavailable", http.StatusServiceUnavailable)
				return
			}
			next, err := config.SecurityTXTConfigFromUpdates(updates)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			actor := "unknown"
			if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
				actor = authenticatedOperator
			}
			document, err := config.SaveSecurityTXTControlPlane(r.Context(), h.SecurityTXTStore, next, actor, "admin_update")
			if err != nil {
				if errors.Is(err, config.ErrSecurityTXTRevisionConflict) {
					http.Error(w, "Security.txt configuration changed on the server; reload before saving", http.StatusConflict)
					return
				}
				if h.Logger != nil {
					h.Logger.Error("Failed to save Security.txt control-plane document", zap.Error(err))
				}
				http.Error(w, "Failed to save Security.txt configuration", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "updated", "revision": document.Revision})
			return
		}

		if err := config.UpdateConfigBatch(updates); err != nil {
			if errors.Is(err, config.ErrConfigValidation) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			h.Logger.Error("Failed to save config", zap.Error(err))
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func overlayErrorPagesSnapshot(snapshot map[string]interface{}, pages config.ErrorPagesConfig) error {
	if err := pages.Validate(); err != nil {
		return fmt.Errorf("validate Error Pages control-plane document: %w", err)
	}
	encoded, err := json.Marshal(pages)
	if err != nil {
		return fmt.Errorf("encode Error Pages control-plane document: %w", err)
	}
	var value map[string]interface{}
	if err := json.Unmarshal(encoded, &value); err != nil {
		return fmt.Errorf("decode Error Pages control-plane document: %w", err)
	}
	modules, ok := snapshot["modules"].(map[string]interface{})
	if !ok {
		modules = make(map[string]interface{})
		snapshot["modules"] = modules
	}
	modules["errorpages"] = value
	return nil
}

func overlaySecurityTXTSnapshot(snapshot map[string]interface{}, securityTXT config.SecurityTXTConfig) error {
	canonical, err := config.CanonicalSecurityTXTConfig(securityTXT)
	if err != nil {
		return fmt.Errorf("validate Security.txt control-plane document: %w", err)
	}
	if canonical != securityTXT {
		return errors.New("Security.txt control-plane document is not canonical")
	}
	snapshot["security_txt"] = map[string]interface{}{"contact": securityTXT.Contact}
	return nil
}

func overlayInfrastructureSnapshot(snapshot map[string]interface{}, infrastructure config.InfrastructureConfig) error {
	canonical, err := config.CanonicalInfrastructureConfig(infrastructure, 0)
	if err != nil {
		return fmt.Errorf("validate infrastructure control-plane document: %w", err)
	}
	if !reflect.DeepEqual(canonical, infrastructure) {
		return errors.New("infrastructure control-plane document is not canonical")
	}
	encoded, err := json.Marshal(infrastructure)
	if err != nil {
		return fmt.Errorf("encode infrastructure control-plane document: %w", err)
	}
	var value map[string]interface{}
	if err := json.Unmarshal(encoded, &value); err != nil {
		return fmt.Errorf("decode infrastructure control-plane document: %w", err)
	}
	snapshot["infrastructure"] = value
	return nil
}

func overlayUpstreamRuntimeSnapshot(snapshot map[string]interface{}, settings config.UpstreamRuntimeSettings) error {
	canonical, err := config.CanonicalUpstreamRuntimeSettings(settings)
	if err != nil {
		return fmt.Errorf("validate upstream runtime control-plane document: %w", err)
	}
	if canonical != settings {
		return errors.New("upstream runtime control-plane document is not canonical")
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("encode upstream runtime control-plane document: %w", err)
	}
	var runtime map[string]interface{}
	if err := json.Unmarshal(encoded, &runtime); err != nil {
		return fmt.Errorf("decode upstream runtime control-plane document: %w", err)
	}
	upstream, ok := snapshot["upstream"].(map[string]interface{})
	if !ok {
		upstream = make(map[string]interface{})
		snapshot["upstream"] = upstream
	}
	for key, value := range runtime {
		upstream[key] = value
	}
	return nil
}

func overlayCircuitBreakerSnapshot(snapshot map[string]interface{}, policy config.CircuitBreakerConfig) error {
	canonical, err := config.CanonicalCircuitBreakerConfig(policy)
	if err != nil {
		return fmt.Errorf("validate circuit-breaker control-plane document: %w", err)
	}
	if canonical != policy {
		return errors.New("circuit-breaker control-plane document is not canonical")
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("encode circuit-breaker control-plane document: %w", err)
	}
	var value map[string]interface{}
	if err := json.Unmarshal(encoded, &value); err != nil {
		return fmt.Errorf("decode circuit-breaker control-plane document: %w", err)
	}
	upstream, ok := snapshot["upstream"].(map[string]interface{})
	if !ok || upstream == nil {
		upstream = make(map[string]interface{})
		snapshot["upstream"] = upstream
	}
	upstream["circuit_breaker"] = value
	return nil
}

func overlayLegacyRoutesSnapshot(snapshot map[string]interface{}, routes map[string]string, groups []config.UpstreamGroup) error {
	canonical, err := config.CanonicalLegacyRoutesForGroups(routes, groups)
	if err != nil {
		return fmt.Errorf("validate legacy host-route control-plane document: %w", err)
	}
	if !reflect.DeepEqual(canonical, routes) {
		return errors.New("legacy host-route control-plane document is not canonical")
	}
	encoded, err := json.Marshal(routes)
	if err != nil {
		return fmt.Errorf("encode legacy host-route control-plane document: %w", err)
	}
	var value map[string]interface{}
	if err := json.Unmarshal(encoded, &value); err != nil {
		return fmt.Errorf("decode legacy host-route control-plane document: %w", err)
	}
	upstream, ok := snapshot["upstream"].(map[string]interface{})
	if !ok || upstream == nil {
		upstream = make(map[string]interface{})
		snapshot["upstream"] = upstream
	}
	upstream["routes"] = value
	return nil
}

func overlayUpstreamGroupsSnapshot(snapshot map[string]interface{}, groups []config.UpstreamGroup) error {
	canonical, err := config.CanonicalUpstreamGroups(groups)
	if err != nil {
		return fmt.Errorf("validate upstream Origin-pool control-plane document: %w", err)
	}
	if !reflect.DeepEqual(canonical, groups) {
		return errors.New("upstream Origin-pool control-plane document is not canonical")
	}
	encoded, err := json.Marshal(groups)
	if err != nil {
		return fmt.Errorf("encode upstream Origin-pool control-plane document: %w", err)
	}
	var value []interface{}
	if err := json.Unmarshal(encoded, &value); err != nil {
		return fmt.Errorf("decode upstream Origin-pool control-plane document: %w", err)
	}
	upstream, ok := snapshot["upstream"].(map[string]interface{})
	if !ok {
		upstream = make(map[string]interface{})
		snapshot["upstream"] = upstream
	}
	upstream["groups"] = value
	return nil
}

func overlayRouteRulesSnapshot(snapshot map[string]interface{}, rules []config.RouteConfig) error {
	canonical, err := config.CanonicalRouteRules(rules)
	if err != nil {
		return fmt.Errorf("validate route-rule control-plane document: %w", err)
	}
	if !reflect.DeepEqual(canonical, rules) {
		return errors.New("route-rule control-plane document is not canonical")
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return fmt.Errorf("encode route-rule control-plane document: %w", err)
	}
	var value []interface{}
	if err := json.Unmarshal(encoded, &value); err != nil {
		return fmt.Errorf("decode route-rule control-plane document: %w", err)
	}
	upstream, ok := snapshot["upstream"].(map[string]interface{})
	if !ok || upstream == nil {
		upstream = make(map[string]interface{})
		snapshot["upstream"] = upstream
	}
	upstream["rules"] = value
	return nil
}

func sanitizedConfigSnapshot() map[string]interface{} {
	encoded, err := json.Marshal(config.GetCurrentConfig())
	if err != nil {
		return map[string]interface{}{}
	}
	var snapshot map[string]interface{}
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return map[string]interface{}{}
	}
	redactSensitiveConfigValues(snapshot)
	return snapshot
}

const redactedConfigValue = "[REDACTED]"

type configImportValidationError struct {
	err error
}

func (e *configImportValidationError) Error() string { return e.err.Error() }
func (e *configImportValidationError) Unwrap() error { return e.err }

func redactSensitiveConfigValues(value interface{}) {
	redactSensitiveConfigValueAtPath(value, nil)
}

func redactSensitiveConfigValueAtPath(value interface{}, path []string) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			childPath := appendConfigPath(path, key)
			if shouldRedactConfigValue(childPath, child) {
				typed[key] = redactedConfigValue
				continue
			}
			redactSensitiveConfigValueAtPath(child, childPath)
		}
	case []interface{}:
		for _, child := range typed {
			redactSensitiveConfigValueAtPath(child, path)
		}
	}
}

func appendConfigPath(path []string, key string) []string {
	childPath := make([]string, len(path)+1)
	copy(childPath, path)
	childPath[len(path)] = key
	return childPath
}

func shouldRedactConfigValue(path []string, value interface{}) bool {
	if len(path) == 0 {
		return false
	}
	return isSensitiveConfigKey(path[len(path)-1]) || isCredentialBearingDatabaseURL(path, value)
}

func isSensitiveConfigKey(key string) bool {
	normalized := normalizeConfigKey(key)
	for _, fragment := range []string{
		"password", "passwd", "passphrase", "secret", "token", "apikey",
		"credential", "privatekey", "accesskey", "signingkey", "licensekey",
		"connectionstring", "dsn", "bearer", "hmackey", "encryptionkey",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func normalizeConfigKey(key string) string {
	return strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(strings.ToLower(key))
}

func isCredentialBearingDatabaseURL(path []string, value interface{}) bool {
	if len(path) < 2 || normalizeConfigKey(path[len(path)-1]) != "url" {
		return false
	}
	parent := normalizeConfigKey(path[len(path)-2])
	if parent != "database" && parent != "analytics" {
		return false
	}
	connectionURL, ok := value.(string)
	if !ok {
		return false
	}
	parsed, err := url.Parse(connectionURL)
	if err != nil {
		return false
	}
	if parsed.User != nil {
		return true
	}
	for queryKey := range parsed.Query() {
		if isSensitiveConfigKey(queryKey) {
			return true
		}
	}
	return false
}

func sanitizedConfigYAML(data []byte) ([]byte, error) {
	var snapshot map[string]interface{}
	if err := yaml.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	redactSensitiveConfigValues(snapshot)
	return yaml.Marshal(snapshot)
}

func readSanitizedConfigYAML(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return sanitizedConfigYAML(data)
}

// HandleUnavailableFeature is a placeholder for routes that are not
// available in the community edition.
func (h *Handler) HandleUnavailableFeature(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "not_available_in_community_edition"})
}

type moduleConfigHandler func(*Handler, http.ResponseWriter, *http.Request)

var (
	captchaConfigHandler    moduleConfigHandler = unavailableModuleConfig
	challengeConfigHandler  moduleConfigHandler = unavailableModuleConfig
	reputationConfigHandler moduleConfigHandler = unavailableModuleConfig
)

func unavailableModuleConfig(h *Handler, w http.ResponseWriter, r *http.Request) {
	h.HandleUnavailableFeature(w, r)
}

// HandleCaptchaConfig, HandleChallengeConfig, and HandleReputationConfig are
// stable public-core route hooks. Commercial overlay files install their
// implementations at init time without importing paid packages into core.
func (h *Handler) HandleCaptchaConfig(w http.ResponseWriter, r *http.Request) {
	if h.CaptchaStore != nil {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			doc, found, err := h.CaptchaStore.LoadCaptcha(r.Context())
			if err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to load captcha configuration", zap.Error(err))
				}
				h.JSONError(w, "Failed to load captcha configuration", http.StatusInternalServerError)
				return
			}
			cfg := config.CaptchaConfig{Enabled: false}
			if found {
				cfg = doc.Config
			}
			_ = json.NewEncoder(w).Encode(cfg)
			return
		case http.MethodPut:
			var next config.CaptchaConfig
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
				h.JSONError(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			actor := "unknown"
			if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
				actor = authenticatedOperator
			}
			doc, err := config.SaveCaptchaControlPlane(r.Context(), h.CaptchaStore, next, actor, "admin_update")
			if err != nil {
				if errors.Is(err, config.ErrCaptchaRevisionConflict) {
					h.JSONError(w, "Captcha configuration changed on the server; reload before saving", http.StatusConflict)
					return
				}
				if h.Logger != nil {
					h.Logger.Error("Failed to save captcha control-plane document", zap.Error(err))
				}
				h.JSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(doc.Config)
			return
		default:
			h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
	captchaConfigHandler(h, w, r)
}

func (h *Handler) HandleChallengeConfig(w http.ResponseWriter, r *http.Request) {
	if h.ChallengeStore != nil {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			doc, found, err := h.ChallengeStore.LoadChallenge(r.Context())
			if err != nil {
				if h.Logger != nil {
					h.Logger.Error("Failed to load challenge configuration", zap.Error(err))
				}
				h.JSONError(w, "Failed to load challenge configuration", http.StatusInternalServerError)
				return
			}
			cfg := config.DefaultChallengeConfig()
			if found {
				cfg = doc.Config
			}
			_ = json.NewEncoder(w).Encode(cfg)
			return
		case http.MethodPut:
			var next config.ChallengeConfig
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
				h.JSONError(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			actor := "unknown"
			if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
				actor = authenticatedOperator
			}
			doc, err := config.SaveChallengeControlPlane(r.Context(), h.ChallengeStore, next, actor, "admin_update")
			if err != nil {
				if errors.Is(err, config.ErrChallengeRevisionConflict) {
					h.JSONError(w, "Challenge configuration changed on the server; reload before saving", http.StatusConflict)
					return
				}
				if h.Logger != nil {
					h.Logger.Error("Failed to save challenge control-plane document", zap.Error(err))
				}
				h.JSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(doc.Config)
			return
		default:
			h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
	challengeConfigHandler(h, w, r)
}

func (h *Handler) HandleReputationConfig(w http.ResponseWriter, r *http.Request) {
	reputationConfigHandler(h, w, r)
}

func (h *Handler) HandleConfigExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := readSanitizedConfigYAML("config.yaml")
	if err != nil {
		h.Logger.Error("Failed to read config export", zap.Error(err))
		http.Error(w, "Failed to read config", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="aegis-config.yaml"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *Handler) HandleConfigBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.rejectIncompleteControlPlaneArchive(w, r) {
		return
	}

	configData, err := readSanitizedConfigYAML("config.yaml")
	if err != nil {
		h.Logger.Error("Failed to read config backup", zap.Error(err))
		http.Error(w, "Failed to read config", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("aegis-backup-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	backupDirs := []string{"config"}
	archiveContents := []string{"config.yaml"}
	if _, err := os.Stat("data/rules"); err == nil {
		backupDirs = append([]string{"data/rules"}, backupDirs...)
		archiveContents = append(archiveContents, "data/rules/")
	} else if _, err := os.Stat("rules"); err == nil {
		backupDirs = append([]string{"rules"}, backupDirs...)
		archiveContents = append(archiveContents, "rules/")
	}
	archiveContents = append(archiveContents, "config/")

	manifest, err := json.Marshal(map[string]interface{}{
		"format":    "aegis-configuration-archive",
		"version":   1,
		"sanitized": true,
		"contents":  archiveContents,
	})
	if err != nil {
		h.Logger.Error("Failed to create backup manifest", zap.Error(err))
		return
	}
	if err := addBackupData(tw, "manifest.json", manifest); err != nil {
		h.Logger.Error("Failed to add manifest to backup", zap.Error(err))
		return
	}
	if err := addBackupData(tw, "config.yaml", configData); err != nil {
		h.Logger.Error("Failed to add config to backup", zap.Error(err))
		return
	}
	for _, dir := range backupDirs {
		if err := addBackupPath(tw, dir, dir); err != nil {
			h.Logger.Warn("Skipping backup path", zap.String("path", dir), zap.Error(err))
		}
	}
}

func (h *Handler) HandleConfigImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(maxConfigImportBytes); err != nil {
		http.Error(w, "Invalid upload", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("config")
	if err != nil {
		http.Error(w, "Missing config file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxConfigImportBytes+1))
	if err != nil {
		http.Error(w, "Failed to read upload", http.StatusBadRequest)
		return
	}
	if len(data) > maxConfigImportBytes {
		http.Error(w, "Upload exceeds the configuration import size limit", http.StatusRequestEntityTooLarge)
		return
	}

	isArchive := isConfigArchive(data)
	var archive configArchive
	if isArchive {
		archive, err = readConfigArchive(data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if h.rejectIncompleteControlPlaneArchive(w, r) {
			return
		}
		data = archive.configData
	}
	var prepared []byte
	err = config.WithConfigMutation(func() error {
		prepared, err = prepareImportedConfig(data)
		if err != nil {
			return &configImportValidationError{err: err}
		}
		if isArchive {
			if err := prepareImportedArchiveFiles(&archive); err != nil {
				return &configImportValidationError{err: err}
			}
		}
		if err := config.ValidateConfigDocument(prepared); err != nil {
			return &configImportValidationError{err: err}
		}
		if isArchive {
			return restoreConfigArchive(prepared, archive)
		}
		return replaceConfigFile(prepared)
	})
	if err != nil {
		var invalidImport *configImportValidationError
		if errors.As(err, &invalidImport) {
			http.Error(w, invalidImport.Error(), http.StatusBadRequest)
			return
		}
		h.Logger.Error("Failed to import config", zap.Error(err))
		http.Error(w, "Failed to import config", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "imported", "restart_required": true, "active_runtime_changed": false})
}

// rejectIncompleteControlPlaneArchive refuses the legacy YAML archive format
// once PostgreSQL is authoritative for any operator-managed document. Writing
// such an archive would promise recoverability while silently omitting the
// active control plane. A standalone YAML import remains available for
// bootstrap settings because it is not represented as a complete backup.
func (h *Handler) rejectIncompleteControlPlaneArchive(w http.ResponseWriter, r *http.Request) bool {
	if h.ControlPlaneDocuments == nil {
		return false
	}
	active, err := h.ControlPlaneDocuments.HasActiveDocuments(r.Context())
	if err != nil {
		if h.Logger != nil {
			h.Logger.Error("Failed to inspect PostgreSQL control-plane documents for configuration recovery", zap.Error(err))
		}
		http.Error(w, "PostgreSQL control-plane configuration is temporarily unavailable", http.StatusServiceUnavailable)
		return true
	}
	if !active {
		return false
	}
	http.Error(w, incompleteControlPlaneArchiveMessage, http.StatusConflict)
	return true
}

func (h *Handler) HandleConfigReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resetConfig := []byte(`server:
  port: 8080
  enable_http3: true
  admin:
    host: 127.0.0.1
    port: 8081
    secure_cookies: false
    username: admin
  tls:
    enabled: false
    auto: false
    cert_dir: data/tls/certs
    cache_dir: data/tls/acme
storage:
  analytics:
    mode: optional
    driver: clickhouse
    host: 127.0.0.1
    port: 9000
    database: aegis
    username: default
    password_secret_ref: env:AEGIS_ANALYTICS_DB_PASSWORD
    secure: false
telemetry:
  prometheus_enabled: false
  prometheus_path: /metrics
  prometheus_token: ""
  request_logging: true
  retention_days: 30
  snapshot_interval: 60
access_log:
  enabled: true
  path: ./logs/access.log
  rotate_size_mb: 100
  keep_files: 14
`)

	if err := config.ValidateConfigDocument(resetConfig); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := config.WithConfigMutation(func() error { return replaceConfigFile(resetConfig) }); err != nil {
		h.Logger.Error("Failed to reset config", zap.Error(err))
		http.Error(w, "Failed to reset config", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "reset", "restart_required": true, "active_runtime_changed": false})
}

func addBackupData(tw *tar.Writer, archivePath string, data []byte) error {
	header := &tar.Header{
		Name: filepath.ToSlash(archivePath),
		Mode: 0600,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func addBackupPath(tw *tar.Writer, sourcePath, archivePath string) error {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return addBackupFile(tw, sourcePath, archivePath, info)
	}
	return filepath.WalkDir(sourcePath, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(sourcePath, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(filepath.Join(archivePath, rel))
		if rel == "." {
			name = archivePath
		}
		if info.IsDir() {
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = strings.TrimSuffix(name, "/") + "/"
			return tw.WriteHeader(header)
		}
		return addBackupFile(tw, path, name, info)
	})
}

func addBackupFile(tw *tar.Writer, sourcePath, archivePath string, info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("backup entry %q is not a regular file", sourcePath)
	}
	if !isYAMLFile(sourcePath) {
		return nil
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = filepath.ToSlash(archivePath)

	data, err := readSanitizedConfigYAML(sourcePath)
	if err != nil {
		return err
	}
	header.Size = int64(len(data))
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err = tw.Write(data)
	return err
}

func isYAMLFile(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	return extension == ".yaml" || extension == ".yml"
}

func validateConfigYAML(data []byte) error {
	var decoded map[string]interface{}
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}
	if len(decoded) == 0 {
		return fmt.Errorf("config file is empty")
	}
	return nil
}

// containsRedactedConfigValue prevents a sanitized export from replacing a
// working secret with the literal redaction marker during a restore.
func containsRedactedConfigValue(data []byte) bool {
	var decoded interface{}
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		return false
	}
	return containsRedactedConfigNode(decoded)
}

func containsRedactedConfigNode(value interface{}) bool {
	switch typed := value.(type) {
	case string:
		return typed == redactedConfigValue
	case map[string]interface{}:
		for _, child := range typed {
			if containsRedactedConfigNode(child) {
				return true
			}
		}
	case map[interface{}]interface{}:
		for _, child := range typed {
			if containsRedactedConfigNode(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range typed {
			if containsRedactedConfigNode(child) {
				return true
			}
		}
	}
	return false
}

func replaceConfigFile(data []byte) error {
	const configPath = "config.yaml"
	if err := config.ValidateConfigDocument(data); err != nil {
		return err
	}
	backupPath := fmt.Sprintf("config.yaml.bak-%s", time.Now().UTC().Format("20060102-150405.000000000"))

	current, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(current) > 0 {
		if err := config.ReplaceConfigFileAtomically(backupPath, current); err != nil {
			return err
		}
	}
	return config.ReplaceConfigFileAtomically(configPath, data)
}
