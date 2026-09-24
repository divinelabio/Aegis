package httpbasic

import (
	"encoding/json"
	"net/http"

	"github.com/divinelab-io/aegis/internal/sections"
)

const (
	appSecurityStatusAvailable      = "available"
	appSecurityStatusUpgrade        = "upgrade"
	appSecurityStatusUnsupported    = "unsupported"
	appSecurityStatusNotImplemented = "not_implemented"
	appSecurityUpgradeFeature       = "http_advanced"
)

type appSecurityFunctionDefinition struct {
	ID          string
	Name        string
	Description string
	Area        string
	Status      string
	ConfigKeys  []string
}

var communityFunctionCatalog = []appSecurityFunctionDefinition{
	{ID: "upload_limit", Name: "Upload Limiter", Description: "Enforce max request body size", Area: "payload", Status: appSecurityStatusAvailable, ConfigKeys: []string{"upload_limit"}},
	{ID: "extension_filter", Name: "Extension Filter", Description: "Block dangerous file extensions", Area: "upload", Status: appSecurityStatusAvailable, ConfigKeys: []string{"extension_filter"}},
	{ID: "method_enforcer", Name: "Method Enforcer", Description: "Block unsafe HTTP methods", Area: "request", Status: appSecurityStatusAvailable, ConfigKeys: []string{"method_enforcer"}},
	{ID: "host_validator", Name: "Host Validator", Description: "Validate Host header", Area: "request", Status: appSecurityStatusAvailable, ConfigKeys: []string{"host_validator"}},
	{ID: "content_type_validator", Name: "Content-Type Validator", Description: "Validate Content-Type on mutations", Area: "request", Status: appSecurityStatusAvailable, ConfigKeys: []string{"content_type_validator"}},
	{ID: "request_size_guard", Name: "Request Size Guard", Description: "Enforce URL/header/query size limits", Area: "request", Status: appSecurityStatusAvailable, ConfigKeys: []string{"request_size_guard"}},
	{ID: "request_body_guard", Name: "Request Body Guard", Description: "Detect parser abuse in JSON, XML, form, multipart, and GraphQL bodies", Area: "payload", Status: appSecurityStatusUpgrade, ConfigKeys: []string{"request_body_guard"}},
	{ID: "upload_protection", Name: "Upload Protection", Description: "Inspect uploaded files for filename, MIME, active content, and archive risk", Area: "upload", Status: appSecurityStatusAvailable, ConfigKeys: []string{"upload_protection"}},
	{ID: "security_headers", Name: "Security Headers", Description: "Inject security response headers", Area: "response", Status: appSecurityStatusAvailable, ConfigKeys: []string{"security_headers"}},
	{ID: "security_txt", Name: "Security.txt", Description: "Publish a public vulnerability disclosure contact", Area: "response", Status: appSecurityStatusAvailable, ConfigKeys: []string{"security_txt.contact"}},
	{ID: "header_manager", Name: "Header Manager", Description: "Add/remove request/response headers", Area: "response", Status: appSecurityStatusAvailable, ConfigKeys: []string{"header_manager"}},
	{ID: "info_hiding", Name: "Info Hiding", Description: "Strip server identity headers", Area: "response", Status: appSecurityStatusAvailable, ConfigKeys: []string{"info_hiding"}},
	{ID: "cookie_hardener", Name: "Cookie Hardener", Description: "Force Secure/HttpOnly/SameSite on cookies", Area: "response", Status: appSecurityStatusAvailable, ConfigKeys: []string{"cookie_hardener"}},
	{ID: "https_redirect", Name: "HTTPS Redirect", Description: "Redirect HTTP to HTTPS", Area: "response", Status: appSecurityStatusAvailable, ConfigKeys: []string{"https_redirect"}},
	{ID: "gzip", Name: "Gzip Compression", Description: "Delivery optimization; excluded from security coverage", Area: "optimization", Status: appSecurityStatusAvailable, ConfigKeys: []string{"gzip"}},
	{ID: "html_injector", Name: "HTML Injector", Description: "Inject HTML snippets into responses", Area: "optimization", Status: appSecurityStatusUnsupported, ConfigKeys: []string{"html_injector"}},
}

var communitySupportedConfigKeys = map[string]struct{}{
	"upload_limit":           {},
	"extension_filter":       {},
	"upload_protection":      {},
	"method_enforcer":        {},
	"host_validator":         {},
	"content_type_validator": {},
	"request_size_guard":     {},
	"security_headers":       {},
	"header_manager":         {},
	"info_hiding":            {},
	"cookie_hardener":        {},
	"https_redirect":         {},
	"gzip":                   {},
}

var communityPaidConfigKeys = map[string]struct{}{
	"request_body_guard": {},
}

func appSecurityFunctionCapability(def appSecurityFunctionDefinition) *sections.FunctionCapability {
	toggleSupported := def.Status == appSecurityStatusAvailable
	if def.ID == "security_txt" {
		toggleSupported = false
	}
	capability := &sections.FunctionCapability{
		Area:               def.Area,
		Status:             def.Status,
		ConfigSupported:    def.Status == appSecurityStatusAvailable,
		RuntimeImplemented: def.Status == appSecurityStatusAvailable,
		ToggleSupported:    toggleSupported,
		ConfigKeys:         def.ConfigKeys,
	}
	switch def.Status {
	case appSecurityStatusUpgrade:
		capability.UpgradeFeature = appSecurityUpgradeFeature
		capability.Reason = "feature_not_entitled"
	case appSecurityStatusUnsupported:
		capability.Reason = "not_supported_in_community"
	case appSecurityStatusNotImplemented:
		capability.Reason = "feature_not_implemented"
	}
	return capability
}

func (s *Section) functionInfo(def appSecurityFunctionDefinition) sections.FunctionInfo {
	return sections.FunctionInfo{
		ID:          def.ID,
		Name:        def.Name,
		Description: def.Description,
		Enabled:     s.functionEnabled(def.ID),
		Category:    "app_security",
		Capability:  appSecurityFunctionCapability(def),
	}
}

func (s *Section) functionEnabled(id string) bool {
	s.mu.RLock()
	config := cloneCommunityConfig(s.config)
	s.mu.RUnlock()
	return functionEnabledInConfig(config, id)
}

func functionEnabledInConfig(config Config, id string) bool {
	switch id {
	case "upload_limit":
		return config.UploadLimit.Enabled
	case "extension_filter":
		return config.ExtensionFilter.Enabled
	case "upload_protection":
		return config.UploadProtection.Enabled
	case "method_enforcer":
		return config.MethodEnforcer.Enabled
	case "host_validator":
		return config.HostValidator.Enabled
	case "content_type_validator":
		return config.ContentTypeValidator.Enabled
	case "request_size_guard":
		return config.RequestSizeGuard.Enabled
	case "security_headers":
		return config.SecurityHeaders.Enabled
	case "security_txt":
		return true
	case "header_manager":
		return config.HeaderManager.Enabled
	case "info_hiding":
		return config.InfoHiding.Enabled
	case "cookie_hardener":
		return config.CookieHardener.Enabled
	case "https_redirect":
		return config.HTTPSRedirect.Enabled
	case "gzip":
		return config.Gzip.Enabled
	default:
		return false
	}
}

func (s *Section) findFunctionInfo(id string) (sections.FunctionInfo, bool) {
	for _, info := range s.ListFunctions() {
		if info.ID == id {
			return info, true
		}
	}
	return sections.FunctionInfo{}, false
}

func settingsFromConfig(c Config) map[string]interface{} {
	data, _ := json.Marshal(c)
	var settings map[string]interface{}
	_ = json.Unmarshal(data, &settings)
	if settings == nil {
		return map[string]interface{}{}
	}
	return settings
}

func writeAppSecurityError(w http.ResponseWriter, status int, code, feature, message, upgradeFeature string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]string{
		"error":   code,
		"section": SectionID,
		"message": message,
	}
	if feature != "" {
		body["feature"] = feature
	}
	if upgradeFeature != "" {
		body["upgrade_feature"] = upgradeFeature
	}
	_ = json.NewEncoder(w).Encode(body)
}

func appSecurityMethodNotAllowed(w http.ResponseWriter) {
	writeAppSecurityError(w, http.StatusMethodNotAllowed, "method_not_allowed", "", "Method not allowed", "")
}
