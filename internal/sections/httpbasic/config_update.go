package httpbasic

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/divinelab-io/aegis/internal/sections"
)

const maxCommunityConfigBytes = 1 << 20

var communityHTTPTokenPattern = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)
var communityExtensionPattern = regexp.MustCompile(`^\.[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$`)

type communityValidationDetail struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func decodeCommunityConfigUpdate(r *http.Request, current sections.SectionConfig) (sections.SectionConfig, bool, int, string, []communityValidationDetail) {
	if r.ContentLength > maxCommunityConfigBytes {
		return current, false, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", []communityValidationDetail{{Code: "BODY_TOO_LARGE", Message: "Configuration body exceeds 1 MiB."}}
	}
	if r.Body == nil {
		return current, false, http.StatusBadRequest, "INVALID_CONFIGURATION", []communityValidationDetail{{Code: "INVALID_BODY", Message: "Invalid request body."}}
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxCommunityConfigBytes+1))
	if err != nil {
		return current, false, http.StatusBadRequest, "INVALID_CONFIGURATION", []communityValidationDetail{{Code: "INVALID_BODY", Message: "Invalid request body."}}
	}
	if len(data) > maxCommunityConfigBytes {
		return current, false, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", []communityValidationDetail{{Code: "BODY_TOO_LARGE", Message: "Configuration body exceeds 1 MiB."}}
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var incoming map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&incoming); err != nil || incoming == nil {
		return current, false, http.StatusBadRequest, "INVALID_CONFIGURATION", []communityValidationDetail{{Code: "INVALID_JSON", Message: "Expected one JSON object."}}
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return current, false, http.StatusBadRequest, "INVALID_CONFIGURATION", []communityValidationDetail{{Code: "INVALID_JSON", Message: "Only one JSON object is allowed."}}
	}
	input := sections.SectionConfig{Enabled: current.Enabled, ProtectionLevel: current.ProtectionLevel, Settings: cloneMap(current.Settings)}
	if raw, ok := incoming["enabled"]; ok {
		enabled, valid := raw.(bool)
		if !valid {
			return current, false, http.StatusUnprocessableEntity, "VALIDATION_ERROR", []communityValidationDetail{{Path: "enabled", Code: "INVALID_TYPE", Message: "Enabled must be a boolean."}}
		}
		input.Enabled = enabled
		delete(incoming, "enabled")
	}
	if raw, ok := incoming["protection_level"]; ok {
		level, valid := numericInt(raw)
		if !valid || level < 0 || level > 5 {
			return current, false, http.StatusUnprocessableEntity, "VALIDATION_ERROR", []communityValidationDetail{{Path: "protection_level", Code: "OUT_OF_RANGE", Message: "Protection level must be between 0 and 5."}}
		}
		input.ProtectionLevel = level
		delete(incoming, "protection_level")
	}
	for key := range incoming {
		if _, paid := communityPaidConfigKeys[key]; paid {
			return current, false, http.StatusForbidden, "FEATURE_NOT_ENTITLED", []communityValidationDetail{{Path: key, Code: "FEATURE_NOT_ENTITLED", Message: key + " requires App Security advanced features."}}
		}
		if _, supported := communitySupportedConfigKeys[key]; !supported {
			return current, false, http.StatusUnprocessableEntity, "UNKNOWN_FIELD", []communityValidationDetail{{Path: key, Code: "UNKNOWN_FIELD", Message: key + " is not supported by the community App Security build."}}
		}
	}
	deepMergeCommunityJSON(input.Settings, incoming)
	merged, _ := json.Marshal(input.Settings)
	strict := json.NewDecoder(bytes.NewReader(merged))
	strict.DisallowUnknownFields()
	var cfg Config
	if err := strict.Decode(&cfg); err != nil {
		return current, false, http.StatusUnprocessableEntity, "UNKNOWN_FIELD", []communityValidationDetail{{Code: "UNKNOWN_FIELD", Message: "Configuration contains an unknown or invalid field."}}
	}
	if err := validate(cfg); err != nil {
		return current, false, http.StatusUnprocessableEntity, "VALIDATION_ERROR", []communityValidationDetail{{Code: "INVALID_CONFIGURATION", Message: err.Error()}}
	}
	details := validateCommunityHeaders(cfg)
	if len(details) > 0 {
		return current, false, http.StatusUnprocessableEntity, "VALIDATION_ERROR", details
	}
	input.Settings = settingsFromConfig(cfg)
	partial := len(incoming) < len(communitySupportedConfigKeys)
	return input, partial, 0, "", nil
}

func deepMergeCommunityJSON(dst, src map[string]interface{}) {
	for key, value := range src {
		if srcMap, ok := value.(map[string]interface{}); ok {
			if dstMap, ok := dst[key].(map[string]interface{}); ok {
				deepMergeCommunityJSON(dstMap, srcMap)
				continue
			}
		}
		dst[key] = value
	}
}

func validateCommunityHeaders(cfg Config) []communityValidationDetail {
	var details []communityValidationDetail
	for path, value := range map[string]string{
		"security_headers.hsts":               cfg.SecurityHeaders.HSTS,
		"security_headers.csp":                cfg.SecurityHeaders.CSP,
		"security_headers.permissions_policy": cfg.SecurityHeaders.PermissionsPolicy,
	} {
		if strings.ContainsAny(value, "\r\n\x00") {
			details = append(details, communityValidationDetail{Path: path, Code: "INVALID_HEADER_VALUE", Message: "Security policy values cannot contain CR, LF, or NUL characters."})
		}
	}
	for _, name := range cfg.InfoHiding.StripHeaders {
		if !communityHTTPTokenPattern.MatchString(name) {
			details = append(details, communityValidationDetail{Path: "info_hiding.strip_headers", Code: "INVALID_HEADER_NAME", Message: "Header names must be valid HTTP tokens."})
			break
		}
	}
	for field, methods := range map[string][]string{"method_enforcer.allowed_methods": cfg.MethodEnforcer.AllowedMethods, "method_enforcer.blocked_methods": cfg.MethodEnforcer.BlockedMethods, "content_type_validator.required_on": cfg.ContentTypeValidator.RequiredOn} {
		for _, method := range methods {
			if !communityHTTPTokenPattern.MatchString(method) || method != strings.ToUpper(method) {
				details = append(details, communityValidationDetail{Path: field, Code: "INVALID_HTTP_METHOD", Message: "HTTP methods must be uppercase valid tokens."})
				break
			}
		}
	}
	for _, extension := range cfg.ExtensionFilter.BlockedExtensions {
		if !communityExtensionPattern.MatchString(extension) {
			details = append(details, communityValidationDetail{Path: "extension_filter.blocked_extensions", Code: "INVALID_EXTENSION", Message: "Extensions must start with a dot and contain only safe extension characters."})
			break
		}
	}
	for path, value := range map[string]int{"request_size_guard.max_url_length": cfg.RequestSizeGuard.MaxURLLength, "request_size_guard.max_query_length": cfg.RequestSizeGuard.MaxQueryLength, "request_size_guard.max_header_count": cfg.RequestSizeGuard.MaxHeaderCount, "request_size_guard.max_single_header_size": cfg.RequestSizeGuard.MaxSingleHeaderSize, "gzip.min_size": cfg.Gzip.MinSize} {
		if value < 0 || value > 1<<30 {
			details = append(details, communityValidationDetail{Path: path, Code: "OUT_OF_RANGE", Message: "Numeric limits must be non-negative and within the documented upper bound."})
		}
	}
	if cfg.CookieHardener.ForceSameSite != "" && cfg.CookieHardener.ForceSameSite != "Strict" && cfg.CookieHardener.ForceSameSite != "Lax" && cfg.CookieHardener.ForceSameSite != "None" {
		details = append(details, communityValidationDetail{Path: "cookie_hardener.force_samesite", Code: "INVALID_ENUM", Message: "SameSite must be Strict, Lax, None, or empty."})
	}
	if cfg.CookieHardener.ForceSameSite == "None" && !cfg.CookieHardener.ForceSecure {
		details = append(details, communityValidationDetail{Path: "cookie_hardener.force_secure", Code: "INSECURE_COOKIE_POLICY", Message: "SameSite=None requires Secure cookies."})
	}
	if strings.Contains(strings.ToLower(cfg.SecurityHeaders.CSP), "'unsafe-eval'") {
		details = append(details, communityValidationDetail{Path: "security_headers.csp", Code: "UNSAFE_DIRECTIVE", Message: "Strict mode cannot include unsafe-eval."})
	}
	if strings.TrimSpace(cfg.SecurityHeaders.PermissionsPolicy) != "" {
		for _, entry := range strings.Split(cfg.SecurityHeaders.PermissionsPolicy, ",") {
			parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
			if len(parts) != 2 || !communityHTTPTokenPattern.MatchString(strings.TrimSpace(parts[0])) || strings.TrimSpace(parts[1]) == "" {
				details = append(details, communityValidationDetail{Path: "security_headers.permissions_policy", Code: "INVALID_POLICY", Message: "Permissions Policy entries must use feature=allowlist syntax."})
				break
			}
		}
	}
	if cfg.HeaderManager.Enabled {
		for k, v := range cfg.HeaderManager.AddRequestHeaders {
			if !communityHTTPTokenPattern.MatchString(k) {
				details = append(details, communityValidationDetail{Path: "header_manager.add_request_headers", Code: "INVALID_HEADER_NAME", Message: "Header names must be valid HTTP tokens."})
				break
			}
			if strings.ContainsAny(v, "\r\n\x00") {
				details = append(details, communityValidationDetail{Path: "header_manager.add_request_headers", Code: "INVALID_HEADER_VALUE", Message: "Header values cannot contain CR, LF, or NUL characters."})
				break
			}
		}
		for _, k := range cfg.HeaderManager.RemoveRequestHeaders {
			if !communityHTTPTokenPattern.MatchString(k) {
				details = append(details, communityValidationDetail{Path: "header_manager.remove_request_headers", Code: "INVALID_HEADER_NAME", Message: "Header names must be valid HTTP tokens."})
				break
			}
		}
		for k, v := range cfg.HeaderManager.AddResponseHeaders {
			if !communityHTTPTokenPattern.MatchString(k) {
				details = append(details, communityValidationDetail{Path: "header_manager.add_response_headers", Code: "INVALID_HEADER_NAME", Message: "Header names must be valid HTTP tokens."})
				break
			}
			if strings.ContainsAny(v, "\r\n\x00") {
				details = append(details, communityValidationDetail{Path: "header_manager.add_response_headers", Code: "INVALID_HEADER_VALUE", Message: "Header values cannot contain CR, LF, or NUL characters."})
				break
			}
		}
		for _, k := range cfg.HeaderManager.RemoveResponseHeaders {
			if !communityHTTPTokenPattern.MatchString(k) {
				details = append(details, communityValidationDetail{Path: "header_manager.remove_response_headers", Code: "INVALID_HEADER_NAME", Message: "Header names must be valid HTTP tokens."})
				break
			}
		}
	}
	if cfg.HTTPSRedirect.StatusCode != 0 &&
		cfg.HTTPSRedirect.StatusCode != http.StatusMovedPermanently &&
		cfg.HTTPSRedirect.StatusCode != http.StatusFound &&
		cfg.HTTPSRedirect.StatusCode != http.StatusTemporaryRedirect &&
		cfg.HTTPSRedirect.StatusCode != http.StatusPermanentRedirect {
		details = append(details, communityValidationDetail{Path: "https_redirect.status_code", Code: "INVALID_STATUS_CODE", Message: "HTTPS redirect status code must be 301, 302, 307, or 308."})
	}
	if cfg.UploadProtection.Mode != "" &&
		!strings.EqualFold(cfg.UploadProtection.Mode, "allow") &&
		!strings.EqualFold(cfg.UploadProtection.Mode, "detect") &&
		!strings.EqualFold(cfg.UploadProtection.Mode, "block") {
		details = append(details, communityValidationDetail{Path: "upload_protection.mode", Code: "INVALID_ENUM", Message: "Upload protection mode must be allow, detect, or block."})
	}
	return details
}

func writeCommunityConfigError(w http.ResponseWriter, status int, code string, details []communityValidationDetail) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]interface{}{"code": code, "message": "The App Security configuration is invalid.", "details": details}})
}

func cloneCommunityConfig(cfg Config) Config {
	data, _ := json.Marshal(cfg)
	var cloned Config
	_ = json.Unmarshal(data, &cloned)
	return cloned
}
