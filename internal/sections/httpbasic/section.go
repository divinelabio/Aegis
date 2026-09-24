// Package httpbasic implements the Community HTTP hardening layer. Structural
// body inspection and deep upload analysis are commercial overlay features.
package httpbasic

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/transport"
	"github.com/divinelab-io/aegis/internal/sections"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
)

const (
	SectionID   = "http_security"
	SectionName = "HTTP Security"
)

type Config struct {
	UploadLimit struct {
		Enabled     bool   `json:"enabled" mapstructure:"enabled"`
		MaxBodySize string `json:"max_body_size" mapstructure:"max_body_size"`
	} `json:"upload_limit" mapstructure:"upload_limit"`
	ExtensionFilter struct {
		Enabled           bool     `json:"enabled" mapstructure:"enabled"`
		BlockedExtensions []string `json:"blocked_extensions" mapstructure:"blocked_extensions"`
	} `json:"extension_filter" mapstructure:"extension_filter"`
	UploadProtection UploadProtectionConfig `json:"upload_protection" mapstructure:"upload_protection"`
	MethodEnforcer struct {
		Enabled        bool     `json:"enabled" mapstructure:"enabled"`
		Mode           string   `json:"mode" mapstructure:"mode"`
		BlockedMethods []string `json:"blocked_methods" mapstructure:"blocked_methods"`
		AllowedMethods []string `json:"allowed_methods" mapstructure:"allowed_methods"`
	} `json:"method_enforcer" mapstructure:"method_enforcer"`
	HostValidator struct {
		Enabled      bool     `json:"enabled" mapstructure:"enabled"`
		AllowedHosts []string `json:"allowed_hosts" mapstructure:"allowed_hosts"`
	} `json:"host_validator" mapstructure:"host_validator"`
	ContentTypeValidator struct {
		Enabled    bool     `json:"enabled" mapstructure:"enabled"`
		RequiredOn []string `json:"required_on" mapstructure:"required_on"`
	} `json:"content_type_validator" mapstructure:"content_type_validator"`
	RequestSizeGuard struct {
		Enabled             bool `json:"enabled" mapstructure:"enabled"`
		MaxURLLength        int  `json:"max_url_length" mapstructure:"max_url_length"`
		MaxHeaderCount      int  `json:"max_header_count" mapstructure:"max_header_count"`
		MaxSingleHeaderSize int  `json:"max_single_header_size" mapstructure:"max_single_header_size"`
		MaxQueryLength      int  `json:"max_query_length" mapstructure:"max_query_length"`
	} `json:"request_size_guard" mapstructure:"request_size_guard"`
	SecurityHeaders struct {
		Enabled           bool   `json:"enabled" mapstructure:"enabled"`
		HSTS              string `json:"hsts" mapstructure:"hsts"`
		XFrameOptions     string `json:"x_frame_options" mapstructure:"x_frame_options"`
		XContentTypeOpts  string `json:"x_content_type_options" mapstructure:"x_content_type_options"`
		ReferrerPolicy    string `json:"referrer_policy" mapstructure:"referrer_policy"`
		CSP               string `json:"csp" mapstructure:"csp"`
		PermissionsPolicy string `json:"permissions_policy" mapstructure:"permissions_policy"`
	} `json:"security_headers" mapstructure:"security_headers"`
	InfoHiding struct {
		Enabled      bool     `json:"enabled" mapstructure:"enabled"`
		StripHeaders []string `json:"strip_headers" mapstructure:"strip_headers"`
	} `json:"info_hiding" mapstructure:"info_hiding"`
	HeaderManager struct {
		Enabled               bool              `json:"enabled" mapstructure:"enabled"`
		AddRequestHeaders     map[string]string `json:"add_request_headers" mapstructure:"add_request_headers"`
		RemoveRequestHeaders  []string          `json:"remove_request_headers" mapstructure:"remove_request_headers"`
		AddResponseHeaders    map[string]string `json:"add_response_headers" mapstructure:"add_response_headers"`
		RemoveResponseHeaders []string          `json:"remove_response_headers" mapstructure:"remove_response_headers"`
	} `json:"header_manager" mapstructure:"header_manager"`
	HTTPSRedirect struct {
		Enabled    bool `json:"enabled" mapstructure:"enabled"`
		StatusCode int  `json:"status_code" mapstructure:"status_code"`
	} `json:"https_redirect" mapstructure:"https_redirect"`
	CookieHardener struct {
		Enabled       bool   `json:"enabled" mapstructure:"enabled"`
		ForceSecure   bool   `json:"force_secure" mapstructure:"force_secure"`
		ForceHTTPOnly bool   `json:"force_httponly" mapstructure:"force_httponly"`
		ForceSameSite string `json:"force_samesite" mapstructure:"force_samesite"`
	} `json:"cookie_hardener" mapstructure:"cookie_hardener"`
	Gzip struct {
		Enabled      bool     `json:"enabled" mapstructure:"enabled"`
		MinSize      int      `json:"min_size" mapstructure:"min_size"`
		ContentTypes []string `json:"content_types" mapstructure:"content_types"`
		Level        int      `json:"level" mapstructure:"level"`
	} `json:"gzip" mapstructure:"gzip"`
}

type Section struct {
	logger     *zap.Logger
	mu         sync.RWMutex
	enabled    bool
	protection int
	config     Config
	settings   map[string]interface{}
	started    atomic.Bool
	total      atomic.Int64
	blocked    atomic.Int64
	allowed    atomic.Int64
	compressed atomic.Int64
	persist    sections.SectionConfigPersister
}

func New(logger *zap.Logger, persisters ...sections.SectionConfigPersister) *Section {
	if logger == nil {
		logger = zap.NewNop()
	}
	section := &Section{logger: logger, enabled: true, protection: 3, config: defaultConfig(), settings: map[string]interface{}{}}
	if len(persisters) > 0 {
		section.persist = persisters[0]
	}
	return section
}

func defaultConfig() Config {
	var c Config
	c.UploadLimit.Enabled, c.UploadLimit.MaxBodySize = true, "10MB"
	c.ExtensionFilter.Enabled = true
	c.ExtensionFilter.BlockedExtensions = []string{".exe", ".php", ".sh", ".bat", ".cmd", ".jsp", ".cgi"}
	c.UploadProtection = DefaultUploadProtectionConfig()
	c.MethodEnforcer.Enabled, c.MethodEnforcer.Mode = true, "blocklist"
	c.MethodEnforcer.BlockedMethods = []string{"TRACE", "TRACK", "CONNECT", "DEBUG"}
	c.ContentTypeValidator.Enabled = true
	c.ContentTypeValidator.RequiredOn = []string{"POST", "PUT", "PATCH"}
	c.RequestSizeGuard.Enabled = true
	c.RequestSizeGuard.MaxURLLength, c.RequestSizeGuard.MaxHeaderCount = 2048, 50
	c.RequestSizeGuard.MaxSingleHeaderSize, c.RequestSizeGuard.MaxQueryLength = 8192, 2048
	c.SecurityHeaders.Enabled = true
	c.SecurityHeaders.HSTS = "max-age=31536000; includeSubDomains"
	c.SecurityHeaders.XFrameOptions, c.SecurityHeaders.XContentTypeOpts = "DENY", "nosniff"
	c.SecurityHeaders.ReferrerPolicy = "strict-origin-when-cross-origin"
	c.HeaderManager.Enabled = false
	c.HeaderManager.AddRequestHeaders = make(map[string]string)
	c.HeaderManager.RemoveRequestHeaders = []string{}
	c.HeaderManager.AddResponseHeaders = make(map[string]string)
	c.HeaderManager.RemoveResponseHeaders = []string{}
	c.HTTPSRedirect.Enabled = false
	c.HTTPSRedirect.StatusCode = http.StatusMovedPermanently
	c.InfoHiding.Enabled, c.InfoHiding.StripHeaders = true, []string{"Server", "X-Powered-By", "X-AspNet-Version"}
	c.CookieHardener.Enabled, c.CookieHardener.ForceSecure, c.CookieHardener.ForceHTTPOnly = true, true, true
	c.CookieHardener.ForceSameSite = "Lax"
	c.Gzip.Enabled, c.Gzip.MinSize, c.Gzip.Level = true, 1024, 6
	c.Gzip.ContentTypes = []string{"text/html", "text/css", "application/javascript", "application/json", "text/xml"}
	return c
}

func (s *Section) Name() string                { return SectionName }
func (s *Section) ID() string                  { return SectionID }
func (*Section) AlwaysInstallMiddleware() bool { return true }
func (s *Section) Description() string {
	return "HTTP headers, cookies, methods, content validation, upload limits, and gzip"
}
func (s *Section) Icon() string      { return "globe-lock" }
func (s *Section) Enabled() bool     { s.mu.RLock(); defer s.mu.RUnlock(); return s.enabled }
func (s *Section) SetEnabled(v bool) { s.mu.Lock(); s.enabled = v; s.mu.Unlock() }

func (s *Section) Init(input sections.SectionConfig) error {
	c := defaultConfig()
	if err := mapstructure.Decode(input.Settings, &c); err != nil {
		return err
	}
	if err := validate(c); err != nil {
		return err
	}
	s.mu.Lock()
	s.enabled, s.protection, s.config, s.settings = input.Enabled, input.ProtectionLevel, c, settingsFromConfig(c)
	s.mu.Unlock()
	return nil
}
func (s *Section) Start(context.Context) error           { s.started.Store(true); return nil }
func (s *Section) Stop(context.Context) error            { s.started.Store(false); return nil }
func (s *Section) Reload(c sections.SectionConfig) error { return s.Init(c) }
func (s *Section) GetConfig() sections.SectionConfig {
	s.mu.RLock()
	config := cloneCommunityConfig(s.config)
	enabled := s.enabled
	protection := s.protection
	s.mu.RUnlock()
	return sections.SectionConfig{Enabled: enabled, ProtectionLevel: protection, Settings: settingsFromConfig(config)}
}
func (s *Section) UpdateConfig(input sections.SectionConfig) error {
	for key := range input.Settings {
		if _, ok := communityPaidConfigKeys[key]; ok {
			return sections.ErrFeatureNotEntitled
		}
		if _, ok := communitySupportedConfigKeys[key]; !ok {
			return sections.ErrUnsupportedConfigKey
		}
	}
	c := defaultConfig()
	if err := mapstructure.Decode(input.Settings, &c); err != nil {
		return err
	}
	if err := validate(c); err != nil {
		return err
	}
	if s.persist != nil {
		if err := s.persist(SectionID, sections.SectionConfig{
			Enabled: input.Enabled, ProtectionLevel: input.ProtectionLevel, Settings: settingsFromConfig(c),
		}); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.config = cloneCommunityConfig(c)
	s.enabled = input.Enabled
	s.protection = input.ProtectionLevel
	s.settings = settingsFromConfig(c)
	s.mu.Unlock()
	return nil
}

func validate(c Config) error {
	bodySize := parseSize(c.UploadLimit.MaxBodySize)
	if c.UploadLimit.Enabled && (bodySize <= 0 || bodySize > 1<<30) {
		return errors.New("upload body limit is invalid")
	}
	if c.MethodEnforcer.Mode != "blocklist" && c.MethodEnforcer.Mode != "allowlist" {
		return errors.New("method policy mode is invalid")
	}
	if c.Gzip.Level < gzip.HuffmanOnly || c.Gzip.Level > gzip.BestCompression {
		return errors.New("gzip level is invalid")
	}
	if c.HTTPSRedirect.StatusCode != 0 &&
		c.HTTPSRedirect.StatusCode != http.StatusMovedPermanently &&
		c.HTTPSRedirect.StatusCode != http.StatusFound &&
		c.HTTPSRedirect.StatusCode != http.StatusTemporaryRedirect &&
		c.HTTPSRedirect.StatusCode != http.StatusPermanentRedirect {
		return errors.New("https redirect status code is invalid")
	}
	return nil
}

func (s *Section) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		c := cloneCommunityConfig(s.config)
		enabled := s.enabled
		s.mu.RUnlock()
		if !enabled {
			next.ServeHTTP(w, r)
			return
		}
		if !transport.RouteAllowsSection(r, SectionID) {
			next.ServeHTTP(w, r)
			return
		}
		s.total.Add(1)

		writeErrorResponse := func(status int, reason string) {
			s.blocked.Add(1)
			if !transport.WriteConfiguredErrorPage(w, r, status) {
				http.Error(w, reason, status)
			}
		}

		if c.HTTPSRedirect.Enabled && r.TLS == nil && !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			statusCode := c.HTTPSRedirect.StatusCode
			if statusCode == 0 {
				statusCode = http.StatusMovedPermanently
			}
			host := r.Host
			if host == "" {
				host = "localhost"
			}
			target := "https://" + host + r.URL.RequestURI()
			http.Redirect(w, r, target, statusCode)
			return
		}

		if c.HeaderManager.Enabled {
			for k, v := range c.HeaderManager.AddRequestHeaders {
				r.Header.Set(k, v)
			}
			for _, k := range c.HeaderManager.RemoveRequestHeaders {
				r.Header.Del(k)
			}
		}

		if status, reason := validateRequest(r, c); status != 0 {
			if status == http.StatusMethodNotAllowed && c.MethodEnforcer.Mode == "allowlist" && len(c.MethodEnforcer.AllowedMethods) > 0 {
				w.Header().Set("Allow", strings.Join(c.MethodEnforcer.AllowedMethods, ", "))
			}
			writeErrorResponse(status, reason)
			return
		}

		maxBody := parseSize(c.UploadLimit.MaxBodySize)
		if (c.UploadProtection.Enabled || c.ExtensionFilter.Enabled) && isMultipart(r) {
			max := maxBody
			if !c.UploadLimit.Enabled || max <= 0 {
				max = 32 << 20
			}
			if c.UploadProtection.Enabled && c.UploadProtection.MaxTotalUploadSize > max {
				max = c.UploadProtection.MaxTotalUploadSize
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
			if err != nil || int64(len(body)) > max {
				writeErrorResponse(http.StatusRequestEntityTooLarge, "Request body too large")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			if err := validateMultipartBody(r.Header.Get("Content-Type"), body); err != nil {
				writeErrorResponse(http.StatusBadRequest, "Malformed multipart request")
				return
			}
			if c.ExtensionFilter.Enabled && blockedUpload(body, r.Header.Get("Content-Type"), c.ExtensionFilter.BlockedExtensions) {
				writeErrorResponse(http.StatusForbidden, "File extension is not allowed")
				return
			}
			if c.UploadProtection.Enabled {
				uploadResult := NewUploadProtectionEngine(c.UploadProtection).Inspect(r, body, false)
				if uploadResult.Blocked() && !strings.EqualFold(c.UploadProtection.Mode, "detect") {
					writeErrorResponse(http.StatusForbidden, "Forbidden - Upload Protection")
					return
				}
			}
		} else if c.UploadLimit.Enabled && maxBody > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}

		writer := &responseWriter{underlying: w, status: http.StatusOK, config: c, acceptsGzip: strings.Contains(r.Header.Get("Accept-Encoding"), "gzip"), passthrough: requestSkipsResponseBuffer(r)}
		next.ServeHTTP(writer, r)
		if writer.finish() {
			s.compressed.Add(1)
		}
		s.allowed.Add(1)
	})
}

func validateRequest(r *http.Request, c Config) (int, string) {
	if c.UploadLimit.Enabled {
		max := parseSize(c.UploadLimit.MaxBodySize)
		if max > 0 && r.ContentLength > max {
			return http.StatusRequestEntityTooLarge, "Request body too large"
		}
	}
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if c.MethodEnforcer.Enabled {
		if c.MethodEnforcer.Mode == "allowlist" && !containsFold(c.MethodEnforcer.AllowedMethods, method) {
			return http.StatusMethodNotAllowed, "Method not allowed"
		}
		if c.MethodEnforcer.Mode == "blocklist" && containsFold(c.MethodEnforcer.BlockedMethods, method) {
			return http.StatusMethodNotAllowed, "Method not allowed"
		}
	}
	if c.HostValidator.Enabled && len(c.HostValidator.AllowedHosts) > 0 && !hostAllowed(r.Host, c.HostValidator.AllowedHosts) {
		return http.StatusBadRequest, "Host is not allowed"
	}
	if c.ContentTypeValidator.Enabled && containsFold(c.ContentTypeValidator.RequiredOn, method) {
		if _, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil {
			return http.StatusUnsupportedMediaType, "Valid Content-Type is required"
		}
	}
	if c.RequestSizeGuard.Enabled {
		rawURI := r.RequestURI
		if rawURI == "" {
			rawURI = r.URL.String()
		}
		if c.RequestSizeGuard.MaxURLLength > 0 && len(rawURI) > c.RequestSizeGuard.MaxURLLength || c.RequestSizeGuard.MaxQueryLength > 0 && len(r.URL.RawQuery) > c.RequestSizeGuard.MaxQueryLength {
			return http.StatusRequestURITooLong, "Request URI is too long"
		}
		if c.RequestSizeGuard.MaxHeaderCount > 0 && len(r.Header) > c.RequestSizeGuard.MaxHeaderCount {
			return http.StatusRequestHeaderFieldsTooLarge, "Too many headers"
		}
		for name, values := range r.Header {
			for _, value := range values {
				if c.RequestSizeGuard.MaxSingleHeaderSize > 0 && len(name)+len(value) > c.RequestSizeGuard.MaxSingleHeaderSize {
					return http.StatusRequestHeaderFieldsTooLarge, "Header is too large"
				}
			}
		}
	}
	return 0, ""
}

const maxHTTPBasicCompressionBuffer = 8 << 20 // 8 MiB buffer limit

type responseWriter struct {
	underlying  http.ResponseWriter
	status      int
	wroteHeader bool
	body        bytes.Buffer
	config      Config
	acceptsGzip bool
	passthrough bool
}

func (w *responseWriter) Header() http.Header { return w.underlying.Header() }
func (w *responseWriter) WriteHeader(status int) {
	if w.status == http.StatusOK {
		w.status = status
	}
	if w.passthrough {
		if !w.wroteHeader {
			w.wroteHeader = true
			applyHeaders(w.Header(), w.config)
			w.underlying.WriteHeader(status)
		}
	}
}
func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.passthrough && (strings.HasPrefix(strings.ToLower(w.Header().Get("Content-Type")), "text/event-stream") ||
		w.Header().Get("Trailer") != "" ||
		w.body.Len()+len(data) > maxHTTPBasicCompressionBuffer) {
		w.commitBuffered()
		w.passthrough = true
	}
	if w.passthrough {
		if !w.wroteHeader {
			w.WriteHeader(w.status)
		}
		return w.underlying.Write(data)
	}
	return w.body.Write(data)
}

func (w *responseWriter) commitBuffered() {
	if !w.wroteHeader {
		w.wroteHeader = true
		applyHeaders(w.Header(), w.config)
		w.underlying.WriteHeader(w.status)
	}
	if w.body.Len() > 0 {
		_, _ = w.underlying.Write(w.body.Bytes())
		w.body.Reset()
	}
}

func (w *responseWriter) finish() bool {
	if w.passthrough {
		if !w.wroteHeader {
			w.WriteHeader(w.status)
		}
		return false
	}
	applyHeaders(w.Header(), w.config)
	if w.status == http.StatusNoContent || w.status == http.StatusNotModified {
		w.Header().Del("Content-Length")
		w.underlying.WriteHeader(w.status)
		return false
	}
	body := w.body.Bytes()
	compressed := false
	if w.config.Gzip.Enabled && w.acceptsGzip && w.Header().Get("Content-Encoding") == "" && w.Header().Get("Content-Range") == "" && len(body) >= w.config.Gzip.MinSize && compressible(w.Header().Get("Content-Type"), w.config.Gzip.ContentTypes) {
		var output bytes.Buffer
		gz, err := gzip.NewWriterLevel(&output, w.config.Gzip.Level)
		if err == nil {
			_, _ = gz.Write(body)
			_ = gz.Close()
			body = output.Bytes()
			compressed = true
			w.Header().Set("Content-Encoding", "gzip")
			appendCommunityVary(w.Header(), "Accept-Encoding")
		}
	}
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.underlying.WriteHeader(w.status)
	_, _ = w.underlying.Write(body)
	return compressed
}

func (w *responseWriter) Flush() {
	w.commitBuffered()
	w.passthrough = true
	if flusher, ok := w.underlying.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.underlying.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	w.commitBuffered()
	w.passthrough = true
	return hijacker.Hijack()
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.underlying }

func requestSkipsResponseBuffer(r *http.Request) bool {
	return r.Header.Get("Range") != "" || strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func applyHeaders(header http.Header, c Config) {
	if c.SecurityHeaders.Enabled {
		values := map[string]string{
			"Strict-Transport-Security": c.SecurityHeaders.HSTS,
			"X-Frame-Options":           c.SecurityHeaders.XFrameOptions,
			"X-Content-Type-Options":    c.SecurityHeaders.XContentTypeOpts,
			"Referrer-Policy":           c.SecurityHeaders.ReferrerPolicy,
			"Content-Security-Policy":   c.SecurityHeaders.CSP,
			"Permissions-Policy":        c.SecurityHeaders.PermissionsPolicy,
		}
		for key, value := range values {
			if value != "" {
				header.Set(key, value)
			}
		}
	}
	if c.HeaderManager.Enabled {
		for k, v := range c.HeaderManager.AddResponseHeaders {
			header.Set(k, v)
		}
		for _, k := range c.HeaderManager.RemoveResponseHeaders {
			header.Del(k)
		}
	}
	if c.InfoHiding.Enabled {
		for _, key := range c.InfoHiding.StripHeaders {
			header.Del(key)
		}
	}
	if c.CookieHardener.Enabled {
		cookies := header.Values("Set-Cookie")
		header.Del("Set-Cookie")
		for _, cookie := range cookies {
			attributes := map[string]struct{}{}
			parts := strings.Split(cookie, ";")
			for _, raw := range parts[1:] {
				name, _, _ := strings.Cut(strings.TrimSpace(raw), "=")
				attributes[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
			}
			if _, exists := attributes["secure"]; c.CookieHardener.ForceSecure && !exists {
				cookie += "; Secure"
			}
			if _, exists := attributes["httponly"]; c.CookieHardener.ForceHTTPOnly && !exists {
				cookie += "; HttpOnly"
			}
			if _, exists := attributes["samesite"]; c.CookieHardener.ForceSameSite != "" && !exists {
				cookie += "; SameSite=" + c.CookieHardener.ForceSameSite
			}
			header.Add("Set-Cookie", cookie)
		}
	}
}

func appendCommunityVary(header http.Header, value string) {
	for _, existing := range header.Values("Vary") {
		for _, token := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(token), value) {
				return
			}
		}
	}
	header.Add("Vary", value)
}

func (s *Section) Stats() sections.SectionStats {
	return sections.SectionStats{Name: SectionName, Enabled: s.Enabled(), TotalRequests: s.total.Load(), BlockedRequests: s.blocked.Load(), AllowedRequests: s.allowed.Load(), Custom: map[string]interface{}{"responses_compressed": s.compressed.Load()}, UpdatedAt: time.Now().UTC()}
}
func (s *Section) Health() sections.HealthStatus {
	state := sections.HealthStateHealthy
	message := "HTTP hardening is operational"
	if s.Enabled() && !s.started.Load() {
		state, message = sections.HealthStateUnhealthy, "section is not started"
	}
	return sections.HealthStatus{Status: state, Message: message, CheckedAt: time.Now().UTC()}
}
func (s *Section) RegisterRoutes(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(prefix+"/config", s.handleConfig)
	mux.HandleFunc(prefix+"/stats", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.Stats()) })
	mux.HandleFunc(prefix+"/analytics", s.handleAnalytics)
	mux.HandleFunc(prefix+"/analytics/", s.handleAnalytics)
	mux.HandleFunc(prefix+"/functions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			appSecurityMethodNotAllowed(w)
			return
		}
		writeJSON(w, s.ListFunctions())
	})
	mux.HandleFunc(prefix+"/effective-state", s.handleEffectiveState)
	s.registerFunctionToggle(mux, prefix)
}
func (s *Section) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		config := s.GetConfig()
		response := cloneMap(config.Settings)
		response["enabled"] = config.Enabled
		response["protection_level"] = config.ProtectionLevel
		writeJSON(w, response)
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		appSecurityMethodNotAllowed(w)
		return
	}
	current := s.GetConfig()
	input, partial, status, code, details := decodeCommunityConfigUpdate(r, current)
	if status != 0 {
		writeCommunityConfigError(w, status, code, details)
		return
	}
	if err := s.UpdateConfig(input); err != nil {
		if errors.Is(err, sections.ErrFeatureNotEntitled) {
			writeAppSecurityError(w, http.StatusForbidden, "feature_not_entitled", "", "App Security advanced features are not entitled.", appSecurityUpgradeFeature)
			return
		}
		if errors.Is(err, sections.ErrUnsupportedConfigKey) {
			writeAppSecurityError(w, http.StatusBadRequest, "unsupported_config_key", "", "Configuration contains unsupported App Security keys.", "")
			return
		}
		writeAppSecurityError(w, http.StatusServiceUnavailable, "persistence_unavailable", "", "The App Security configuration could not be saved; the current runtime configuration remains active.", "")
		return
	}
	if r.Method == http.MethodPut && partial {
		w.Header().Set("Warning", `299 Aegis "Partial PUT for App Security config is deprecated; use PATCH"`)
		w.Header().Set("Deprecation", "true")
	}
	writeJSON(w, map[string]interface{}{"success": true, "durable": s.persist != nil})
}

func (s *Section) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		appSecurityMethodNotAllowed(w)
		return
	}
	stats := s.Stats()
	if strings.Contains(r.URL.Path, "/events/") {
		writeJSON(w, map[string]interface{}{"event": nil})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/events") {
		writeJSON(w, map[string]interface{}{"events": []interface{}{}, "total": 0})
		return
	}
	writeJSON(w, map[string]interface{}{"dashboard": map[string]interface{}{"total_requests": stats.TotalRequests, "blocked_requests": stats.BlockedRequests, "allowed_requests": stats.AllowedRequests}, "history": []interface{}{}, "events": []interface{}{}})
}

func (s *Section) GetConfigSchema() sections.ConfigSchema {
	return sections.ConfigSchema{Groups: []sections.ConfigGroup{
		{ID: "request", Name: "Request validation", Fields: []sections.ConfigField{
			{ID: "max_body", Key: "upload_limit.max_body_size", Label: "Maximum body size", Type: sections.ConfigTypeText, Default: "10MB"},
			{ID: "methods", Key: "method_enforcer.blocked_methods", Label: "Blocked methods", Type: sections.ConfigTypeTags, Default: []string{"TRACE", "TRACK", "CONNECT"}},
		}},
		{ID: "response", Name: "Response hardening", Fields: []sections.ConfigField{
			{ID: "headers", Key: "security_headers.enabled", Label: "Security headers", Type: sections.ConfigTypeToggle, Default: true},
			{ID: "cookies", Key: "cookie_hardener.enabled", Label: "Cookie hardening", Type: sections.ConfigTypeToggle, Default: true},
			{ID: "gzip", Key: "gzip.enabled", Label: "Gzip", Type: sections.ConfigTypeToggle, Default: true},
		}},
	}}
}
func (s *Section) GetPolicies() []sections.Policy      { return nil }
func (s *Section) SetPolicies([]sections.Policy) error { return nil }
func (s *Section) GetRules() []sections.Rule           { return nil }
func (s *Section) SetRules([]sections.Rule) error      { return nil }
func (s *Section) ValidateRule(sections.Rule) error    { return nil }
func (s *Section) ListFunctions() []sections.FunctionInfo {
	functions := make([]sections.FunctionInfo, 0, len(communityFunctionCatalog))
	for _, def := range communityFunctionCatalog {
		functions = append(functions, s.functionInfo(def))
	}
	return functions
}
func (s *Section) GetFunction(string) sections.Function { return nil }

func isMultipart(r *http.Request) bool {
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return media == "multipart/form-data"
}
func blockedUpload(body []byte, contentType string, blocked []string) bool {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return false
	}
	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return false
		}
		if err != nil {
			return false
		}
		filename := part.FileName()
		_ = part.Close()
		if filename != "" && isBlockedFilename(filename, blocked) {
			return true
		}
	}
}

func isBlockedFilename(filename string, blocked []string) bool {
	filename = strings.ToLower(strings.TrimSpace(filename))
	filename = strings.TrimRight(filename, ". \t\r\n")
	ext := filepath.Ext(filename)

	for _, b := range blocked {
		b = strings.ToLower(strings.TrimSpace(b))
		if b == "" {
			continue
		}
		if !strings.HasPrefix(b, ".") {
			b = "." + b
		}
		if ext == b || strings.Contains(filename, b) {
			return true
		}
	}
	return false
}

func validateMultipartBody(contentType string, body []byte) error {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return errors.New("invalid multipart content type")
	}
	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, part)
		_ = part.Close()
	}
}
func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	for _, value := range allowed {
		value = strings.ToLower(strings.TrimSpace(value))
		if host == value || strings.HasPrefix(value, "*.") && strings.HasSuffix(host, strings.TrimPrefix(value, "*")) {
			return true
		}
	}
	return false
}
func containsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}
func compressible(contentType string, allowed []string) bool {
	media, _, _ := mime.ParseMediaType(contentType)
	for _, value := range allowed {
		if strings.EqualFold(media, value) {
			return true
		}
	}
	return false
}
func parseSize(value string) int64 {
	value = strings.ToUpper(strings.TrimSpace(value))
	units := []struct {
		suffix     string
		multiplier int64
	}{{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}}
	for _, unit := range units {
		if strings.HasSuffix(value, unit.suffix) {
			number, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(value, unit.suffix)), 64)
			if err == nil {
				return int64(number * float64(unit.multiplier))
			}
		}
	}
	number, _ := strconv.ParseInt(value, 10, 64)
	return number
}
func cloneMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return map[string]interface{}{}
	}
	data, _ := json.Marshal(input)
	var output map[string]interface{}
	_ = json.Unmarshal(data, &output)
	return output
}
func writeJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func numericInt(value interface{}) (int, bool) {
	switch number := value.(type) {
	case int:
		return number, true
	case float64:
		converted := int(number)
		return converted, float64(converted) == number
	case json.Number:
		converted, err := number.Int64()
		return int(converted), err == nil && int64(int(converted)) == converted
	default:
		return 0, false
	}
}
