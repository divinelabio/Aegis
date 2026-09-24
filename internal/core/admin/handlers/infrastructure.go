package handlers

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/transport"
	"github.com/divinelab-io/aegis/internal/sections"
	"go.uber.org/zap"
)

type routeTestRequest struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Host       string            `json:"host"`
	RemoteAddr string            `json:"remote_addr"`
	Headers    map[string]string `json:"headers"`
}

type proxySettingsRuntimeStatus struct {
	Applied         bool   `json:"applied"`
	RestartRequired bool   `json:"restart_required"`
	Revision        string `json:"revision"`
}

type trustedProxyListStatus struct {
	Path              string     `json:"path"`
	Exists            bool       `json:"exists"`
	Entries           int        `json:"entries"`
	UpdatedAt         *time.Time `json:"updated_at,omitempty"`
	ConfiguredSources int        `json:"configured_sources"`
	Error             string     `json:"error,omitempty"`
}

type proxySettingsResponse struct {
	Settings    config.InfrastructureConfig `json:"settings"`
	Runtime     proxySettingsRuntimeStatus  `json:"runtime"`
	TrustedList trustedProxyListStatus      `json:"trusted_list"`
}

// HandleProxySettings owns the complete ingress trust contract. GET is safe
// for infrastructure operators; PUT validates, persists once, and hot-applies
// the resolver without requiring a process restart.
func (h *Handler) HandleProxySettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	current := config.GetGlobalConfig()
	if current == nil {
		h.JSONError(w, "Configuration not loaded", http.StatusInternalServerError)
		return
	}
	if h.InfrastructureStore == nil {
		h.JSONError(w, "Infrastructure configuration persistence is unavailable", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		document, found, err := h.InfrastructureStore.LoadInfrastructure(r.Context())
		if err != nil {
			if h.Logger != nil {
				h.Logger.Error("Failed to load infrastructure control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Infrastructure configuration is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if !found {
			h.JSONError(w, "Infrastructure configuration is unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(proxySettingsSnapshot(document.Config, h.RealIPResolver != nil && h.ProxyTransport != nil))
	case http.MethodPut:
		var next config.InfrastructureConfig
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&next); err != nil {
			h.JSONError(w, "Invalid proxy settings payload", http.StatusBadRequest)
			return
		}
		var trailing interface{}
		if err := decoder.Decode(&trailing); err != io.EOF {
			h.JSONError(w, "Request body must contain one JSON object", http.StatusBadRequest)
			return
		}
		next = config.NormalizeInfrastructureConfig(next, current.Server.Port)
		if err := config.ValidateInfrastructureConfig(next); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}

		actor := "unknown"
		if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
			actor = authenticatedOperator
		}
		document, err := config.SaveInfrastructureControlPlane(r.Context(), h.InfrastructureStore, next, actor, "admin_update")
		if err != nil {
			if errors.Is(err, config.ErrInfrastructureRevisionConflict) {
				h.JSONError(w, "Infrastructure configuration changed on the server; reload before saving", http.StatusConflict)
				return
			}
			if h.Logger != nil {
				h.Logger.Error("Failed to save infrastructure control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Failed to save proxy settings", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(proxySettingsSnapshot(document.Config, h.RealIPResolver != nil && h.ProxyTransport != nil))
	default:
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func proxySettingsSnapshot(settings config.InfrastructureConfig, liveRuntime bool) proxySettingsResponse {
	return proxySettingsResponse{
		Settings: settings,
		Runtime: proxySettingsRuntimeStatus{
			Applied:         liveRuntime,
			RestartRequired: !liveRuntime,
			Revision:        infrastructureRevision(settings),
		},
		TrustedList: inspectTrustedProxyList(settings.TrustedProxies),
	}
}

func infrastructureRevision(settings config.InfrastructureConfig) string {
	encoded, _ := json.Marshal(settings)
	digest := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", digest[:8])
}

func inspectTrustedProxyList(settings config.TrustedProxyConfig) trustedProxyListStatus {
	status := trustedProxyListStatus{
		Path:              settings.CombinedList,
		ConfiguredSources: len(settings.SourceURLs) + len(settings.SourceFiles),
	}
	path := strings.TrimSpace(settings.CombinedList)
	if path == "" {
		return status
	}
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			status.Error = err.Error()
		}
		return status
	}
	defer f.Close()
	status.Exists = true
	if info, statErr := f.Stat(); statErr == nil {
		updated := info.ModTime().UTC()
		status.UpdatedAt = &updated
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, ";") {
			status.Entries++
		}
	}
	if err := scanner.Err(); err != nil {
		status.Error = err.Error()
	}
	return status
}

func (h *Handler) HandleInfrastructureOverview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := config.GetGlobalConfig()
	if cfg == nil {
		h.JSONError(w, "Configuration not loaded", http.StatusInternalServerError)
		return
	}

	cbStatus := "unknown"
	cbFailures := 0
	if h.ProxyTransport != nil {
		cbStatus, cbFailures = h.ProxyTransport.GetStatus()
	}

	routesCount := len(cfg.Upstream.Rules)
	legacyRoutesCount := len(cfg.Upstream.Routes)
	targetsCount := 0
	for _, group := range cfg.Upstream.Groups {
		targetsCount += len(group.Targets)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"mode":                   cfg.Infrastructure.Mode,
		"public_base_url":        cfg.Infrastructure.PublicBaseURL,
		"trusted_proxies":        cfg.Infrastructure.TrustedProxies,
		"routes_count":           routesCount,
		"legacy_routes_count":    legacyRoutesCount,
		"upstream_groups_count":  len(cfg.Upstream.Groups),
		"upstream_targets_count": targetsCount,
		"default_target":         cfg.Upstream.Target,
		"tls_enabled":            cfg.Server.TLS.Enabled,
		"http3_enabled":          cfg.Server.EnableHTTP3,
		"listener_port":          cfg.Server.Port,
		"circuit_breaker": map[string]interface{}{
			"status":   cbStatus,
			"failures": cbFailures,
		},
	})
}

func (h *Handler) HandleRouteTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody routeTestRequest
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reqBody); err != nil {
		h.JSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		h.JSONError(w, "Request body must contain one JSON object", http.StatusBadRequest)
		return
	}
	if reqBody.Method == "" {
		reqBody.Method = http.MethodGet
	}
	if reqBody.URL == "" {
		reqBody.URL = "http://localhost/"
	}
	if reqBody.RemoteAddr == "" {
		reqBody.RemoteAddr = "127.0.0.1:12345"
	}

	parsed, err := url.Parse(reqBody.URL)
	if err != nil {
		h.JSONError(w, "Invalid URL", http.StatusBadRequest)
		return
	}
	testReq := httptest.NewRequest(reqBody.Method, parsed.String(), nil)
	testReq.RemoteAddr = reqBody.RemoteAddr
	if reqBody.Host != "" {
		testReq.Host = reqBody.Host
	} else if parsed.Host != "" {
		testReq.Host = parsed.Host
	}
	for name, value := range reqBody.Headers {
		testReq.Header.Set(name, value)
	}

	cfg := config.GetGlobalConfig()
	if cfg == nil {
		h.JSONError(w, "Configuration not loaded", http.StatusInternalServerError)
		return
	}
	resolver, err := transport.NewRealIPResolver(cfg.Infrastructure.TrustedProxies)
	if err != nil {
		h.JSONError(w, "Invalid trusted proxy configuration", http.StatusInternalServerError)
		return
	}
	clientInfo := resolver.Resolve(testReq)

	var rule *config.RouteConfig
	if h.Router != nil {
		rule = h.Router.MatchWithClient(testReq, clientInfo)
	}

	response := map[string]interface{}{
		"matched":     rule != nil,
		"client_info": clientInfo,
		"request": map[string]interface{}{
			"method": testReq.Method,
			"host":   testReq.Host,
			"path":   testReq.URL.Path,
			"query":  testReq.URL.RawQuery,
		},
	}
	if rule != nil {
		response["route"] = rule
		response["upstream"] = selectedRouteUpstream(*rule)
		response["sections"] = routeSectionSummary(*rule)
		response["delivery"] = map[string]interface{}{
			"named_upstream": selectedRouteUpstream(*rule),
			"strategy":       rule.Action.Strategy,
			"backend_count":  len(rule.Action.Backends),
			"strip_prefix":   rule.Action.StripPrefix,
			"rewrite_path":   rule.Action.RewritePath,
			"preserve_host":  rule.Action.PreserveHost,
			"timeout":        rule.Action.Timeout,
			"retries":        rule.Action.Retries,
		}
	}

	json.NewEncoder(w).Encode(response)
}

func (h *Handler) HandleInfrastructureTemplate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	provider := strings.TrimPrefix(r.URL.Path, "/api/edge/templates/")
	provider = strings.TrimPrefix(provider, "/api/infrastructure/templates/")
	provider = strings.ToLower(strings.Trim(provider, "/"))
	if provider == "" {
		provider = strings.ToLower(r.URL.Query().Get("provider"))
	}
	if provider == "" {
		h.JSONError(w, "Provider is required", http.StatusBadRequest)
		return
	}

	cfg := config.GetGlobalConfig()
	if cfg == nil {
		h.JSONError(w, "Configuration not loaded", http.StatusInternalServerError)
		return
	}
	settings := config.NormalizeInfrastructureConfig(cfg.Infrastructure, cfg.Server.Port)
	if override := strings.TrimSpace(r.URL.Query().Get("public_base_url")); override != "" {
		settings.PublicBaseURL = override
	}
	if override := strings.TrimSpace(r.URL.Query().Get("aegis_address")); override != "" {
		settings.AegisAddress = override
	}
	if err := config.ValidateInfrastructureConfig(settings); err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	guide, err := renderIntegrationGuide(provider, cfg.Server.Port, settings)
	if err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	guide.Provider = provider
	_ = json.NewEncoder(w).Encode(guide)
}

func selectedRouteUpstream(rule config.RouteConfig) string {
	if rule.Action.Upstream != "" {
		if config.IsRouteStrategy(rule.Action.Upstream) && len(rule.Action.Backends) > 0 {
			return ""
		}
		return rule.Action.Upstream
	}
	if config.IsRouteStrategy(rule.LoadBalance) {
		return ""
	}
	return rule.LoadBalance
}

func routeSectionSummary(rule config.RouteConfig) map[string]interface{} {
	return map[string]interface{}{
		"waf_core":        routeSectionEnabled(rule.Security.WAFCore),
		"bot_protection":  routeSectionEnabled(rule.Security.BotProtection),
		"traffic_control": routeSectionEnabled(rule.Security.TrafficControl),
		"api_security":    routeSectionEnabled(rule.Security.APISecurity),
		"access_control":  routeSectionEnabled(rule.Security.AccessControl),
		"http_security":   routeSectionEnabled(rule.Security.HTTPSecurity),
		"country_policy":  rule.Security.Country,
	}
}

func routeSectionEnabled(value *bool) bool {
	return value == nil || *value
}

type integrationGuide struct {
	Provider string   `json:"provider"`
	Title    string   `json:"title"`
	Subtitle string   `json:"subtitle"`
	Steps    []string `json:"steps"`
	Template string   `json:"template"`
}

func renderIntegrationGuide(provider string, serverPort int, settings config.InfrastructureConfig) (integrationGuide, error) {
	aegisURL := strings.TrimRight(settings.AegisAddress, "/")
	if aegisURL == "" {
		aegisURL = fmt.Sprintf("http://127.0.0.1:%d", serverPort)
	}
	host := "example.com"
	if settings.PublicBaseURL != "" {
		if parsed, err := url.Parse(settings.PublicBaseURL); err == nil && parsed.Host != "" {
			host = parsed.Host
		}
	}

	switch provider {
	case "standalone":
		return integrationGuide{
			Title:    "Aegis standalone",
			Subtitle: "Aegis owns the public listener; no external reverse proxy is required.",
			Steps: []string{
				"Configure the public listeners and TLS under SSL Certificates and server settings.",
				"Attach applications through Routing.",
				"Create reusable backend pools in Origins.",
			},
		}, nil
	case "nginx":
		return integrationGuide{Title: "Nginx in front of Aegis", Subtitle: "Nginx owns the public listener and forwards a normalized identity chain to Aegis.", Steps: []string{"Bind Aegis to a private address or internal port.", "Install this server block on the ingress node.", "Trust only the Nginx address or subnet in Aegis."}, Template: fmt.Sprintf(`server {
    listen 80;
    server_name %s;

    location / {
        proxy_pass %s;
        proxy_set_header Forwarded "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}`, host, aegisURL)}, nil
	case "traefik":
		return integrationGuide{Title: "Traefik in front of Aegis", Subtitle: "Traefik routes the public host to Aegis and clears untrusted RFC Forwarded input.", Steps: []string{"Create the router and service.", "Attach the forwarded-header safety middleware.", "Trust only the Traefik network in Aegis."}, Template: fmt.Sprintf(`http:
  routers:
    aegis:
      rule: "Host(`+"`%s`"+`)"
      entryPoints: ["web", "websecure"]
      service: aegis
      middlewares: ["aegis-forwarded-safety"]
      observability:
        accessLogs: true
        metrics: true
  middlewares:
    aegis-forwarded-safety:
      headers:
        customRequestHeaders:
          Forwarded: ""
  services:
    aegis:
      loadBalancer:
        servers:
          - url: "%s"`, host, aegisURL)}, nil
	case "caddy":
		return integrationGuide{Title: "Caddy in front of Aegis", Subtitle: "Caddy handles the public site and forwards a normalized client identity.", Steps: []string{"Use Caddy for the public hostname and certificate automation.", "Point reverse_proxy at the private Aegis address.", "Trust only the Caddy node or subnet in Aegis."}, Template: fmt.Sprintf(`%s {
    reverse_proxy %s {
        header_up -Forwarded
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-Host {host}
    }
}`, host, aegisURL)}, nil
	case "apache":
		return integrationGuide{Title: "Apache in front of Aegis", Subtitle: "Apache owns the public listener and replaces client-supplied forwarding metadata.", Steps: []string{"Enable mod_proxy, mod_proxy_http, and mod_headers.", "Install the virtual host.", "Trust only the Apache address or subnet in Aegis."}, Template: fmt.Sprintf(`<VirtualHost *:80>
    ServerName %s
    ProxyRequests Off
    ProxyPreserveHost On

    RequestHeader unset Forwarded
    RequestHeader set X-Forwarded-Proto "http"
    RequestHeader set X-Real-IP "%%{REMOTE_ADDR}s"
    RequestHeader set X-Forwarded-For "%%{REMOTE_ADDR}s"
    RequestHeader set X-Forwarded-Host "%%{HTTP_HOST}s"

    ProxyPass / %s/
    ProxyPassReverse / %s/
</VirtualHost>`, host, aegisURL, aegisURL)}, nil
	case "sidecar":
		return integrationGuide{Title: "Sidecar deployment", Subtitle: "Aegis runs beside the application and trusts only the local workload proxy.", Steps: []string{"Bind the Aegis listener to the pod or task network.", "Route workload ingress through Aegis before the application.", "Trust only the sidecar or loopback CIDR; do not trust the full cluster network."}}, nil
	case "kubernetes_ingress":
		return integrationGuide{Title: "Kubernetes ingress", Subtitle: "The ingress controller forwards public traffic to the Aegis Service.", Steps: []string{"Create a ClusterIP Service for Aegis.", "Point the Ingress backend at that Service.", "Trust only the ingress-controller pod or node CIDRs and keep the list updated."}}, nil
	default:
		return integrationGuide{}, fmt.Errorf("unsupported provider %q", provider)
	}
}
