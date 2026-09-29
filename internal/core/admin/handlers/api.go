package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/divinelab-io/aegis/internal/edition"
	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/storage"
	"github.com/divinelab-io/aegis/internal/infra/transport"
	"github.com/divinelab-io/aegis/internal/sections"
	"github.com/google/uuid"
)

var (
	errRouteNotFound          = errors.New("route not found")
	errProtectedRouteMutation = errors.New("route is referenced by Edge Access")
	errUpstreamNotFound       = errors.New("upstream group not found")
)

func (h *Handler) HandleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Use unified metrics instead of storage stubs
	if h.Sections.UnifiedMetrics == nil {
		h.JSONError(w, "Metrics not available", http.StatusServiceUnavailable)
		return
	}

	// Get real-time statistics from unified traffic collector
	trafficStats := h.Sections.UnifiedMetrics.GetTrafficCollector().GetRealtimeStats()

	// Convert to storage.MetricSnapshot format for backward compatibility
	stats := &storage.MetricSnapshot{
		Timestamp:         time.Now(),
		TotalRequests:     trafficStats.TotalRequests,
		ActiveConnections: 0, // Not tracked yet
		RequestsPerSec:    trafficStats.RequestsPerSec,
		AvgLatencyMs:      trafficStats.AvgLatencyMs,
		StatusCodes:       trafficStats.StatusDistribution,
		TopPaths:          make(map[string]int64),
	}

	// Get top paths
	topEndpoints := h.Sections.UnifiedMetrics.GetTrafficCollector().GetTopEndpoints(10)
	for _, ep := range topEndpoints {
		stats.TopPaths[ep.Path] = ep.Count
	}

	json.NewEncoder(w).Encode(stats)
}

func (h *Handler) HandlePipelineStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Use unified metrics instead of storage stubs
	if h.Sections.UnifiedMetrics == nil {
		h.JSONError(w, "Metrics not available", http.StatusServiceUnavailable)
		return
	}

	// Get global metrics from unified collector
	globalMetrics := h.Sections.UnifiedMetrics.GetGlobalMetrics()

	// Get all section metrics for stage stats
	sectionMetrics := h.Sections.UnifiedMetrics.GetAllSectionMetrics()
	stageStats := make(map[string]int64)
	for sectionID, metrics := range sectionMetrics {
		stageStats[sectionID] = metrics.RequestsTotal
	}

	// Convert to storage.PipelineStats format
	stats := &storage.PipelineStats{
		TotalProcessed:  globalMetrics.TotalRequests,
		TotalBlocked:    globalMetrics.TotalBlocked,
		AvgProcessingMs: globalMetrics.AverageLatency,
		StageStats:      stageStats,
	}

	json.NewEncoder(w).Encode(stats)
}

func (h *Handler) HandleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	window := r.URL.Query().Get("window")
	if window == "" {
		window = "1h"
	}
	typeFilter := r.URL.Query().Get("type")
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
		limit = l
	}

	query := storage.WAFAnalyticsQuery{
		Window: window,
		Limit:  limit,
	}

	if strings.EqualFold(typeFilter, "blocked") {
		query.Action = "block"
	} else if strings.EqualFold(typeFilter, "allowed") {
		query.Action = "allow"
	}

	if ip := r.URL.Query().Get("ip"); ip != "" {
		query.IP = ip
	}
	if path := r.URL.Query().Get("path"); path != "" {
		query.Path = path
	}
	if rule := r.URL.Query().Get("rule"); rule != "" {
		query.RuleID = rule
	}
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		query.Cursor = cursor
	}

	page, err := storage.GetWAFAnalyticsEvents(query)
	if err != nil || len(page.Events) == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"logs":        []interface{}{},
			"count":       0,
			"next_cursor": "",
			"message":     "No threat events matching query criteria",
		})
		return
	}

	logs := make([]map[string]interface{}, 0, len(page.Events))
	for _, ev := range page.Events {
		isBlocked := strings.EqualFold(ev.Action, "block") || strings.EqualFold(ev.Action, "deny") || strings.EqualFold(ev.Action, "drop")
		severity := "medium"
		if len(ev.Severities) > 0 && ev.Severities[0] != "" {
			severity = strings.ToLower(ev.Severities[0])
		} else if ev.AnomalyScore >= 15 {
			severity = "critical"
		} else if ev.AnomalyScore >= 5 {
			severity = "high"
		}

		category := "WAF Core"
		if len(ev.Categories) > 0 && ev.Categories[0] != "" {
			category = ev.Categories[0]
		}

		ruleName := ev.RuleName
		if ruleName == "" {
			ruleName = ev.RuleID
		}
		if ruleName == "" {
			ruleName = "Security Policy Violation"
		}

		logs = append(logs, map[string]interface{}{
			"id":                ev.ID,
			"ts":                ev.Timestamp,
			"timestamp":         ev.Timestamp,
			"ip":                ev.ClientIP,
			"country":           ev.Country,
			"city":              ev.City,
			"method":            ev.Method,
			"host":              ev.Host,
			"path":              ev.Path,
			"query_string":      ev.QueryString,
			"status_code":       ev.StatusCode,
			"action":            ev.Action,
			"blocked":           isBlocked,
			"rule":              ruleName,
			"rule_id":           ev.RuleID,
			"rule_messages":     ev.RuleMessages,
			"severities":        ev.Severities,
			"severity":          severity,
			"category":          category,
			"categories":        ev.Categories,
			"score":             ev.AnomalyScore,
			"latency_ms":        ev.LatencyMs,
			"request_id":        ev.RequestID,
			"user_agent":        ev.UserAgent,
			"user_agent_family": ev.UserAgentFamily,
			"matched_fields":    ev.MatchedFields,
			"metadata":          ev.Metadata,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":        logs,
		"count":       len(logs),
		"next_cursor": page.NextCursor,
	})
}

func (h *Handler) HandleSystem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get memory statistics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Calculate uptime
	uptime := time.Since(ServerStartTime)
	uptimeStr := formatUptime(uptime)

	// Get Circuit Breaker Status
	cbStatus := "unknown"
	cbFailures := 0
	if h.ProxyTransport != nil {
		cbStatus, cbFailures = h.ProxyTransport.GetStatus()
	}

	// Build response
	response := map[string]interface{}{
		"memory_mb":                memStats.Alloc / 1024 / 1024,
		"memory_sys_mb":            memStats.Sys / 1024 / 1024,
		"heap_alloc_mb":            memStats.HeapAlloc / 1024 / 1024,
		"heap_inuse_mb":            memStats.HeapInuse / 1024 / 1024,
		"heap_idle_mb":             memStats.HeapIdle / 1024 / 1024,
		"heap_released_mb":         memStats.HeapReleased / 1024 / 1024,
		"next_gc_mb":               memStats.NextGC / 1024 / 1024,
		"heap_objects":             memStats.HeapObjects,
		"total_alloc_mb":           memStats.TotalAlloc / 1024 / 1024,
		"gc_pause_total_ms":        memStats.PauseTotalNs / uint64(time.Millisecond),
		"last_gc_unix":             memStats.LastGC / uint64(time.Second),
		"goroutines":               runtime.NumGoroutine(),
		"num_gc":                   memStats.NumGC,
		"uptime":                   uptimeStr,
		"uptime_seconds":           int(uptime.Seconds()),
		"go_version":               runtime.Version(),
		"num_cpu":                  runtime.NumCPU(),
		"os":                       runtime.GOOS,
		"arch":                     runtime.GOARCH,
		"circuit_breaker_status":   cbStatus,
		"circuit_breaker_failures": cbFailures,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *Handler) HandleSystemInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uptime := time.Since(ServerStartTime)

	// Version info (set via ldflags in production: -X main.Version=...)
	version := Version
	if version == "" {
		version = "dev"
	}
	buildDate := BuildDate
	if buildDate == "" {
		buildDate = ServerStartTime.Format("2006-01-02")
	}

	response := map[string]interface{}{
		"version":        version,
		"build_date":     buildDate,
		"go_version":     runtime.Version(),
		"coraza_version": "v3.3.3", // Match go.mod
		"os":             runtime.GOOS,
		"arch":           runtime.GOARCH,
		"cpu_cores":      runtime.NumCPU(),
		"uptime_seconds": int(uptime.Seconds()),
		"config_path":    "./config.yaml",
		"data_dir":       "./data",
		"rules_dir":      "./rules",
		"log_level":      "info",
	}

	json.NewEncoder(w).Encode(response)
}

func (h *Handler) HandleUpstreams(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.UpstreamGroupsStore == nil {
		h.JSONError(w, "Origin-pool configuration persistence is unavailable", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		document, found, err := h.UpstreamGroupsStore.LoadUpstreamGroups(r.Context())
		if err != nil {
			if h.Logger != nil {
				h.Logger.Error("Failed to load upstream Origin-pool control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Origin-pool configuration is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if !found {
			h.JSONError(w, "Origin-pool configuration is unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(config.CloneUpstreamGroups(document.Groups))

	case http.MethodPost:
		var group config.UpstreamGroup
		if err := decodeUpstreamRequest(w, r, &group); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		group.Name = strings.TrimSpace(group.Name)
		actor := "unknown"
		if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
			actor = authenticatedOperator
		}
		_, err := config.MutateUpstreamGroupsControlPlane(r.Context(), h.UpstreamGroupsStore, func(groups []config.UpstreamGroup) ([]config.UpstreamGroup, error) {
			for index := range groups {
				if groups[index].Name == group.Name {
					groups[index] = group
					return groups, nil
				}
			}
			return append(groups, group), nil
		}, actor, "admin_update")
		if err != nil {
			h.upstreamMutationError(w, "save", err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved", "name": group.Name})

	case http.MethodDelete:
		var req struct {
			Name string `json:"name"`
		}
		if r.Body != nil && r.ContentLength != 0 {
			if err := decodeUpstreamRequest(w, r, &req); err != nil {
				h.JSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if strings.TrimSpace(req.Name) == "" {
			req.Name = r.URL.Query().Get("name")
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			h.JSONError(w, "Origin pool name is required", http.StatusBadRequest)
			return
		}
		actor := "unknown"
		if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
			actor = authenticatedOperator
		}
		_, err := config.MutateUpstreamGroupsControlPlane(r.Context(), h.UpstreamGroupsStore, func(groups []config.UpstreamGroup) ([]config.UpstreamGroup, error) {
			filtered := make([]config.UpstreamGroup, 0, len(groups))
			found := false
			for _, existing := range groups {
				if existing.Name == req.Name {
					found = true
					continue
				}
				filtered = append(filtered, existing)
			}
			if !found {
				return nil, errUpstreamNotFound
			}
			return filtered, nil
		}, actor, "admin_update")
		if err != nil {
			h.upstreamMutationError(w, "delete", err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "name": req.Name})

	default:
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) HandleUpstreamStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.UpstreamManager == nil {
		_ = json.NewEncoder(w).Encode([]transport.UpstreamGroupRuntimeStatus{})
		return
	}
	_ = json.NewEncoder(w).Encode(h.UpstreamManager.RuntimeStatus())
}

func (h *Handler) HandleUpstreamSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.UpstreamRuntimeStore == nil {
		h.JSONError(w, "Upstream runtime configuration persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		document, found, err := h.UpstreamRuntimeStore.LoadUpstreamRuntime(r.Context())
		if err != nil {
			if h.Logger != nil {
				h.Logger.Error("Failed to load upstream runtime control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Upstream runtime configuration is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if !found {
			h.JSONError(w, "Upstream runtime configuration is unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(document.Settings)
	case http.MethodPost:
		var settings config.UpstreamRuntimeSettings
		if err := decodeUpstreamRequest(w, r, &settings); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		actor := "unknown"
		if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
			actor = authenticatedOperator
		}
		document, err := config.SaveUpstreamRuntimeControlPlane(r.Context(), h.UpstreamRuntimeStore, settings, actor, "admin_update")
		if err != nil {
			if errors.Is(err, config.ErrUpstreamRuntimeRevisionConflict) {
				h.JSONError(w, "Upstream runtime configuration changed on the server; reload before saving", http.StatusConflict)
				return
			}
			if h.Logger != nil {
				h.Logger.Error("Failed to save upstream runtime control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Failed to save upstream runtime settings", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(document.Settings)
	default:
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) HandleCircuitBreakerSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.CircuitBreakerStore == nil {
		h.JSONError(w, "Circuit-breaker configuration persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		document, found, err := h.CircuitBreakerStore.LoadCircuitBreaker(r.Context())
		if err != nil {
			if h.Logger != nil {
				h.Logger.Error("Failed to load circuit-breaker control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Circuit-breaker configuration is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if !found {
			h.JSONError(w, "Circuit-breaker configuration is unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(document.Config)
	case http.MethodPost:
		var policy config.CircuitBreakerConfig
		if err := decodeUpstreamRequest(w, r, &policy); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := config.CanonicalCircuitBreakerConfig(policy); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		actor := "unknown"
		if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
			actor = authenticatedOperator
		}
		document, err := config.SaveCircuitBreakerControlPlane(r.Context(), h.CircuitBreakerStore, policy, actor, "admin_update")
		if err != nil {
			if errors.Is(err, config.ErrCircuitBreakerRevisionConflict) {
				h.JSONError(w, "Circuit-breaker configuration changed on the server; reload before saving", http.StatusConflict)
				return
			}
			if h.Logger != nil {
				h.Logger.Error("Failed to save circuit-breaker control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Failed to save circuit-breaker configuration", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(document.Config)
	default:
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleLegacyRoutes manages the complete legacy host-to-Origin map. Advanced
// route rules have their own CRUD API at /api/routes.
func (h *Handler) HandleLegacyRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.LegacyRoutesStore == nil {
		h.JSONError(w, "Legacy host-route configuration persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		document, found, err := h.LegacyRoutesStore.LoadLegacyRoutes(r.Context())
		if err != nil {
			if h.Logger != nil {
				h.Logger.Error("Failed to load legacy host-route control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Legacy host-route configuration is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if !found {
			h.JSONError(w, "Legacy host-route configuration is unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(document.Routes)
	case http.MethodPost:
		var routes map[string]string
		if err := decodeUpstreamRequest(w, r, &routes); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := config.CanonicalLegacyRoutes(routes); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		actor := "unknown"
		if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
			actor = authenticatedOperator
		}
		document, err := config.SaveLegacyRoutesControlPlane(r.Context(), h.LegacyRoutesStore, routes, actor, "admin_update")
		if err != nil {
			if errors.Is(err, config.ErrLegacyRoutesRevisionConflict) {
				h.JSONError(w, "Legacy host-route configuration changed on the server; reload before saving", http.StatusConflict)
				return
			}
			if h.Logger != nil {
				h.Logger.Error("Failed to save legacy host-route control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Failed to save legacy host-route configuration", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(document.Routes)
	default:
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleStickySecret accepts only a deployment environment reference and
// exposes only a safe configuration status. It never returns the reference or
// the sticky-session signing secret itself.
func (h *Handler) HandleStickySecret(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.StickySecretStore == nil {
		h.JSONError(w, "Sticky-session secret configuration persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		document, found, err := h.StickySecretStore.LoadStickySecret(r.Context())
		if err != nil {
			if h.Logger != nil {
				h.Logger.Error("Failed to load sticky-session secret control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Sticky-session secret configuration is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(config.StickySecretConfigurationStatus(document, found))
	case http.MethodPost:
		var request struct {
			SecretRef string `json:"secret_ref"`
		}
		if err := decodeUpstreamRequest(w, r, &request); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		actor := "unknown"
		if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
			actor = authenticatedOperator
		}
		document, err := config.SaveStickySecretControlPlane(r.Context(), h.StickySecretStore, request.SecretRef, actor, "admin_update")
		if err != nil {
			if errors.Is(err, config.ErrStickySecretRevisionConflict) {
				h.JSONError(w, "Sticky-session secret configuration changed on the server; reload before saving", http.StatusConflict)
				return
			}
			if errors.Is(err, config.ErrStickySecretConfigurationValidation) {
				h.JSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			if h.Logger != nil {
				h.Logger.Error("Failed to save sticky-session secret control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Failed to save sticky-session secret configuration", http.StatusInternalServerError)
			return
		}
		if err := config.ScrubManagedStickySecretFromYAML(); err != nil && h.Logger != nil {
			h.Logger.Warn("Sticky-session secret is active but legacy YAML cleanup is pending", zap.Error(err))
		}
		_ = json.NewEncoder(w).Encode(config.StickySecretConfigurationStatus(document, true))
	default:
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// upstreamManagerSettingsChanged limits health-manager reloads to the two
// settings it consumes. Connection-pool edits must not restart health checks.
func upstreamManagerSettingsChanged(previous, updated config.UpstreamRuntimeSettings) bool {
	return previous.InsecureSkipVerify != updated.InsecureSkipVerify ||
		previous.HealthCheckConcurrency != updated.HealthCheckConcurrency
}

// upstreamProxySettingsChanged limits expensive transport replacement to
// values that affect outbound connections. A health-concurrency-only save now
// preserves pooled keep-alives and circuit-breaker state on the request path.
func upstreamProxySettingsChanged(previous, updated config.UpstreamRuntimeSettings) bool {
	return previous.Target != updated.Target ||
		previous.InsecureSkipVerify != updated.InsecureSkipVerify ||
		previous.MaxIdleConns != updated.MaxIdleConns ||
		previous.MaxIdleConnsPerHost != updated.MaxIdleConnsPerHost ||
		previous.MaxConnsPerHost != updated.MaxConnsPerHost ||
		previous.IdleTimeout != updated.IdleTimeout ||
		previous.TLSHandshakeTimeout != updated.TLSHandshakeTimeout
}

func decodeUpstreamRequest(w http.ResponseWriter, r *http.Request, target interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func (h *Handler) reloadUpstreamGroups(groups []config.UpstreamGroup) error {
	cfg := config.GetGlobalConfig()
	if cfg == nil {
		return errors.New("configuration is not loaded")
	}
	cfg.Upstream.Groups = config.CloneUpstreamGroups(groups)
	if h.UpstreamManager != nil {
		if err := h.UpstreamManager.Reload(cfg.Upstream); err != nil {
			return err
		}
	}
	if h.ProxyTransport != nil {
		if err := h.ProxyTransport.ReloadUpstream(cfg.Upstream, cfg.Server.ReadTimeout); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) upstreamMutationError(w http.ResponseWriter, action string, err error) {
	switch {
	case errors.Is(err, errUpstreamNotFound):
		h.JSONError(w, "Origin pool not found", http.StatusNotFound)
	case errors.Is(err, config.ErrUpstreamGroupsRevisionConflict):
		h.JSONError(w, "Origin-pool configuration changed on the server; reload before saving", http.StatusConflict)
	case errors.Is(err, config.ErrUpstreamDependency):
		h.JSONError(w, err.Error(), http.StatusConflict)
	case errors.Is(err, config.ErrUpstreamValidation):
		h.JSONError(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, config.ErrUpstreamPersistence):
		if h.Logger != nil {
			h.Logger.Error("Failed to persist upstream configuration", zap.String("action", action), zap.Error(err))
		}
		h.JSONError(w, "Failed to save Origin pool configuration", http.StatusInternalServerError)
	default:
		if h.Logger != nil {
			h.Logger.Error("Failed to apply upstream configuration", zap.String("action", action), zap.Error(err))
		}
		h.JSONError(w, "Failed to apply Origin pool configuration", http.StatusInternalServerError)
	}
}

func (h *Handler) HandleCertificates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		h.listTLSCertificates(w)
	case http.MethodPost:
		h.uploadAndActivateTLSCertificate(w, r)
	case http.MethodDelete:
		h.deleteTLSCertificate(w, r)
	default:
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// formatUptime returns a human-readable uptime string
func formatUptime(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

func (h *Handler) HandleModules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	snapshot := h.currentLicenseSnapshot()
	features := edition.NewFeatureSet(snapshot.Features...)
	modules := map[string]interface{}{
		"dashboard":      true,
		"waf":            true,
		"monitor":        true,
		"logs":           true,
		"settings":       true,
		"bot_protection": features.Has(edition.FeatureBotProtection),
		"api_security":   features.Has(edition.FeatureAPISecurity),
		"access_control": features.Has(edition.FeatureAccessControl),
		"traffic_ddos":   features.Has(edition.FeatureTrafficDDoS),
		"license_tier":   string(snapshot.EffectiveTier),
	}

	json.NewEncoder(w).Encode(modules)
}

func (h *Handler) HandleCertificatesConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get fresh config because it might have changed on disk
	cfg := config.GetGlobalConfig()

	switch r.Method {
	case http.MethodGet:
		autoStatus := map[string]transport.AutoCertificateStatus{}
		tlsMetrics := map[string]uint64{}
		if h.TLSManager != nil {
			autoStatus = h.TLSManager.AutoStatus()
			tlsMetrics = h.TLSManager.Metrics()
		}
		renewal := buildTLSRenewalStatus(cfg.Server.TLS, autoStatus)
		restartRequired := h.tlsRestartRequired.Load() || cfg.Server.TLS.Enabled != h.TLSListenerEnabled
		response := map[string]interface{}{
			"enabled":            cfg.Server.TLS.Enabled,
			"auto":               cfg.Server.TLS.Auto,
			"domains":            cfg.Server.TLS.Domains,
			"email":              cfg.Server.TLS.Email,
			"cert_file":          cfg.Server.TLS.CertFile,
			"provider":           renewal["provider"],
			"challenge":          renewal["challenge"],
			"cache_path":         renewal["cache_path"],
			"renew_before_days":  renewal["renew_before_days"],
			"renewal":            renewal,
			"auto_status":        autoStatus,
			"metrics":            tlsMetrics,
			"warnings":           renewal["warnings"],
			"recommendations":    renewal["recommendations"],
			"automation_summary": renewal["summary"],
			"suggested_domains":  buildTLSDomainSuggestions(cfg),
			"listener_mode":      map[bool]string{true: "https", false: "http"}[h.TLSListenerEnabled],
			"restart_required":   restartRequired,
		}
		json.NewEncoder(w).Encode(response)

	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var req struct {
			Enabled bool     `json:"enabled"`
			Auto    bool     `json:"auto"`
			Domains []string `json:"domains"`
			Email   string   `json:"email"`
		}

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			h.JSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if len(req.Domains) > 100 {
			h.JSONError(w, "Auto-TLS supports at most 100 domains per installation", http.StatusBadRequest)
			return
		}

		if email := strings.TrimSpace(req.Email); email != "" {
			address, err := mail.ParseAddress(email)
			if err != nil || !strings.EqualFold(address.Address, email) {
				h.JSONError(w, "Enter a valid ACME contact email address", http.StatusBadRequest)
				return
			}
			req.Email = address.Address
		}
		if req.Enabled && req.Auto {
			domains, err := transport.NormalizeACMEDomains(req.Domains)
			if err != nil {
				h.JSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			req.Domains = domains
		}

		h.Logger.Info("Updating TLS Configuration", zap.Bool("auto", req.Auto), zap.Strings("domains", req.Domains))

		newTLS := cfg.Server.TLS
		newTLS.Enabled = req.Enabled
		newTLS.Auto = req.Auto
		newTLS.Domains = req.Domains
		newTLS.Email = req.Email
		if req.Enabled && !req.Auto &&
			(strings.TrimSpace(newTLS.CertFile) == "" || strings.TrimSpace(newTLS.KeyFile) == "") {
			h.JSONError(w, "Upload and activate a manual certificate before enabling manual TLS", http.StatusBadRequest)
			return
		}

		h.tlsMutationMu.Lock()
		restartRequired, err := h.applyAndPersistTLSConfig(cfg.Server.TLS, newTLS)
		h.tlsMutationMu.Unlock()
		if err != nil {
			h.Logger.Error("Failed to apply TLS configuration", zap.Error(err))
			h.JSONError(w, "TLS configuration was not changed: "+err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":           "updated",
			"config":           newTLS,
			"restart_required": restartRequired,
		})

	default:
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func buildTLSDomainSuggestions(cfg *config.Config) []string {
	if cfg == nil {
		return []string{}
	}

	seen := map[string]bool{}
	add := func(value string) {
		host := normalizeTLSDomain(value)
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
	}

	add(cfg.Infrastructure.PublicBaseURL)
	for host := range cfg.Upstream.Routes {
		add(host)
	}
	for _, rule := range cfg.Upstream.Rules {
		for _, host := range rule.Hosts {
			add(host)
		}
		for _, host := range rule.Match.Hosts {
			add(host)
		}
	}

	domains := make([]string, 0, len(seen))
	for domain := range seen {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

func normalizeTLSDomain(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
		value = parsed.Hostname()
	}
	value = strings.Split(value, "/")[0]
	value = strings.TrimSuffix(value, ".")
	domains, err := transport.NormalizeACMEDomains([]string{value})
	if err != nil || len(domains) != 1 {
		return ""
	}
	return domains[0]
}

func buildTLSRenewalStatus(tlsCfg config.TLSConfig, autoStatus map[string]transport.AutoCertificateStatus) map[string]interface{} {
	warnings := []string{}
	recommendations := []string{
		"Use Auto-TLS only for public hostnames whose TCP port 443 reaches Aegis.",
		"Upload a manual certificate for private hosts, IP addresses, or wildcard domains.",
	}

	if !tlsCfg.Enabled {
		warnings = append(warnings, "The public listener is currently configured without TLS.")
	} else if tlsCfg.Auto {
		if len(tlsCfg.Domains) == 0 {
			warnings = append(warnings, "Auto-TLS is enabled but no domains are configured.")
		}
		if strings.TrimSpace(tlsCfg.Email) == "" {
			warnings = append(warnings, "Add an ACME contact email for certificate authority notices.")
		}
		for domain, status := range autoStatus {
			if status.LastError != "" {
				warnings = append(warnings, fmt.Sprintf("%s: %s", domain, status.LastError))
			}
		}
	} else if strings.TrimSpace(tlsCfg.CertFile) == "" {
		warnings = append(warnings, "Manual TLS is enabled but no active certificate is configured.")
	} else {
		warnings = append(warnings, "Automatic renewal is disabled; uploaded certificates require manual rotation.")
	}

	summary := "TLS disabled"
	if tlsCfg.Enabled && tlsCfg.Auto {
		ready := 0
		for _, status := range autoStatus {
			if status.Ready {
				ready++
			}
		}
		summary = fmt.Sprintf("Auto-TLS active; %d of %d domains ready", ready, len(tlsCfg.Domains))
	} else if tlsCfg.Enabled {
		summary = "Manual certificate mode"
	}

	return map[string]interface{}{
		"enabled":           tlsCfg.Enabled && tlsCfg.Auto,
		"provider":          "Let's Encrypt via autocert",
		"challenge":         "TLS-ALPN-01",
		"cache_path":        effectiveTLSDirectory(tlsCfg.CacheDir, transport.DefaultACMECacheDir),
		"renew_before_days": nil,
		"summary":           summary,
		"warnings":          warnings,
		"recommendations":   recommendations,
	}
}

func (h *Handler) HandleRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.RouteRulesStore == nil {
		h.JSONError(w, "Route-rule configuration persistence is unavailable", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		document, found, err := h.RouteRulesStore.LoadRouteRules(r.Context())
		if err != nil {
			if h.Logger != nil {
				h.Logger.Error("Failed to load route-rule control-plane document", zap.Error(err))
			}
			h.JSONError(w, "Route-rule configuration is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if !found {
			h.JSONError(w, "Route-rule configuration is unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(document.Rules)

	case http.MethodPost:
		var rule config.RouteConfig
		if err := decodeRouteRequest(w, r, &rule); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if rule.ID == "" {
			rule.ID = uuid.New().String()
		}
		if rule.Priority == 0 {
			rule.Priority = 100
		}
		actor := "unknown"
		if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
			actor = authenticatedOperator
		}
		document, err := config.MutateRouteRulesControlPlane(r.Context(), h.RouteRulesStore, func(routes []config.RouteConfig) ([]config.RouteConfig, error) {
			for _, existing := range routes {
				if existing.ID == rule.ID {
					return nil, fmt.Errorf("route id %q already exists", rule.ID)
				}
			}
			return append(routes, rule), nil
		}, actor, "admin_create")
		if err != nil {
			h.routeMutationError(w, "create", err)
			return
		}
		created := routeByID(document.Rules, rule.ID)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "created", "rule": created})

	case http.MethodPut:
		var rule config.RouteConfig
		if err := decodeRouteRequest(w, r, &rule); err != nil {
			h.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if rule.ID == "" {
			h.JSONError(w, "Rule ID is required for update", http.StatusBadRequest)
			return
		}
		actor := "unknown"
		if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
			actor = authenticatedOperator
		}
		document, err := config.MutateRouteRulesControlPlane(r.Context(), h.RouteRulesStore, func(routes []config.RouteConfig) ([]config.RouteConfig, error) {
			for index := range routes {
				if routes[index].ID != rule.ID {
					continue
				}
				if routes[index].Enabled && !rule.Enabled && h.protectedAppReferencesRoute(rule.ID) {
					return nil, errProtectedRouteMutation
				}
				routes[index] = rule
				return routes, nil
			}
			return nil, errRouteNotFound
		}, actor, "admin_update")
		if err != nil {
			h.routeMutationError(w, "update", err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "updated", "rule": routeByID(document.Rules, rule.ID)})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			var req struct {
				ID string `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				id = req.ID
			}
		}

		if id == "" {
			h.JSONError(w, "Rule ID is required", http.StatusBadRequest)
			return
		}
		if h.protectedAppReferencesRoute(id) {
			h.routeMutationError(w, "delete", errProtectedRouteMutation)
			return
		}
		actor := "unknown"
		if authenticatedOperator, ok := sections.AuthenticatedOperator(r.Context()); ok {
			actor = authenticatedOperator
		}
		_, err := config.MutateRouteRulesControlPlane(r.Context(), h.RouteRulesStore, func(routes []config.RouteConfig) ([]config.RouteConfig, error) {
			filtered := make([]config.RouteConfig, 0, len(routes))
			found := false
			for _, existing := range routes {
				if existing.ID == id {
					found = true
					continue
				}
				filtered = append(filtered, existing)
			}
			if !found {
				return nil, errRouteNotFound
			}
			return filtered, nil
		}, actor, "admin_delete")
		if err != nil {
			h.routeMutationError(w, "delete", err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "deleted", "id": id})

	default:
		h.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

type protectedRouteReferenceChecker interface {
	ProtectedAppReferencesRoute(routeID string) bool
}

func (h *Handler) protectedAppReferencesRoute(routeID string) bool {
	if h == nil {
		return false
	}
	if h.routeReferences != nil {
		return h.routeReferences.ProtectedAppReferencesRoute(routeID)
	}
	if h.Sections == nil {
		return false
	}
	section, ok := h.Sections.GetSection("access_control")
	if !ok {
		return false
	}
	checker, ok := section.(protectedRouteReferenceChecker)
	return ok && checker.ProtectedAppReferencesRoute(routeID)
}

func (h *Handler) routeMutationError(w http.ResponseWriter, action string, err error) {
	switch {
	case errors.Is(err, errRouteNotFound):
		h.JSONError(w, "Route not found", http.StatusNotFound)
	case errors.Is(err, errProtectedRouteMutation):
		h.JSONError(w, "Route is linked to an Edge Access Protected App; unlink or remove the app before disabling or deleting the route", http.StatusConflict)
	case errors.Is(err, config.ErrRouteRulesRevisionConflict):
		h.JSONError(w, "Route-rule configuration changed on the server; reload before saving", http.StatusConflict)
	case errors.Is(err, config.ErrRoutePersistence):
		if h.Logger != nil {
			h.Logger.Error("Failed to persist route configuration", zap.String("action", action), zap.Error(err))
		}
		h.JSONError(w, "Failed to save route configuration", http.StatusInternalServerError)
	default:
		if h.Logger != nil {
			h.Logger.Error("Failed to mutate route configuration", zap.String("action", action), zap.Error(err))
		}
		h.JSONError(w, err.Error(), http.StatusBadRequest)
	}
}

func decodeRouteRequest(w http.ResponseWriter, r *http.Request, target *config.RouteConfig) error {
	r.Body = http.MaxBytesReader(w, r.Body, config.MaxRouteBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func routeByID(routes []config.RouteConfig, id string) config.RouteConfig {
	for _, route := range routes {
		if route.ID == id {
			return route
		}
	}
	return config.RouteConfig{}
}
