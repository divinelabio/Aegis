package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/divinelab-io/aegis/internal/infra/metrics"
	"go.uber.org/zap"
)

// MetricsHandler handles metrics API endpoints using the unified collector
type MetricsHandler struct {
	collector *metrics.UnifiedCollector
	logger    *zap.Logger
}

// NewMetricsHandler creates a new metrics handler
func NewMetricsHandler(collector *metrics.UnifiedCollector, logger *zap.Logger) *MetricsHandler {
	return &MetricsHandler{
		collector: collector,
		logger:    logger,
	}
}

// HandleRealtime returns current real-time traffic statistics
// GET /api/metrics/traffic/realtime
func (h *MetricsHandler) HandleRealtime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	traffic := h.collector.GetTrafficCollector()
	stats := traffic.GetRealtimeStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// HandleTimeSeries returns time-series data for charts
// GET /api/metrics/traffic/timeseries?window=60
func (h *MetricsHandler) HandleTimeSeries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse window parameter (default: 60 minutes)
	windowStr := r.URL.Query().Get("window")
	window := 60
	if windowStr != "" {
		if parsed, err := strconv.Atoi(windowStr); err == nil && parsed > 0 {
			window = parsed
		}
	}

	traffic := h.collector.GetTrafficCollector()
	data := traffic.GetTimeSeries(window)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// HandleTopEndpoints returns the most popular endpoints
// GET /api/metrics/traffic/endpoints?limit=20
func (h *MetricsHandler) HandleTopEndpoints(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 20
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	traffic := h.collector.GetTrafficCollector()
	endpoints := traffic.GetTopEndpoints(limit)

	response := map[string]interface{}{
		"endpoints": endpoints,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleTopIPs returns the top visitor IPs
// GET /api/metrics/traffic/ips?limit=20
func (h *MetricsHandler) HandleTopIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 20
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	traffic := h.collector.GetTrafficCollector()
	ips := traffic.GetTopIPs(limit)

	response := map[string]interface{}{
		"ips": ips,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleMethods returns HTTP method distribution
// GET /api/metrics/traffic/methods
func (h *MetricsHandler) HandleMethods(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	traffic := h.collector.GetTrafficCollector()
	methods := traffic.GetMethodDistribution()

	response := map[string]interface{}{
		"methods": methods,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleGeographic returns geographic distribution
// GET /api/metrics/traffic/geographic
func (h *MetricsHandler) HandleGeographic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	traffic := h.collector.GetTrafficCollector()
	countries := traffic.GetCountryDistribution()

	response := map[string]interface{}{
		"countries": countries,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleGlobalMetrics returns aggregated global metrics
// GET /api/metrics/global
func (h *MetricsHandler) HandleGlobalMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	global := h.collector.GetGlobalMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(global)
}

// HandleSections returns metrics for all sections
// GET /api/metrics/sections
func (h *MetricsHandler) HandleSections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sections := h.collector.GetAllSectionMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sections": sections,
	})
}

// HandleSectionMetrics returns metrics for a specific section
// GET /api/metrics/sections/:id
func (h *MetricsHandler) HandleSectionMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract section ID from URL (simplified - in production use a router)
	sectionID := r.URL.Query().Get("id")
	if sectionID == "" {
		http.Error(w, "Missing section ID", http.StatusBadRequest)
		return
	}

	collector, ok := h.collector.GetSectionCollector(sectionID)
	if !ok {
		http.Error(w, "Section not found", http.StatusNotFound)
		return
	}

	metrics := collector.GetMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// PrometheusFormat returns metrics in Prometheus text format
func (h *MetricsHandler) PrometheusFormat() string {
	return h.collector.PrometheusFormat()
}
