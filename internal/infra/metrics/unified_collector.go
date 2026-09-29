package metrics

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// UnifiedCollector is the single source of truth for all metrics
type UnifiedCollector struct {
	// Traffic metrics (HTTP-level analytics)
	traffic *TrafficCollector

	// Section metrics (WAF, Bot, Access, etc.)
	sections map[string]*SectionCollector

	// Global aggregated metrics
	global *GlobalMetrics

	mu        sync.RWMutex
	startTime time.Time
}

// GlobalMetrics holds system-wide aggregated metrics
type GlobalMetrics struct {
	TotalRequests              int64
	TotalBlocked               int64
	TotalAllowed               int64
	UniqueVisitors             int64
	UniqueVisitorsEstimated    bool
	UniqueVisitorRelativeError float64
	AverageLatency             float64
	CurrentRPS                 float64
	UptimeSeconds              int64
	SectionsHealthy            int
	SectionsTotal              int
}

// NewUnifiedCollector creates the unified metrics collector
func NewUnifiedCollector() *UnifiedCollector {
	return &UnifiedCollector{
		traffic:   NewTrafficCollector(),
		sections:  make(map[string]*SectionCollector),
		global:    &GlobalMetrics{},
		startTime: time.Now(),
	}
}

// RegisterSection registers a new section for metrics tracking
func (u *UnifiedCollector) RegisterSection(sectionID string) *SectionCollector {
	u.mu.Lock()
	defer u.mu.Unlock()

	collector := NewSectionCollector(sectionID)
	u.sections[sectionID] = collector
	return collector
}

// GetSectionCollector returns the collector for a specific section
func (u *UnifiedCollector) GetSectionCollector(sectionID string) (*SectionCollector, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	collector, ok := u.sections[sectionID]
	return collector, ok
}

// GetTrafficCollector returns the traffic metrics collector
func (u *UnifiedCollector) GetTrafficCollector() *TrafficCollector {
	return u.traffic
}

// RecordHTTPRequest records a complete HTTP request with all details
func (u *UnifiedCollector) RecordHTTPRequest(req HTTPRequestMetric) {
	// Record in traffic collector
	u.traffic.RecordRequest(req)

	// Update global metrics
	u.updateGlobalMetrics()
}

// RecordSectionEvent records a section-specific event
func (u *UnifiedCollector) RecordSectionEvent(sectionID string, event SectionEvent) {
	u.mu.RLock()
	collector, ok := u.sections[sectionID]
	u.mu.RUnlock()

	if ok {
		collector.RecordEvent(event)
	}
}

// GetGlobalMetrics returns aggregated global metrics
func (u *UnifiedCollector) GetGlobalMetrics() GlobalMetrics {
	u.mu.RLock()
	defer u.mu.RUnlock()

	// Get traffic stats
	trafficStats := u.traffic.getGlobalSnapshot()

	return GlobalMetrics{
		TotalRequests:              trafficStats.totalRequests,
		TotalBlocked:               u.aggregateSectionBlocked(),
		TotalAllowed:               trafficStats.totalRequests - u.aggregateSectionBlocked(),
		UniqueVisitors:             trafficStats.uniqueVisitors,
		UniqueVisitorsEstimated:    true,
		UniqueVisitorRelativeError: uniqueVisitorHLLError,
		AverageLatency:             trafficStats.avgLatencyMs,
		CurrentRPS:                 trafficStats.requestsPerSec,
		UptimeSeconds:              int64(time.Since(u.startTime).Seconds()),
		SectionsHealthy:            u.countHealthySections(),
		SectionsTotal:              len(u.sections),
	}
}

// GetAllSectionMetrics returns metrics for all sections
func (u *UnifiedCollector) GetAllSectionMetrics() map[string]SectionMetrics {
	u.mu.RLock()
	defer u.mu.RUnlock()

	result := make(map[string]SectionMetrics)
	for id, collector := range u.sections {
		result[id] = collector.GetMetrics()
	}
	return result
}

// updateGlobalMetrics aggregates metrics from all sources
func (u *UnifiedCollector) updateGlobalMetrics() {
	u.mu.Lock()
	defer u.mu.Unlock()

	trafficStats := u.traffic.getGlobalSnapshot()

	u.global.TotalRequests = trafficStats.totalRequests
	u.global.TotalBlocked = u.aggregateSectionBlocked()
	u.global.TotalAllowed = u.global.TotalRequests - u.global.TotalBlocked
	u.global.UniqueVisitors = trafficStats.uniqueVisitors
	u.global.UniqueVisitorsEstimated = true
	u.global.UniqueVisitorRelativeError = uniqueVisitorHLLError
	u.global.AverageLatency = trafficStats.avgLatencyMs
	u.global.CurrentRPS = trafficStats.requestsPerSec
	u.global.UptimeSeconds = int64(time.Since(u.startTime).Seconds())
	u.global.SectionsTotal = len(u.sections)
	u.global.SectionsHealthy = u.countHealthySections()
}

// aggregateSectionBlocked sums blocked requests across all sections
func (u *UnifiedCollector) aggregateSectionBlocked() int64 {
	var total int64
	for _, collector := range u.sections {
		total += collector.GetMetrics().RequestsBlocked
	}
	return total
}

// countHealthySections counts how many sections are healthy
func (u *UnifiedCollector) countHealthySections() int {
	healthy := 0
	for _, collector := range u.sections {
		if collector.IsHealthy() {
			healthy++
		}
	}
	return healthy
}

// PrometheusFormat returns all metrics in Prometheus format
func (u *UnifiedCollector) PrometheusFormat() string {
	global := u.GetGlobalMetrics()
	sections := u.GetAllSectionMetrics()
	var output strings.Builder

	// Global metrics
	output.WriteString("# HELP aegis_requests_total Total number of requests\n")
	output.WriteString("# TYPE aegis_requests_total counter\n")
	output.WriteString(formatPrometheusMetric("aegis_requests_total", float64(global.TotalRequests)))

	output.WriteString("# HELP aegis_requests_blocked Total blocked requests\n")
	output.WriteString("# TYPE aegis_requests_blocked counter\n")
	output.WriteString(formatPrometheusMetric("aegis_requests_blocked", float64(global.TotalBlocked)))

	output.WriteString("# HELP aegis_rps Current requests per second\n")
	output.WriteString("# TYPE aegis_rps gauge\n")
	output.WriteString(formatPrometheusMetric("aegis_rps", global.CurrentRPS))

	output.WriteString("# HELP aegis_latency_ms Average latency in milliseconds\n")
	output.WriteString("# TYPE aegis_latency_ms gauge\n")
	output.WriteString(formatPrometheusMetric("aegis_latency_ms", global.AverageLatency))

	output.WriteString("# HELP aegis_unique_visitors Estimated unique visitors in the rolling 24 hour window\n")
	output.WriteString("# TYPE aegis_unique_visitors gauge\n")
	output.WriteString(formatPrometheusMetric("aegis_unique_visitors", float64(global.UniqueVisitors)))
	output.WriteString("# HELP aegis_unique_visitors_estimated Whether unique visitor counting is approximate\n")
	output.WriteString("# TYPE aegis_unique_visitors_estimated gauge\n")
	uniqueVisitorsEstimated := 0.0
	if global.UniqueVisitorsEstimated {
		uniqueVisitorsEstimated = 1
	}
	output.WriteString(formatPrometheusMetric("aegis_unique_visitors_estimated", uniqueVisitorsEstimated))
	output.WriteString("# HELP aegis_unique_visitors_relative_error Expected relative error of the unique visitor estimate\n")
	output.WriteString("# TYPE aegis_unique_visitors_relative_error gauge\n")
	output.WriteString(formatPrometheusMetric("aegis_unique_visitors_relative_error", global.UniqueVisitorRelativeError))

	// Section metrics
	for id, sectionMetrics := range sections {
		output.WriteString(formatPrometheusMetric("aegis_section_requests_total", float64(sectionMetrics.RequestsTotal), "section", id))
		output.WriteString(formatPrometheusMetric("aegis_section_blocked", float64(sectionMetrics.RequestsBlocked), "section", id))
		output.WriteString(formatPrometheusMetric("aegis_section_latency_ms", sectionMetrics.AvgLatencyMs, "section", id))
	}
	return output.String()
}

func formatPrometheusMetric(name string, value float64, labels ...string) string {
	if len(labels) == 0 {
		return name + " " + formatFloat(value) + "\n"
	}

	labelStr := ""
	for i := 0; i < len(labels); i += 2 {
		if i > 0 {
			labelStr += ","
		}
		labelStr += labels[i] + `="` + labels[i+1] + `"`
	}
	return name + "{" + labelStr + "} " + formatFloat(value) + "\n"
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
