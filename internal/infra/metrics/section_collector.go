package metrics

import (
	"sync"
	"time"
)

// SectionCollector tracks metrics for a specific section (WAF, Bot, Access, etc.)
type SectionCollector struct {
	sectionID string
	mu        sync.RWMutex

	// Basic request metrics
	requestsTotal   int64
	requestsBlocked int64
	requestsAllowed int64
	errorsTotal     int64

	// Latency tracking
	totalLatencyMs float64
	avgLatencyMs   float64
	minLatencyMs   float64
	maxLatencyMs   float64

	// RPS tracking
	currentRPS float64

	// Custom metrics (section-specific)
	customMetrics map[string]interface{}

	// Health status
	healthy    bool
	lastUpdate time.Time
	startTime  time.Time
}

// SectionEvent represents a section-specific event
type SectionEvent struct {
	EventType string
	Blocked   bool
	LatencyMs float64
	Metadata  map[string]interface{}
}

// SectionMetrics is the exported snapshot of section metrics
type SectionMetrics struct {
	SectionID       string                 `json:"section_id"`
	RequestsTotal   int64                  `json:"requests_total"`
	RequestsBlocked int64                  `json:"requests_blocked"`
	RequestsAllowed int64                  `json:"requests_allowed"`
	ErrorsTotal     int64                  `json:"errors_total"`
	AvgLatencyMs    float64                `json:"avg_latency_ms"`
	MinLatencyMs    float64                `json:"min_latency_ms"`
	MaxLatencyMs    float64                `json:"max_latency_ms"`
	CurrentRPS      float64                `json:"current_rps"`
	Healthy         bool                   `json:"healthy"`
	UptimeSeconds   int64                  `json:"uptime_seconds"`
	LastUpdate      time.Time              `json:"last_update"`
	CustomMetrics   map[string]interface{} `json:"custom_metrics"`
}

// NewSectionCollector creates a new section-specific metrics collector
func NewSectionCollector(sectionID string) *SectionCollector {
	return &SectionCollector{
		sectionID:     sectionID,
		customMetrics: make(map[string]interface{}),
		healthy:       true,
		startTime:     time.Now(),
		lastUpdate:    time.Now(),
		minLatencyMs:  -1,
	}
}

// RecordEvent records a section-specific event
func (s *SectionCollector) RecordEvent(event SectionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requestsTotal++
	if event.Blocked {
		s.requestsBlocked++
	} else {
		s.requestsAllowed++
	}

	// Update latency (exponential moving average)
	if event.LatencyMs > 0 {
		s.totalLatencyMs += event.LatencyMs
		alpha := 0.1 // Smoothing factor
		s.avgLatencyMs = alpha*event.LatencyMs + (1-alpha)*s.avgLatencyMs

		if s.minLatencyMs < 0 || event.LatencyMs < s.minLatencyMs {
			s.minLatencyMs = event.LatencyMs
		}
		if event.LatencyMs > s.maxLatencyMs {
			s.maxLatencyMs = event.LatencyMs
		}
	}

	// Store custom metadata
	if event.Metadata != nil {
		for key, value := range event.Metadata {
			s.customMetrics[key] = value
		}
	}

	s.lastUpdate = time.Now()
}

// RecordRequest is a simplified version for basic request tracking
func (s *SectionCollector) RecordRequest(blocked bool, latencyMs float64) {
	s.RecordEvent(SectionEvent{
		EventType: "request",
		Blocked:   blocked,
		LatencyMs: latencyMs,
	})
}

// RecordError records an error event
func (s *SectionCollector) RecordError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errorsTotal++
}

// SetCustomMetric sets a custom metric value
func (s *SectionCollector) SetCustomMetric(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.customMetrics[key] = value
}

// GetCustomMetric retrieves a custom metric value
func (s *SectionCollector) GetCustomMetric(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.customMetrics[key]
	return value, ok
}

// SetHealthy sets the health status of the section
func (s *SectionCollector) SetHealthy(healthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = healthy
}

// IsHealthy returns the current health status
func (s *SectionCollector) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.healthy
}

// UpdateRPS updates the current requests per second
func (s *SectionCollector) UpdateRPS(rps float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentRPS = rps
}

// GetMetrics returns a thread-safe snapshot of metrics
func (s *SectionCollector) GetMetrics() SectionMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Copy custom metrics
	custom := make(map[string]interface{})
	for k, v := range s.customMetrics {
		custom[k] = v
	}

	return SectionMetrics{
		SectionID:       s.sectionID,
		RequestsTotal:   s.requestsTotal,
		RequestsBlocked: s.requestsBlocked,
		RequestsAllowed: s.requestsAllowed,
		ErrorsTotal:     s.errorsTotal,
		AvgLatencyMs:    s.avgLatencyMs,
		MinLatencyMs:    s.minLatencyMs,
		MaxLatencyMs:    s.maxLatencyMs,
		CurrentRPS:      s.currentRPS,
		Healthy:         s.healthy,
		UptimeSeconds:   int64(time.Since(s.startTime).Seconds()),
		LastUpdate:      s.lastUpdate,
		CustomMetrics:   custom,
	}
}

// Reset resets all counters (useful for testing)
func (s *SectionCollector) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requestsTotal = 0
	s.requestsBlocked = 0
	s.requestsAllowed = 0
	s.errorsTotal = 0
	s.totalLatencyMs = 0
	s.avgLatencyMs = 0
	s.minLatencyMs = -1
	s.maxLatencyMs = 0
	s.currentRPS = 0
	s.customMetrics = make(map[string]interface{})
}

// IncrementCustomCounter increments a custom counter metric
func (s *SectionCollector) IncrementCustomCounter(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if val, ok := s.customMetrics[key]; ok {
		if count, ok := val.(int64); ok {
			s.customMetrics[key] = count + 1
			return
		}
	}
	s.customMetrics[key] = int64(1)
}

// AddCustomValue adds a value to a custom metric (for averages, totals, etc.)
func (s *SectionCollector) AddCustomValue(key string, value float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if val, ok := s.customMetrics[key]; ok {
		if current, ok := val.(float64); ok {
			s.customMetrics[key] = current + value
			return
		}
	}
	s.customMetrics[key] = value
}
