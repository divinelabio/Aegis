package telemetry

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Global Counters (Atomic for performance)
var (
	TotalRequests   atomic.Int64
	BlockedRequests atomic.Int64
	RequestsPerSec  atomic.Int64

	// RPSHistory stores the last 60 seconds of RPS data
	RPSHistory      [60]int64
	rpsHistoryIndex int

	// Attack Analytics
	AttackVectors = make(map[string]int64)
	BlockedIPs    = make(map[string]int64)

	// Status Code Analytics
	StatusCodes = make(map[string]int64)

	// Advanced Analytics
	Visitors     = make(map[string]bool)
	TopPaths     = make(map[string]int64)
	UserAgents   = make(map[string]int64)
	TopIPs       = make(map[string]int64)
	Referrers    = make(map[string]int64)
	Methods      = make(map[string]int64)
	TopCountries = make(map[string]int64)

	// Latency tracking
	LatencyBuckets = make(map[string]int64)

	metricsMu sync.RWMutex
	startTime = time.Now()
)

// Prometheus Metrics
var (
	RequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegis_requests_total",
		Help: "The total number of processed requests",
	})

	RequestLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "aegis_request_latency_seconds",
		Help:    "Request latency distribution",
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	}, []string{"path"})

	BlockedRequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegis_blocked_requests_total",
		Help: "The total number of blocked requests",
	})

	ActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aegis_active_connections",
		Help: "Current number of active connections",
	})
)

// DashboardStats structure for Admin API
type DashboardStats struct {
	Requests      int64     `json:"requests"`
	Blocked       int64     `json:"blocked"`
	Attackers     int64     `json:"attackers"`
	Visitors      int64     `json:"visitors"`
	Uptime        string    `json:"uptime"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	RPS           int64     `json:"rps"`
	History       [60]int64 `json:"history"`

	StatusDist   map[string]int64 `json:"status_dist"`
	TopPaths     map[string]int64 `json:"top_paths"`
	UserAgents   map[string]int64 `json:"user_agents"`
	TopIPs       map[string]int64 `json:"top_ips"`
	TopCountries map[string]int64 `json:"top_countries"`
	Referrers    map[string]int64 `json:"referrers"`
	Latency      map[string]int64 `json:"latency"`
	ServerTime   int64            `json:"server_time"`
}

func init() {
	// Initialize latency buckets
	LatencyBuckets["<10ms"] = 0
	LatencyBuckets["10-50ms"] = 0
	LatencyBuckets["50-200ms"] = 0
	LatencyBuckets[">200ms"] = 0

	// Start RPS calculator
	go rpsCalculator()

	// Start periodic cleanup to prevent unbounded memory growth
	go periodicCleanup()
}

// periodicCleanup resets analytics maps hourly to prevent unbounded memory growth
func periodicCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		metricsMu.Lock()
		// Reset maps to prevent unbounded growth
		Visitors = make(map[string]bool)
		TopPaths = make(map[string]int64)
		TopIPs = make(map[string]int64)
		Referrers = make(map[string]int64)
		metricsMu.Unlock()
	}
}

func rpsCalculator() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastTotal int64
	for range ticker.C {
		current := TotalRequests.Load()
		rps := current - lastTotal
		lastTotal = current

		RequestsPerSec.Store(rps)

		// Update history
		metricsMu.Lock()
		RPSHistory[rpsHistoryIndex] = rps
		rpsHistoryIndex = (rpsHistoryIndex + 1) % 60
		metricsMu.Unlock()
	}
}

// GetStats returns the current snapshot of metrics

// RecordRequest records detailed analytics for a request
func RecordRequest(ip, path, ua, country, referrer string) {
	metricsMu.Lock()
	defer metricsMu.Unlock()

	// Increment total requests
	TotalRequests.Add(1)
	RequestsTotal.Inc()

	// Strip port from IP if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// Unique Visitor
	Visitors[ip] = true

	// Top Paths (limit to 100 entries)
	if len(TopPaths) < 100 || TopPaths[path] > 0 {
		TopPaths[path]++
	}

	// Top IPs (limit to 100 entries)
	if len(TopIPs) < 100 || TopIPs[ip] > 0 {
		TopIPs[ip]++
	}

	// User Agent Classification
	os := classifyUserAgent(ua)
	UserAgents[os]++

	// Top Countries
	if country != "" {
		TopCountries[country]++
	}

	// Referrers
	if referrer != "" {
		// Simplify referrer to domain only
		if len(Referrers) < 100 || Referrers[referrer] > 0 {
			Referrers[referrer]++
		}
	}
}

func classifyUserAgent(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case ua == "":
		return "Unknown"
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os"):
		return "macOS"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return "iOS"
	case strings.Contains(ua, "linux"):
		return "Linux"
	case strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") || strings.Contains(ua, "spider"):
		return "Bot"
	default:
		return "Other"
	}
}

// RecordLatency records the latency of a request
func RecordLatency(latencyMs int64) {
	metricsMu.Lock()
	defer metricsMu.Unlock()

	switch {
	case latencyMs < 10:
		LatencyBuckets["<10ms"]++
	case latencyMs < 50:
		LatencyBuckets["10-50ms"]++
	case latencyMs < 200:
		LatencyBuckets["50-200ms"]++
	default:
		LatencyBuckets[">200ms"]++
	}
}

// RecordStatus increments the counter for a specific HTTP status code
func RecordStatus(code int) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	s := fmt.Sprintf("%dxx", code/100)
	StatusCodes[s]++
}
