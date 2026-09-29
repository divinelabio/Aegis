package metrics

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// Time-series configuration
	MinuteBuckets         = 60    // Last 60 minutes
	HourBuckets           = 24    // Last 24 hours
	TopKLimit             = 100   // Track top 100 items
	latencySampleCapacity = 2_048 // Fixed per-time-bucket P95 sample
)

// TrafficCollector handles HTTP-level traffic metrics
type TrafficCollector struct {
	mu sync.RWMutex

	// Circular buffers for time-series
	minuteBuckets [MinuteBuckets]*TimeBucket
	hourBuckets   [HourBuckets]*TimeBucket
	currentMinute int
	currentHour   int

	// Lifetime counters
	totalRequests int64
	totalErrors   int64

	// Analytics tracking
	pathCounts           map[string]*pathStats
	ipCounts             map[string]*ipStats
	pathCardinalityDrops int64
	ipCardinalityDrops   int64
	referrerCounts       map[string]int64
	methodCounts         map[string]int64
	countryCounts        map[string]int64
	userAgents           map[string]int64

	// Fixed-memory, approximate unique visitors over the rolling 24-hour window.
	uniqueVisitors          uniqueVisitorCounter
	uniqueVisitorEstimate   int64
	uniqueVisitorEstimateAt time.Time

	// Latency buckets for distribution
	latencyBuckets map[string]int64
}

// HTTPRequestMetric represents a complete HTTP request
type HTTPRequestMetric struct {
	Timestamp  time.Time
	Method     string
	Path       string
	StatusCode int
	LatencyMs  float64
	ClientIP   string
	UserAgent  string
	Referrer   string
	Country    string
	BytesSent  int64
	BytesRecv  int64
}

type pathStats struct {
	count        int64
	totalLatency float64
}

type ipStats struct {
	count    int64
	lastSeen time.Time
}

// TrafficStats represents current traffic statistics
type TrafficStats struct {
	RequestsPerSec             float64          `json:"requests_per_sec"`
	AvgLatencyMs               float64          `json:"avg_latency_ms"`
	TotalRequests              int64            `json:"total_requests"`
	UniqueVisitors             int64            `json:"unique_visitors"`
	ErrorRate                  float64          `json:"error_rate"`
	StatusDistribution         map[string]int64 `json:"status_distribution"`
	PathCardinalityDrops       int64            `json:"path_cardinality_drops"`
	IPCardinalityDrops         int64            `json:"ip_cardinality_drops"`
	UniqueVisitorsEstimated    bool             `json:"unique_visitors_estimated"`
	UniqueVisitorRelativeError float64          `json:"unique_visitor_relative_error"`
}

type trafficGlobalSnapshot struct {
	requestsPerSec float64
	avgLatencyMs   float64
	totalRequests  int64
	uniqueVisitors int64
}

// NewTrafficCollector creates a new traffic collector
func NewTrafficCollector() *TrafficCollector {
	c := &TrafficCollector{
		pathCounts:     make(map[string]*pathStats),
		ipCounts:       make(map[string]*ipStats),
		referrerCounts: make(map[string]int64),
		methodCounts:   make(map[string]int64),
		countryCounts:  make(map[string]int64),
		userAgents:     make(map[string]int64),
		uniqueVisitors: newUniqueVisitorCounter(),
		latencyBuckets: make(map[string]int64),
	}

	// Initialize buckets
	for i := 0; i < MinuteBuckets; i++ {
		c.minuteBuckets[i] = newTimeBucket()
	}
	for i := 0; i < HourBuckets; i++ {
		c.hourBuckets[i] = newTimeBucket()
	}

	// Initialize latency buckets
	c.latencyBuckets["<10ms"] = 0
	c.latencyBuckets["10-50ms"] = 0
	c.latencyBuckets["50-200ms"] = 0
	c.latencyBuckets[">200ms"] = 0

	return c
}

func newTimeBucket() *TimeBucket {
	return &TimeBucket{
		StatusCounts:   make(map[int]int64),
		MethodCounts:   make(map[string]int64),
		MinLatencyMs:   -1,
		LatencySamples: make([]float64, 0, latencySampleCapacity),
	}
}

// RecordRequest records a single HTTP request
func (c *TrafficCollector) RecordRequest(m HTTPRequestMetric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	// Update lifetime counters
	c.totalRequests++
	if m.StatusCode >= 400 {
		c.totalErrors++
	}

	// Update time buckets
	c.updateTimeBuckets(m, now)

	// Update analytics
	c.updateAnalytics(m, now)

	// Track rolling approximate unique visitors without retaining source IPs.
	c.uniqueVisitors.add(m.ClientIP, now)

	// Update latency buckets
	c.updateLatencyBuckets(m.LatencyMs)
}

func (c *TrafficCollector) updateTimeBuckets(m HTTPRequestMetric, now time.Time) {
	// Minute bucket
	minuteIdx := now.Minute()
	if minuteIdx != c.currentMinute || c.minuteBuckets[minuteIdx].Timestamp.IsZero() {
		c.currentMinute = minuteIdx
		c.minuteBuckets[minuteIdx] = newTimeBucket()
		c.minuteBuckets[minuteIdx].Timestamp = now.Truncate(time.Minute)
	}

	bucket := c.minuteBuckets[minuteIdx]
	c.updateBucket(bucket, m)

	// Hour bucket
	hourIdx := now.Hour()
	if hourIdx != c.currentHour || c.hourBuckets[hourIdx].Timestamp.IsZero() {
		c.currentHour = hourIdx
		c.hourBuckets[hourIdx] = newTimeBucket()
		c.hourBuckets[hourIdx].Timestamp = now.Truncate(time.Hour)
	}

	hourBucket := c.hourBuckets[hourIdx]
	c.updateBucket(hourBucket, m)
}

func (c *TrafficCollector) updateBucket(bucket *TimeBucket, m HTTPRequestMetric) {
	bucket.RequestCount++
	bucket.TotalLatencyMs += m.LatencyMs
	bucket.BytesSent += m.BytesSent
	bucket.BytesRecv += m.BytesRecv

	if bucket.MinLatencyMs < 0 || m.LatencyMs < bucket.MinLatencyMs {
		bucket.MinLatencyMs = m.LatencyMs
	}
	if m.LatencyMs > bucket.MaxLatencyMs {
		bucket.MaxLatencyMs = m.LatencyMs
	}
	if len(bucket.LatencySamples) < latencySampleCapacity {
		bucket.LatencySamples = append(bucket.LatencySamples, m.LatencyMs)
	} else {
		bucket.LatencySamples[(bucket.RequestCount-1)%latencySampleCapacity] = m.LatencyMs
	}

	bucket.StatusCounts[m.StatusCode]++
	bucket.MethodCounts[m.Method]++
}

func (c *TrafficCollector) updateAnalytics(m HTTPRequestMetric, now time.Time) {
	// Path stats
	c.trackPath(m.Path, m.LatencyMs)

	// IP stats
	c.trackIP(m.ClientIP, now)

	// Referrers (limit to 100)
	if m.Referrer != "" && (len(c.referrerCounts) < TopKLimit || c.referrerCounts[m.Referrer] > 0) {
		c.referrerCounts[m.Referrer]++
	}

	// Methods
	c.methodCounts[m.Method]++

	// Countries
	if m.Country != "" {
		c.countryCounts[m.Country]++
	}

	// User agents (simplified classification)
	os := classifyUserAgent(m.UserAgent)
	c.userAgents[os]++
}

func (c *TrafficCollector) updateLatencyBuckets(latencyMs float64) {
	switch {
	case latencyMs < 10:
		c.latencyBuckets["<10ms"]++
	case latencyMs < 50:
		c.latencyBuckets["10-50ms"]++
	case latencyMs < 200:
		c.latencyBuckets["50-200ms"]++
	default:
		c.latencyBuckets[">200ms"]++
	}
}

func (c *TrafficCollector) trackPath(path string, latencyMs float64) {
	if stats, exists := c.pathCounts[path]; exists {
		stats.count++
		stats.totalLatency += latencyMs
		return
	}
	if len(c.pathCounts) >= TopKLimit {
		c.pathCardinalityDrops++
		return
	}
	c.pathCounts[path] = &pathStats{count: 1, totalLatency: latencyMs}
}

func (c *TrafficCollector) trackIP(ip string, now time.Time) {
	if stats, exists := c.ipCounts[ip]; exists {
		stats.count++
		stats.lastSeen = now
		return
	}
	if len(c.ipCounts) >= TopKLimit {
		c.ipCardinalityDrops++
		return
	}
	c.ipCounts[ip] = &ipStats{count: 1, lastSeen: now}
}

// GetRealtimeStats returns current real-time statistics
func (c *TrafficCollector) GetRealtimeStats() TrafficStats {
	now := time.Now()
	c.ensureUniqueVisitorEstimate(now)
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.realtimeStatsLocked()
}

func (c *TrafficCollector) getGlobalSnapshot() trafficGlobalSnapshot {
	now := time.Now()
	c.ensureUniqueVisitorEstimate(now)
	c.mu.RLock()
	defer c.mu.RUnlock()

	currentBucket := c.minuteBuckets[c.currentMinute]
	avgLatency := 0.0
	if currentBucket.RequestCount > 0 {
		avgLatency = currentBucket.TotalLatencyMs / float64(currentBucket.RequestCount)
	}
	return trafficGlobalSnapshot{
		requestsPerSec: float64(currentBucket.RequestCount) / 60.0,
		avgLatencyMs:   avgLatency,
		totalRequests:  c.totalRequests,
		uniqueVisitors: c.uniqueVisitorEstimate,
	}
}

func (c *TrafficCollector) ensureUniqueVisitorEstimate(now time.Time) {
	c.mu.RLock()
	needsRefresh := c.totalRequests > 0 && (c.uniqueVisitorEstimateAt.IsZero() || now.Sub(c.uniqueVisitorEstimateAt) >= uniqueVisitorEstimateRefreshInterval)
	c.mu.RUnlock()
	if !needsRefresh {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.totalRequests > 0 && (c.uniqueVisitorEstimateAt.IsZero() || now.Sub(c.uniqueVisitorEstimateAt) >= uniqueVisitorEstimateRefreshInterval) {
		c.uniqueVisitorEstimate = c.uniqueVisitors.estimate(now)
		c.uniqueVisitorEstimateAt = now
	}
}

func (c *TrafficCollector) realtimeStatsLocked() TrafficStats {
	currentBucket := c.minuteBuckets[c.currentMinute]
	rps := float64(currentBucket.RequestCount) / 60.0

	avgLatency := 0.0
	if currentBucket.RequestCount > 0 {
		avgLatency = currentBucket.TotalLatencyMs / float64(currentBucket.RequestCount)
	}

	errorRate := 0.0
	if c.totalRequests > 0 {
		errorRate = (float64(c.totalErrors) / float64(c.totalRequests)) * 100
	}

	statusDist := make(map[string]int64)
	for status, count := range currentBucket.StatusCounts {
		statusDist[statusCodeToString(status)] = count
	}

	return TrafficStats{
		RequestsPerSec:             rps,
		AvgLatencyMs:               avgLatency,
		TotalRequests:              c.totalRequests,
		UniqueVisitors:             c.uniqueVisitorEstimate,
		ErrorRate:                  errorRate,
		StatusDistribution:         statusDist,
		PathCardinalityDrops:       c.pathCardinalityDrops,
		IPCardinalityDrops:         c.ipCardinalityDrops,
		UniqueVisitorsEstimated:    true,
		UniqueVisitorRelativeError: uniqueVisitorHLLError,
	}
}

// GetTimeSeries returns time-series data for charts
func (c *TrafficCollector) GetTimeSeries(windowMinutes int) TimeSeriesData {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if windowMinutes > MinuteBuckets {
		windowMinutes = MinuteBuckets
	}

	data := TimeSeriesData{
		Timestamps: make([]string, 0, windowMinutes),
		Requests:   make([]int64, 0, windowMinutes),
		LatencyAvg: make([]float64, 0, windowMinutes),
		LatencyP95: make([]float64, 0, windowMinutes),
		Errors:     make([]int64, 0, windowMinutes),
	}

	now := time.Now()
	for i := 0; i < windowMinutes; i++ {
		bucketTime := now.Add(-time.Duration(windowMinutes-i-1) * time.Minute)
		idx := bucketTime.Minute()
		bucket := c.minuteBuckets[idx]

		data.Timestamps = append(data.Timestamps, bucketTime.Format(time.RFC3339))
		data.Requests = append(data.Requests, bucket.RequestCount)

		avgLatency := 0.0
		if bucket.RequestCount > 0 {
			avgLatency = bucket.TotalLatencyMs / float64(bucket.RequestCount)
		}
		data.LatencyAvg = append(data.LatencyAvg, avgLatency)
		data.LatencyP95 = append(data.LatencyP95, percentile95(bucket.LatencySamples))

		// Count errors
		errors := int64(0)
		for status, count := range bucket.StatusCounts {
			if status >= 400 {
				errors += count
			}
		}
		data.Errors = append(data.Errors, errors)
	}

	return data
}

func percentile95(samples []float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	ordered := append([]float64(nil), samples...)
	sort.Float64s(ordered)
	index := (95*len(ordered) + 99) / 100
	if index > 0 {
		index--
	}
	return ordered[index]
}

// GetTopEndpoints returns most popular endpoints
func (c *TrafficCollector) GetTopEndpoints(limit int) []TopEndpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()

	endpoints := make([]TopEndpoint, 0, len(c.pathCounts))
	for path, stats := range c.pathCounts {
		avgLatency := 0.0
		if stats.count > 0 {
			avgLatency = stats.totalLatency / float64(stats.count)
		}
		endpoints = append(endpoints, TopEndpoint{
			Path:       path,
			Count:      stats.count,
			AvgLatency: avgLatency,
		})
	}

	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].Count > endpoints[j].Count
	})

	if len(endpoints) > limit {
		endpoints = endpoints[:limit]
	}

	return endpoints
}

// GetTopIPs returns top visitor IPs
func (c *TrafficCollector) GetTopIPs(limit int) []TopIP {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ips := make([]TopIP, 0, len(c.ipCounts))
	for ip, stats := range c.ipCounts {
		ips = append(ips, TopIP{
			IP:       ip,
			Count:    stats.count,
			LastSeen: stats.lastSeen,
		})
	}

	sort.Slice(ips, func(i, j int) bool {
		return ips[i].Count > ips[j].Count
	})

	if len(ips) > limit {
		ips = ips[:limit]
	}

	return ips
}

// GetMethodDistribution returns HTTP method distribution
func (c *TrafficCollector) GetMethodDistribution() map[string]int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]int64)
	for method, count := range c.methodCounts {
		result[method] = count
	}
	return result
}

// GetCountryDistribution returns geographic distribution
func (c *TrafficCollector) GetCountryDistribution() map[string]int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]int64)
	for country, count := range c.countryCounts {
		result[country] = count
	}
	return result
}

func statusCodeToString(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500:
		return "5xx"
	default:
		return "other"
	}
}

func classifyUserAgent(ua string) string {
	// Simplified classification
	switch {
	case ua == "":
		return "Unknown"
	case contains(ua, "windows"):
		return "Windows"
	case contains(ua, "macintosh") || contains(ua, "mac os"):
		return "macOS"
	case contains(ua, "android"):
		return "Android"
	case contains(ua, "iphone") || contains(ua, "ipad"):
		return "iOS"
	case contains(ua, "linux"):
		return "Linux"
	case contains(ua, "bot") || contains(ua, "crawler") || contains(ua, "spider"):
		return "Bot"
	default:
		return "Other"
	}
}

func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
