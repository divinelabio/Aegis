package metrics

import "time"

// RequestMetric represents a single HTTP request metric
type RequestMetric struct {
	Timestamp  time.Time
	Method     string
	Path       string
	StatusCode int
	LatencyMs  float64
	ClientIP   string
	UserAgent  string
	Referrer   string
	BytesSent  int64
	BytesRecv  int64
}

// TimeBucket represents aggregated metrics for a time period
type TimeBucket struct {
	Timestamp      time.Time
	RequestCount   int64
	TotalLatencyMs float64
	MinLatencyMs   float64
	MaxLatencyMs   float64
	LatencySamples []float64
	StatusCounts   map[int]int64
	MethodCounts   map[string]int64
	BytesSent      int64
	BytesRecv      int64
}

// RealtimeStats represents current real-time statistics
type RealtimeStats struct {
	RequestsPerSec             float64          `json:"requests_per_sec"`
	AvgLatencyMs               float64          `json:"avg_latency_ms"`
	TotalRequests              int64            `json:"total_requests"`
	UniqueVisitors             int64            `json:"unique_visitors"`
	UniqueVisitorsEstimated    bool             `json:"unique_visitors_estimated"`
	UniqueVisitorRelativeError float64          `json:"unique_visitor_relative_error"`
	ErrorRate                  float64          `json:"error_rate"`
	StatusDistribution         map[string]int64 `json:"status_distribution"`
}

// TimeSeriesData represents time-series metrics for charts
type TimeSeriesData struct {
	Timestamps []string  `json:"timestamps"`
	Requests   []int64   `json:"requests"`
	LatencyAvg []float64 `json:"latency_avg"`
	LatencyP95 []float64 `json:"latency_p95"`
	Errors     []int64   `json:"errors"`
}

// TopEndpoint represents a popular endpoint
type TopEndpoint struct {
	Path       string  `json:"path"`
	Count      int64   `json:"count"`
	AvgLatency float64 `json:"avg_latency"`
}

// TopIP represents a top visitor IP
type TopIP struct {
	IP       string    `json:"ip"`
	Count    int64     `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}
