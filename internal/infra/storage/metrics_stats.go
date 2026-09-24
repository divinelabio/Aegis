package storage

import (
	"time"
)

// MetricSnapshot represents a snapshot of system metrics
type MetricSnapshot struct {
	Timestamp         time.Time        `json:"timestamp"`
	TotalRequests     int64            `json:"total_requests"`
	ActiveConnections int              `json:"active_connections"`
	RequestsPerSec    float64          `json:"requests_per_sec"`
	AvgLatencyMs      float64          `json:"avg_latency_ms"`
	StatusCodes       map[string]int64 `json:"status_codes"`
	TopPaths          map[string]int64 `json:"top_paths"`
}

// PipelineStats represents pipeline processing statistics
type PipelineStats struct {
	TotalProcessed  int64            `json:"total_processed"`
	TotalBlocked    int64            `json:"total_blocked"`
	AvgProcessingMs float64          `json:"avg_processing_ms"`
	StageStats      map[string]int64 `json:"stage_stats"`
}
