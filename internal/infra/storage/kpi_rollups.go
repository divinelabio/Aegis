package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TrafficMinuteRollup holds aggregated 1-minute traffic metrics.
type TrafficMinuteRollup struct {
	BucketMinute  time.Time `json:"bucket_minute"`
	RouteID       string    `json:"route_id"`
	TotalRequests int64     `json:"total_requests"`
	BytesIn       int64     `json:"bytes_in"`
	BytesOut      int64     `json:"bytes_out"`
	Status2xx     int64     `json:"status_2xx"`
	Status4xx     int64     `json:"status_4xx"`
	Status5xx     int64     `json:"status_5xx"`
	LatencyP50Ms  int       `json:"latency_p50_ms"`
	LatencyP95Ms  int       `json:"latency_p95_ms"`
	LatencyP99Ms  int       `json:"latency_p99_ms"`
}

// SecurityHourRollup holds aggregated 1-hour security events.
type SecurityHourRollup struct {
	BucketHour         time.Time `json:"bucket_hour"`
	SectionID          string    `json:"section_id"`
	Action             string    `json:"action"`
	TotalEvents        int64     `json:"total_events"`
	BlockedRequests    int64     `json:"blocked_requests"`
	ChallengedRequests int64     `json:"challenged_requests"`
	FlaggedRequests    int64     `json:"flagged_requests"`
}

// KPIRollupStore manages PostgreSQL persistent rollup storage.
type KPIRollupStore struct {
	pool *pgxpool.Pool
}

// NewKPIRollupStore creates a new KPIRollupStore instance.
func NewKPIRollupStore(pool *pgxpool.Pool) *KPIRollupStore {
	return &KPIRollupStore{pool: pool}
}

// EnsureKPIRollupSchema creates the rollup tables and indexes if they do not exist.
func (s *KPIRollupStore) EnsureKPIRollupSchema(ctx context.Context) error {
	if s.pool == nil {
		return fmt.Errorf("control db pool is unavailable")
	}

	const schemaSQL = `
	CREATE TABLE IF NOT EXISTS kpi_traffic_rollups_1m (
		bucket_minute TIMESTAMPTZ NOT NULL,
		route_id VARCHAR(64) NOT NULL DEFAULT 'global',
		total_requests BIGINT NOT NULL DEFAULT 0,
		bytes_in BIGINT NOT NULL DEFAULT 0,
		bytes_out BIGINT NOT NULL DEFAULT 0,
		status_2xx BIGINT NOT NULL DEFAULT 0,
		status_4xx BIGINT NOT NULL DEFAULT 0,
		status_5xx BIGINT NOT NULL DEFAULT 0,
		latency_p50_ms INT NOT NULL DEFAULT 0,
		latency_p95_ms INT NOT NULL DEFAULT 0,
		latency_p99_ms INT NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket_minute, route_id)
	);

	CREATE INDEX IF NOT EXISTS idx_kpi_traffic_time ON kpi_traffic_rollups_1m (bucket_minute DESC);

	CREATE TABLE IF NOT EXISTS kpi_security_rollups_1h (
		bucket_hour TIMESTAMPTZ NOT NULL,
		section_id VARCHAR(32) NOT NULL,
		action VARCHAR(32) NOT NULL,
		total_events BIGINT NOT NULL DEFAULT 0,
		blocked_requests BIGINT NOT NULL DEFAULT 0,
		challenged_requests BIGINT NOT NULL DEFAULT 0,
		flagged_requests BIGINT NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket_hour, section_id, action)
	);

	CREATE INDEX IF NOT EXISTS idx_kpi_security_time ON kpi_security_rollups_1h (bucket_hour DESC);
	`

	_, err := s.pool.Exec(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("ensure kpi rollup schema: %w", err)
	}
	return nil
}

// RecordTrafficRollup inserts or aggregates 1-minute traffic rollup record.
func (s *KPIRollupStore) RecordTrafficRollup(ctx context.Context, r TrafficMinuteRollup) error {
	if s.pool == nil {
		return fmt.Errorf("control db pool is unavailable")
	}
	if r.RouteID == "" {
		r.RouteID = "global"
	}
	r.BucketMinute = r.BucketMinute.Truncate(time.Minute)

	const insertSQL = `
	INSERT INTO kpi_traffic_rollups_1m (
		bucket_minute, route_id, total_requests, bytes_in, bytes_out,
		status_2xx, status_4xx, status_5xx, latency_p50_ms, latency_p95_ms, latency_p99_ms
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	ON CONFLICT (bucket_minute, route_id) DO UPDATE SET
		total_requests = kpi_traffic_rollups_1m.total_requests + EXCLUDED.total_requests,
		bytes_in = kpi_traffic_rollups_1m.bytes_in + EXCLUDED.bytes_in,
		bytes_out = kpi_traffic_rollups_1m.bytes_out + EXCLUDED.bytes_out,
		status_2xx = kpi_traffic_rollups_1m.status_2xx + EXCLUDED.status_2xx,
		status_4xx = kpi_traffic_rollups_1m.status_4xx + EXCLUDED.status_4xx,
		status_5xx = kpi_traffic_rollups_1m.status_5xx + EXCLUDED.status_5xx,
		latency_p50_ms = GREATEST(kpi_traffic_rollups_1m.latency_p50_ms, EXCLUDED.latency_p50_ms),
		latency_p95_ms = GREATEST(kpi_traffic_rollups_1m.latency_p95_ms, EXCLUDED.latency_p95_ms),
		latency_p99_ms = GREATEST(kpi_traffic_rollups_1m.latency_p99_ms, EXCLUDED.latency_p99_ms);
	`

	_, err := s.pool.Exec(ctx, insertSQL,
		r.BucketMinute, r.RouteID, r.TotalRequests, r.BytesIn, r.BytesOut,
		r.Status2xx, r.Status4xx, r.Status5xx, r.LatencyP50Ms, r.LatencyP95Ms, r.LatencyP99Ms,
	)
	return err
}

// RecordSecurityRollup inserts or aggregates 1-hour security rollup record.
func (s *KPIRollupStore) RecordSecurityRollup(ctx context.Context, r SecurityHourRollup) error {
	if s.pool == nil {
		return fmt.Errorf("control db pool is unavailable")
	}
	r.BucketHour = r.BucketHour.Truncate(time.Hour)

	const insertSQL = `
	INSERT INTO kpi_security_rollups_1h (
		bucket_hour, section_id, action, total_events,
		blocked_requests, challenged_requests, flagged_requests
	) VALUES ($1, $2, $3, $4, $5, $6, $7)
	ON CONFLICT (bucket_hour, section_id, action) DO UPDATE SET
		total_events = kpi_security_rollups_1h.total_events + EXCLUDED.total_events,
		blocked_requests = kpi_security_rollups_1h.blocked_requests + EXCLUDED.blocked_requests,
		challenged_requests = kpi_security_rollups_1h.challenged_requests + EXCLUDED.challenged_requests,
		flagged_requests = kpi_security_rollups_1h.flagged_requests + EXCLUDED.flagged_requests;
	`

	_, err := s.pool.Exec(ctx, insertSQL,
		r.BucketHour, r.SectionID, r.Action, r.TotalEvents,
		r.BlockedRequests, r.ChallengedRequests, r.FlaggedRequests,
	)
	return err
}

// QueryTrafficKPIs retrieves minute rollups within a time window.
func (s *KPIRollupStore) QueryTrafficKPIs(ctx context.Context, from, to time.Time, routeID string) ([]TrafficMinuteRollup, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("control db pool is unavailable")
	}

	var query string
	var args []interface{}
	if routeID != "" {
		query = `
		SELECT bucket_minute, route_id, total_requests, bytes_in, bytes_out,
		       status_2xx, status_4xx, status_5xx, latency_p50_ms, latency_p95_ms, latency_p99_ms
		FROM kpi_traffic_rollups_1m
		WHERE bucket_minute >= $1 AND bucket_minute <= $2 AND route_id = $3
		ORDER BY bucket_minute ASC`
		args = []interface{}{from, to, routeID}
	} else {
		query = `
		SELECT bucket_minute, route_id, total_requests, bytes_in, bytes_out,
		       status_2xx, status_4xx, status_5xx, latency_p50_ms, latency_p95_ms, latency_p99_ms
		FROM kpi_traffic_rollups_1m
		WHERE bucket_minute >= $1 AND bucket_minute <= $2
		ORDER BY bucket_minute ASC`
		args = []interface{}{from, to}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query traffic kpis: %w", err)
	}
	defer rows.Close()

	var results []TrafficMinuteRollup
	for rows.Next() {
		var item TrafficMinuteRollup
		if err := rows.Scan(
			&item.BucketMinute, &item.RouteID, &item.TotalRequests, &item.BytesIn, &item.BytesOut,
			&item.Status2xx, &item.Status4xx, &item.Status5xx,
			&item.LatencyP50Ms, &item.LatencyP95Ms, &item.LatencyP99Ms,
		); err != nil {
			return nil, fmt.Errorf("scan traffic kpi row: %w", err)
		}
		results = append(results, item)
	}
	return results, nil
}

// QuerySecurityKPIs retrieves hourly security rollups within a time window.
func (s *KPIRollupStore) QuerySecurityKPIs(ctx context.Context, from, to time.Time) ([]SecurityHourRollup, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("control db pool is unavailable")
	}

	const query = `
	SELECT bucket_hour, section_id, action, total_events,
	       blocked_requests, challenged_requests, flagged_requests
	FROM kpi_security_rollups_1h
	WHERE bucket_hour >= $1 AND bucket_hour <= $2
	ORDER BY bucket_hour ASC`

	rows, err := s.pool.Query(ctx, query, from, to)
	if err != nil {
		return nil, fmt.Errorf("query security kpis: %w", err)
	}
	defer rows.Close()

	var results []SecurityHourRollup
	for rows.Next() {
		var item SecurityHourRollup
		if err := rows.Scan(
			&item.BucketHour, &item.SectionID, &item.Action, &item.TotalEvents,
			&item.BlockedRequests, &item.ChallengedRequests, &item.FlaggedRequests,
		); err != nil {
			return nil, fmt.Errorf("scan security kpi row: %w", err)
		}
		results = append(results, item)
	}
	return results, nil
}
