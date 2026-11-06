package storage

import (
	"context"
	"fmt"
	"log"
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

// AggregateSecurityRollups aggregates security events from section_events (WHERE section != 'traffic')
// grouped by bucket_hour, section, action into kpi_security_rollups_1h using ON CONFLICT DO UPDATE.
func (s *KPIRollupStore) AggregateSecurityRollups(ctx context.Context, since time.Time) error {
	if s.pool == nil {
		return fmt.Errorf("control db pool is unavailable")
	}

	var query string
	var args []interface{}
	if !since.IsZero() {
		since = since.Truncate(time.Hour)
		query = `
		INSERT INTO kpi_security_rollups_1h (
			bucket_hour, section_id, action, total_events,
			blocked_requests, challenged_requests, flagged_requests
		)
		SELECT 
			date_trunc('hour', timestamp) AS bucket_hour,
			section AS section_id,
			action,
			COUNT(*) AS total_events,
			COUNT(*) FILTER (WHERE action IN ('block', 'drop')) AS blocked_requests,
			COUNT(*) FILTER (WHERE action = 'challenge') AS challenged_requests,
			COUNT(*) FILTER (WHERE action IN ('detect', 'flag', 'observe', 'log')) AS flagged_requests
		FROM section_events
		WHERE section != 'traffic' AND timestamp >= $1
		GROUP BY date_trunc('hour', timestamp), section, action
		ON CONFLICT (bucket_hour, section_id, action) DO UPDATE SET
			total_events = EXCLUDED.total_events,
			blocked_requests = EXCLUDED.blocked_requests,
			challenged_requests = EXCLUDED.challenged_requests,
			flagged_requests = EXCLUDED.flagged_requests;
		`
		args = []interface{}{since}
	} else {
		query = `
		INSERT INTO kpi_security_rollups_1h (
			bucket_hour, section_id, action, total_events,
			blocked_requests, challenged_requests, flagged_requests
		)
		SELECT 
			date_trunc('hour', timestamp) AS bucket_hour,
			section AS section_id,
			action,
			COUNT(*) AS total_events,
			COUNT(*) FILTER (WHERE action IN ('block', 'drop')) AS blocked_requests,
			COUNT(*) FILTER (WHERE action = 'challenge') AS challenged_requests,
			COUNT(*) FILTER (WHERE action IN ('detect', 'flag', 'observe', 'log')) AS flagged_requests
		FROM section_events
		WHERE section != 'traffic'
		GROUP BY date_trunc('hour', timestamp), section, action
		ON CONFLICT (bucket_hour, section_id, action) DO UPDATE SET
			total_events = EXCLUDED.total_events,
			blocked_requests = EXCLUDED.blocked_requests,
			challenged_requests = EXCLUDED.challenged_requests,
			flagged_requests = EXCLUDED.flagged_requests;
		`
	}

	_, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("aggregate security rollups: %w", err)
	}
	return nil
}

// AggregateTrafficRollups aggregates traffic events from section_events (WHERE section = 'traffic')
// grouped by bucket_minute into kpi_traffic_rollups_1m using ON CONFLICT DO UPDATE.
func (s *KPIRollupStore) AggregateTrafficRollups(ctx context.Context, since time.Time) error {
	if s.pool == nil {
		return fmt.Errorf("control db pool is unavailable")
	}

	var query string
	var args []interface{}
	if !since.IsZero() {
		since = since.Truncate(time.Minute)
		query = `
		INSERT INTO kpi_traffic_rollups_1m (
			bucket_minute, route_id, total_requests, bytes_in, bytes_out,
			status_2xx, status_4xx, status_5xx,
			latency_p50_ms, latency_p95_ms, latency_p99_ms
		)
		SELECT 
			date_trunc('minute', timestamp) AS bucket_minute,
			'global' AS route_id,
			COUNT(*) AS total_requests,
			0::bigint AS bytes_in,
			COALESCE(SUM(CASE WHEN metadata LIKE '{%}' AND (metadata::jsonb ? 'bytes_sent') AND (metadata::jsonb->>'bytes_sent') ~ '^[0-9]+$' THEN (metadata::jsonb->>'bytes_sent')::bigint ELSE 0 END), 0)::bigint AS bytes_out,
			COUNT(*) FILTER (WHERE status_code >= 200 AND status_code < 300) AS status_2xx,
			COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS status_4xx,
			COUNT(*) FILTER (WHERE status_code >= 500 AND status_code < 600) AS status_5xx,
			COALESCE(percentile_cont(0.50) WITHIN GROUP (ORDER BY latency_ms)::int, 0) AS latency_p50_ms,
			COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)::int, 0) AS latency_p95_ms,
			COALESCE(percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms)::int, 0) AS latency_p99_ms
		FROM section_events
		WHERE timestamp >= $1
		GROUP BY date_trunc('minute', timestamp)
		ON CONFLICT (bucket_minute, route_id) DO UPDATE SET
			total_requests = EXCLUDED.total_requests,
			bytes_in = EXCLUDED.bytes_in,
			bytes_out = EXCLUDED.bytes_out,
			status_2xx = EXCLUDED.status_2xx,
			status_4xx = EXCLUDED.status_4xx,
			status_5xx = EXCLUDED.status_5xx,
			latency_p50_ms = EXCLUDED.latency_p50_ms,
			latency_p95_ms = EXCLUDED.latency_p95_ms,
			latency_p99_ms = EXCLUDED.latency_p99_ms;
		`
		args = []interface{}{since}
	} else {
		query = `
		INSERT INTO kpi_traffic_rollups_1m (
			bucket_minute, route_id, total_requests, bytes_in, bytes_out,
			status_2xx, status_4xx, status_5xx,
			latency_p50_ms, latency_p95_ms, latency_p99_ms
		)
		SELECT 
			date_trunc('minute', timestamp) AS bucket_minute,
			'global' AS route_id,
			COUNT(*) AS total_requests,
			0::bigint AS bytes_in,
			COALESCE(SUM(CASE WHEN metadata LIKE '{%}' AND (metadata::jsonb ? 'bytes_sent') AND (metadata::jsonb->>'bytes_sent') ~ '^[0-9]+$' THEN (metadata::jsonb->>'bytes_sent')::bigint ELSE 0 END), 0)::bigint AS bytes_out,
			COUNT(*) FILTER (WHERE status_code >= 200 AND status_code < 300) AS status_2xx,
			COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS status_4xx,
			COUNT(*) FILTER (WHERE status_code >= 500 AND status_code < 600) AS status_5xx,
			COALESCE(percentile_cont(0.50) WITHIN GROUP (ORDER BY latency_ms)::int, 0) AS latency_p50_ms,
			COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)::int, 0) AS latency_p95_ms,
			COALESCE(percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms)::int, 0) AS latency_p99_ms
		FROM section_events
		GROUP BY date_trunc('minute', timestamp)
		ON CONFLICT (bucket_minute, route_id) DO UPDATE SET
			total_requests = EXCLUDED.total_requests,
			bytes_in = EXCLUDED.bytes_in,
			bytes_out = EXCLUDED.bytes_out,
			status_2xx = EXCLUDED.status_2xx,
			status_4xx = EXCLUDED.status_4xx,
			status_5xx = EXCLUDED.status_5xx,
			latency_p50_ms = EXCLUDED.latency_p50_ms,
			latency_p95_ms = EXCLUDED.latency_p95_ms,
			latency_p99_ms = EXCLUDED.latency_p99_ms;
		`
	}

	_, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("aggregate traffic rollups: %w", err)
	}
	return nil
}

// StartRollupWorker performs an initial backfill on startup, then runs on a background ticker
// (e.g. every 1 minute) to keep rollups continuously updated.
func (s *KPIRollupStore) StartRollupWorker(ctx context.Context, interval time.Duration) {
	if s.pool == nil {
		return
	}
	if interval <= 0 {
		interval = 1 * time.Minute
	}

	// Initial backfill across all history
	if err := s.AggregateSecurityRollups(ctx, time.Time{}); err != nil {
		log.Printf("[kpi_rollups] initial security backfill failed: %v", err)
	}
	if err := s.AggregateTrafficRollups(ctx, time.Time{}); err != nil {
		log.Printf("[kpi_rollups] initial traffic backfill failed: %v", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			secSince := now.Add(-2 * time.Hour)
			if err := s.AggregateSecurityRollups(ctx, secSince); err != nil {
				log.Printf("[kpi_rollups] security rollup update failed: %v", err)
			}

			trafSince := now.Add(-30 * time.Minute)
			if err := s.AggregateTrafficRollups(ctx, trafSince); err != nil {
				log.Printf("[kpi_rollups] traffic rollup update failed: %v", err)
			}
		}
	}
}

