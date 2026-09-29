package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WAFStats represents WAF statistics from database
type WAFStats struct {
	TotalRequests    int64            `json:"total_requests"`
	BlockedRequests  int64            `json:"blocked_requests"`
	PassedRequests   int64            `json:"passed_requests"`
	DetectedRequests int64            `json:"detected_requests"`
	BlockRate        float64          `json:"block_rate"`
	AvgLatencyMs     float64          `json:"avg_latency_ms"`
	CategoryDist     map[string]int64 `json:"category_dist"`
	TopRules         map[string]int64 `json:"top_rules"`
	ActionDist       map[string]int64 `json:"action_dist"`
	History          []HistoryPoint   `json:"history"`
}

// HistoryPoint represents a time-series data point
type HistoryPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Requests  int64     `json:"requests"`
	Blocked   int64     `json:"blocked"`
}

// WAFEvent represents a WAF event from database
type WAFEvent struct {
	ID           string  `json:"id"`
	Timestamp    int64   `json:"timestamp"`
	ClientIP     string  `json:"ip"`
	Method       string  `json:"method"`
	URI          string  `json:"uri"`
	Action       string  `json:"action"`
	RuleID       string  `json:"rule_id"`
	Message      string  `json:"message"`
	Host         string  `json:"host"`
	Categories   string  `json:"categories"`
	RuleMessages string  `json:"rule_messages"`
	AnomalyScore int     `json:"anomaly_score"`
	InspectionMs float64 `json:"inspection_ms"`
}

// GetWAFEvents retrieves WAF events for the given time window
func GetWAFEvents(window string, limit int) ([]WAFEvent, error) {
	if DB == nil {
		return []WAFEvent{}, nil
	}

	if limit <= 0 {
		limit = 100
	}

	since, err := windowStart(window)
	if err != nil {
		return nil, err
	}

	rows, err := DB.Query(`
		SELECT id, toUnixTimestamp(timestamp), client_ip, method, path, action, rule_id, rule_name, score, latency_ms,
		       JSONExtractString(metadata, 'host'),
		       JSONExtractString(metadata, 'categories'),
		       JSONExtractString(metadata, 'rule_messages')
		FROM section_events
		WHERE section = 'waf_core' AND timestamp >= ?
		ORDER BY timestamp DESC
		LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]WAFEvent, 0, limit)
	for rows.Next() {
		var (
			ev           WAFEvent
			ts           uint32
			latencyMsInt int64
		)
		if err := rows.Scan(&ev.ID, &ts, &ev.ClientIP, &ev.Method, &ev.URI, &ev.Action, &ev.RuleID, &ev.Message, &ev.AnomalyScore, &latencyMsInt, &ev.Host, &ev.Categories, &ev.RuleMessages); err != nil {
			continue
		}
		ev.Timestamp = int64(ts)
		ev.InspectionMs = float64(latencyMsInt)

		events = append(events, ev)
	}

	return events, nil
}

// GetWAFStats retrieves aggregated WAF stats for the given window.
func GetWAFStats(window string) (*WAFStats, error) {
	return GetWAFStatsContext(context.Background(), window)
}

// GetWAFStatsContext keeps the dashboard query contract bounded to three
// server-side aggregate queries and honors caller cancellation/deadlines.
func GetWAFStatsContext(ctx context.Context, window string) (*WAFStats, error) {
	stats := &WAFStats{
		CategoryDist: make(map[string]int64),
		TopRules:     make(map[string]int64),
		ActionDist:   make(map[string]int64),
		History:      make([]HistoryPoint, 0),
	}
	if DB == nil {
		return stats, nil
	}

	since, err := windowStart(window)
	if err != nil {
		return nil, err
	}

	row := DB.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN action = 'detect' OR action = 'log' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN action = 'allow' OR action = 'pass' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN action = 'error' THEN 1 ELSE 0 END), 0),
		       COALESCE(AVG(latency_ms), 0)
		FROM section_events
		WHERE section = 'waf_core' AND timestamp >= ?`, since)

	var total, blocked, detected, allowed, errors int64
	if err := row.Scan(&total, &blocked, &detected, &allowed, &errors, &stats.AvgLatencyMs); err != nil {
		return nil, err
	}
	stats.TotalRequests = total
	stats.BlockedRequests = blocked
	stats.DetectedRequests = detected
	stats.PassedRequests = allowed
	if total > 0 {
		stats.BlockRate = (float64(blocked) / float64(total)) * 100
	}
	stats.ActionDist["block"] = blocked
	stats.ActionDist["detect"] = detected
	stats.ActionDist["allow"] = allowed
	if errors > 0 {
		stats.ActionDist["error"] = errors
	}

	historyRows, err := DB.QueryContext(ctx, `
		SELECT toUnixTimestamp(bucket), COUNT(*),
		       COALESCE(SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END), 0)
		FROM (
			SELECT toStartOfHour(timestamp) AS bucket, action
			FROM section_events
			WHERE section = 'waf_core' AND timestamp >= ?
		)
		GROUP BY bucket
		ORDER BY bucket ASC`, since)
	if err != nil {
		return nil, err
	}
	for historyRows.Next() {
		var ts, requests, blockedCount int64
		if err := historyRows.Scan(&ts, &requests, &blockedCount); err != nil {
			_ = historyRows.Close()
			return nil, err
		}
		stats.History = append(stats.History, HistoryPoint{
			Timestamp: time.Unix(ts, 0).UTC(),
			Requests:  requests,
			Blocked:   blockedCount,
		})
	}
	if err := historyRows.Err(); err != nil {
		_ = historyRows.Close()
		return nil, err
	}
	_ = historyRows.Close()

	// Aggregate combinations in the database. The number of rows returned is
	// bounded by distinct category-array/rule pairs, not by request volume.
	breakdownRows, err := DB.QueryContext(ctx, `
		SELECT JSONExtractString(metadata, 'categories') AS categories, rule_id, COUNT(*)
		FROM section_events
		WHERE section = 'waf_core' AND timestamp >= ?
		GROUP BY categories, rule_id`, since)
	if err != nil {
		return nil, err
	}
	for breakdownRows.Next() {
		var categoriesRaw, ruleID string
		var count int64
		if err := breakdownRows.Scan(&categoriesRaw, &ruleID, &count); err != nil {
			_ = breakdownRows.Close()
			return nil, err
		}
		for _, category := range parseStringJSONArray(categoriesRaw) {
			category = strings.ToLower(strings.TrimSpace(category))
			if category != "" {
				stats.CategoryDist[category] += count
			}
		}
		ruleID = strings.TrimSpace(ruleID)
		if ruleID != "" {
			stats.TopRules[ruleID] += count
		}
	}
	if err := breakdownRows.Err(); err != nil {
		_ = breakdownRows.Close()
		return nil, err
	}
	_ = breakdownRows.Close()

	return stats, nil
}

// ValidateWindow returns an error when the provided stats window is invalid.
func ValidateWindow(window string) error {
	_, err := windowStart(window)
	return err
}

func windowStart(window string) (time.Time, error) {
	w := strings.TrimSpace(strings.ToLower(window))
	if w == "" {
		w = "24h"
	}

	switch w {
	case "1h":
		return time.Now().UTC().Add(-1 * time.Hour), nil
	case "24h":
		return time.Now().UTC().Add(-24 * time.Hour), nil
	case "7d":
		return time.Now().UTC().Add(-7 * 24 * time.Hour), nil
	case "30d":
		return time.Now().UTC().Add(-30 * 24 * time.Hour), nil
	default:
		d, err := time.ParseDuration(w)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid window %q", window)
		}
		return time.Now().UTC().Add(-d), nil
	}
}

func parseStringJSONArray(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil
	}

	// Fast path for a single item like ["value"].
	if strings.HasPrefix(raw, `["`) && strings.HasSuffix(raw, `"]`) {
		inner := raw[2 : len(raw)-2]
		if !strings.Contains(inner, `","`) && !strings.Contains(inner, `\"`) {
			return []string{inner}
		}
	}

	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}
