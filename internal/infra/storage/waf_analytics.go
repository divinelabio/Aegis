package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

type sqlScanner interface {
	Scan(dest ...any) error
}

type WAFAnalyticsQuery struct {
	Window   string
	Interval string
	// Section scopes an analytics query to one of the allowed sections. Sections
	// is internal-only and lets the shared dashboard aggregate its security
	// event sources without changing individual section dashboards.
	Section      string
	Sections     []string
	Action       string
	Category     string
	RuleID       string
	IP           string
	Path         string
	Method       string
	Host         string
	Country      string
	Status       string
	Severity     string
	MatchedField string
	UserAgent       string
	UserAgentFamily string
	RequestID       string
	StatusClass     string
	RuleName        string
	JA3             string
	JA4             string
	ASN             string
	Policy          string
	Since           string
	Until           string
	MinScore        *int
	MaxScore        *int
	Limit           int
	Cursor          string
	Sort            string
}

type WAFAnalyticsSummary struct {
	TotalRequests     int64   `json:"total_requests"`
	BlockedRequests   int64   `json:"blocked_requests"`
	DetectedRequests  int64   `json:"detected_requests"`
	AllowedRequests   int64   `json:"allowed_requests"`
	ErrorRequests     int64   `json:"error_requests"`
	BlockRate         float64 `json:"block_rate"`
	DetectionRate     float64 `json:"detection_rate"`
	AvgLatencyMs      float64 `json:"avg_latency_ms"`
	P95LatencyMs      float64 `json:"p95_latency_ms"`
	AvgAnomalyScore   float64 `json:"avg_anomaly_score"`
	MaxAnomalyScore   int     `json:"max_anomaly_score"`
	UniqueSourceIPs   int64   `json:"unique_source_ips"`
	UniqueCountries   int64   `json:"unique_countries"`
	TopAttackCategory string  `json:"top_attack_category"`
	DroppedEvents     int64   `json:"dropped_events"`
	Window            string  `json:"window"`
}

type WAFTimeseriesPoint struct {
	Timestamp       int64            `json:"timestamp"`
	Counts          map[string]int64 `json:"counts"`
	AvgLatencyMs    float64          `json:"avg_latency_ms"`
	P95LatencyMs    float64          `json:"p95_latency_ms"`
	AvgAnomalyScore float64          `json:"avg_anomaly_score"`
}

type WAFBreakdownItem struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	Count        int64   `json:"count"`
	Blocked      int64   `json:"blocked"`
	Detected     int64   `json:"detected"`
	BlockRate    float64 `json:"block_rate"`
	Percent      float64 `json:"percent"`
	LastSeen     int64   `json:"last_seen"`
	AvgScore     float64 `json:"avg_score"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

type WAFAnalyticsEvent struct {
	ID                         string            `json:"id"`
	Timestamp                  int64             `json:"timestamp"`
	Section                    string            `json:"section,omitempty"`
	ClientIP                   string            `json:"client_ip"`
	Country                    string            `json:"country"`
	City                       string            `json:"city"`
	Method                     string            `json:"method"`
	Host                       string            `json:"host"`
	Path                       string            `json:"path"`
	QueryString                string            `json:"query_string"`
	StatusCode                 int               `json:"status_code"`
	Action                     string            `json:"action"`
	UserAgent                  string            `json:"user_agent"`
	RuleID                     string            `json:"rule_id"`
	RuleName                   string            `json:"rule_name"`
	RuleIDs                    []string          `json:"rule_ids"`
	RuleMessages               []string          `json:"rule_messages"`
	Categories                 []string          `json:"categories"`
	Severities                 []string          `json:"severities"`
	MatchedFields              []string          `json:"matched_fields"`
	RuleCount                  int               `json:"rule_count"`
	AnomalyScore               int               `json:"anomaly_score"`
	LatencyMs                  int64             `json:"latency_ms"`
	RequestID                  string            `json:"request_id"`
	RequestSize                int64             `json:"request_size"`
	ResponseSize               int64             `json:"response_size"`
	UserAgentFamily            string            `json:"user_agent_family"`
	RuleSource                 string            `json:"rule_source,omitempty"`
	PolicyID                   string            `json:"policy_id,omitempty"`
	PolicyName                 string            `json:"policy_name,omitempty"`
	ClientIPSource             string            `json:"client_ip_source,omitempty"`
	RequestTruncated           bool              `json:"request_truncated,omitempty"`
	ResponseInspected          bool              `json:"response_inspected,omitempty"`
	ResponseInspectionCoverage string            `json:"response_inspection_coverage,omitempty"`
	ResponseTruncated          bool              `json:"response_truncated,omitempty"`
	ExclusionIDs               []string          `json:"exclusion_ids,omitempty"`
	ReloadID                   string            `json:"reload_id,omitempty"`
	Metadata                   map[string]string `json:"metadata,omitempty"`
}

type WAFAnalyticsEventsPage struct {
	Events     []WAFAnalyticsEvent `json:"events"`
	NextCursor string              `json:"next_cursor,omitempty"`
	Count      int                 `json:"count"`
}

type WAFAnalyticsHealth struct {
	DBAvailable         bool   `json:"db_available"`
	LastEventTimestamp  int64  `json:"last_event_timestamp"`
	IngestionLagSeconds int64  `json:"ingestion_lag_seconds"`
	DroppedEvents       int64  `json:"dropped_events"`
	FreshnessStatus     string `json:"freshness_status"`
	Message             string `json:"message"`
}

type WAFProtectionSummary struct {
	BlockedAttacks    int64   `json:"blocked_attacks"`
	DetectedOnly      int64   `json:"detected_only"`
	RuleMatches       int64   `json:"rule_matches"`
	CriticalHigh      int64   `json:"critical_high"`
	AvgAnomalyScore   float64 `json:"avg_anomaly_score"`
	MaxAnomalyScore   int     `json:"max_anomaly_score"`
	EnforcedBlockRate float64 `json:"enforced_block_rate"`
	TopAttackCategory string  `json:"top_attack_category"`
	Window            string  `json:"window"`
}

type WAFAttackIntelligence struct {
	Categories        []WAFBreakdownItem   `json:"categories"`
	Severities        []WAFBreakdownItem   `json:"severities"`
	AnomalyScoreBands []WAFBreakdownItem   `json:"anomaly_score_bands"`
	Trend             []WAFTimeseriesPoint `json:"trend"`
}

type WAFRuleEffectiveness struct {
	TopBlockingRules   []WAFBreakdownItem `json:"top_blocking_rules"`
	TopDetectOnlyRules []WAFBreakdownItem `json:"top_detect_only_rules"`
	NoisyRules         []WAFBreakdownItem `json:"noisy_rules"`
	MatchedFields      []WAFBreakdownItem `json:"matched_fields"`
}

// SecurityAnalyticsBreakdown is a ranked result set for one protection
// section. These are analysis panels, not repeated KPI cards.
type SecurityAnalyticsBreakdown struct {
	Key   string             `json:"key"`
	Label string             `json:"label"`
	Items []WAFBreakdownItem `json:"items"`
}

// Retained only while the internal aggregation code is migrated. It is not
// part of the dashboard response and is intentionally ignored by JSON.
type SecurityAnalyticsCard struct {
	Key    string `json:"-"`
	Label  string `json:"-"`
	Detail string `json:"-"`
	Value  int64  `json:"-"`
}

type SecuritySectionAnalytics struct {
	Section    string                       `json:"section"`
	Label      string                       `json:"label"`
	Breakdowns []SecurityAnalyticsBreakdown `json:"breakdowns"`
	Cards      []SecurityAnalyticsCard      `json:"-"`
}

type WAFInspectionCoverage struct {
	RequestInspectedCount  int64   `json:"request_inspected_count"`
	ResponseInspectedCount int64   `json:"response_inspected_count"`
	PartialResponseCount   int64   `json:"partial_response_count"`
	TruncatedRequestCount  int64   `json:"truncated_request_count"`
	TruncatedResponseCount int64   `json:"truncated_response_count"`
	TruncatedRequestRate   float64 `json:"truncated_request_rate"`
	TruncatedResponseRate  float64 `json:"truncated_response_rate"`
	DroppedEvents          int64   `json:"dropped_events"`
	FreshnessStatus        string  `json:"freshness_status"`
	Message                string  `json:"message"`
}

type WAFPolicyHealth struct {
	Status         string `json:"status"`
	PolicyID       string `json:"policy_id,omitempty"`
	PolicyName     string `json:"policy_name,omitempty"`
	RuleSource     string `json:"rule_source,omitempty"`
	ReloadID       string `json:"reload_id,omitempty"`
	ExclusionCount int64  `json:"exclusion_count"`
	Message        string `json:"message"`
}

type WAFTuningRecommendation struct {
	Kind         string `json:"kind"`
	Title        string `json:"title"`
	Detail       string `json:"detail"`
	RuleID       string `json:"rule_id,omitempty"`
	RuleName     string `json:"rule_name,omitempty"`
	Count        int64  `json:"count"`
	Severity     string `json:"severity,omitempty"`
	MatchedField string `json:"matched_field,omitempty"`
}

type WAFAnalyticsDashboard struct {
	Summary               WAFAnalyticsSummary           `json:"summary"`
	Timeseries            []WAFTimeseriesPoint          `json:"timeseries"`
	Breakdowns            map[string][]WAFBreakdownItem `json:"breakdowns"`
	Events                WAFAnalyticsEventsPage        `json:"events"`
	Health                WAFAnalyticsHealth            `json:"health"`
	ProtectionSummary     WAFProtectionSummary          `json:"protection_summary"`
	AttackIntelligence    WAFAttackIntelligence         `json:"attack_intelligence"`
	RuleEffectiveness     WAFRuleEffectiveness          `json:"rule_effectiveness"`
	SectionAnalytics      []SecuritySectionAnalytics    `json:"section_analytics"`
	InspectionCoverage    WAFInspectionCoverage         `json:"inspection_coverage"`
	PolicyHealth          WAFPolicyHealth               `json:"policy_health"`
	TuningRecommendations []WAFTuningRecommendation     `json:"tuning_recommendations"`
	Warnings              []string                      `json:"warnings"`
}

func GetWAFAnalyticsSummary(q WAFAnalyticsQuery) (WAFAnalyticsSummary, error) {
	summary := WAFAnalyticsSummary{
		Window:        defaultWindow(q.Window),
		DroppedEvents: WAFDroppedEvents(),
	}
	if DB == nil {
		return summary, nil
	}
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return summary, err
	}
	row := DB.QueryRow(`
		SELECT
			count(),
			countIf(`+normalizedActionSQL()+` = 'block'),
			countIf(`+normalizedActionSQL()+` = 'detect'),
			countIf(`+normalizedActionSQL()+` = 'allow'),
			countIf(`+normalizedActionSQL()+` = 'error'),
			COALESCE(avg(latency_ms), 0),
			COALESCE(quantile(0.95)(latency_ms), 0),
			COALESCE(avg(score), 0),
			COALESCE(max(score), 0),
			uniqExact(client_ip),
			uniqExactIf(country, country != '')
		FROM section_events `+where, args...)

	var total, blocked, detected, allowed, errors, uniqueIPs, uniqueCountries uint64
	var maxScore int32
	if err := row.Scan(&total, &blocked, &detected, &allowed, &errors, &summary.AvgLatencyMs, &summary.P95LatencyMs, &summary.AvgAnomalyScore, &maxScore, &uniqueIPs, &uniqueCountries); err != nil {
		return summary, err
	}
	summary.TotalRequests = int64(total)
	summary.BlockedRequests = int64(blocked)
	summary.DetectedRequests = int64(detected)
	summary.AllowedRequests = int64(allowed)
	summary.ErrorRequests = int64(errors)
	summary.MaxAnomalyScore = int(maxScore)
	summary.UniqueSourceIPs = int64(uniqueIPs)
	summary.UniqueCountries = int64(uniqueCountries)
	if total > 0 {
		summary.BlockRate = float64(blocked) / float64(total) * 100
		summary.DetectionRate = float64(blocked+detected) / float64(total) * 100
	}
	summary.AvgLatencyMs = finiteFloat(summary.AvgLatencyMs)
	summary.P95LatencyMs = finiteFloat(summary.P95LatencyMs)
	summary.AvgAnomalyScore = finiteFloat(summary.AvgAnomalyScore)
	return summary, nil
}

func GetWAFAnalyticsTimeseries(q WAFAnalyticsQuery) ([]WAFTimeseriesPoint, error) {
	if DB == nil {
		return []WAFTimeseriesPoint{}, nil
	}
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	interval, err := ResolveWAFAnalyticsInterval(q.Window, q.Interval)
	if err != nil {
		return nil, err
	}
	rows, err := DB.Query(`
		SELECT
			toUnixTimestamp(bucket),
			action,
			count(),
			COALESCE(avg(latency_ms), 0),
			COALESCE(quantile(0.95)(latency_ms), 0),
			COALESCE(avg(score), 0)
		FROM (
			SELECT
				`+bucketExpression(interval)+` AS bucket,
				`+normalizedActionSQL()+` AS action,
				latency_ms,
				score
			FROM section_events `+where+`
		)
		GROUP BY bucket, action
		ORDER BY bucket ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byBucket := map[int64]*WAFTimeseriesPoint{}
	for rows.Next() {
		var ts uint32
		var action string
		var count uint64
		var avgLatency, p95Latency, avgScore float64
		if err := rows.Scan(&ts, &action, &count, &avgLatency, &p95Latency, &avgScore); err != nil {
			return nil, err
		}
		key := int64(ts)
		point := byBucket[key]
		if point == nil {
			point = &WAFTimeseriesPoint{Timestamp: key, Counts: map[string]int64{}}
			byBucket[key] = point
		}
		point.Counts[action] = int64(count)
		point.Counts["total"] += int64(count)
		point.AvgLatencyMs = finiteFloat(avgLatency)
		point.P95LatencyMs = finiteFloat(p95Latency)
		point.AvgAnomalyScore = finiteFloat(avgScore)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var step time.Duration
	switch interval {
	case "1m":
		step = time.Minute
	case "5m":
		step = 5 * time.Minute
	case "1h":
		step = time.Hour
	case "1d":
		step = 24 * time.Hour
	default:
		step = time.Hour
	}

	since, errSince := windowStart(defaultWindow(q.Window))
	if errSince == nil {
		if value := strings.TrimSpace(q.Since); value != "" {
			if parsed, parseErr := time.Parse(time.RFC3339, value); parseErr == nil {
				since = parsed.UTC()
			}
		}
		until := time.Now().UTC()
		if value := strings.TrimSpace(q.Until); value != "" {
			if parsed, parseErr := time.Parse(time.RFC3339, value); parseErr == nil {
				until = parsed.UTC()
			}
		}

		startBucket := since.Truncate(step)
		endBucket := until.Truncate(step)
		out := make([]WAFTimeseriesPoint, 0)
		for t := startBucket; !t.After(endBucket); t = t.Add(step) {
			key := t.Unix()
			if pt, ok := byBucket[key]; ok {
				out = append(out, *pt)
				delete(byBucket, key)
			} else {
				out = append(out, WAFTimeseriesPoint{
					Timestamp: key,
					Counts: map[string]int64{
						"total":  0,
						"block":  0,
						"detect": 0,
						"allow":  0,
					},
				})
			}
		}
		if len(byBucket) > 0 {
			for _, pt := range byBucket {
				out = append(out, *pt)
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Timestamp < out[j].Timestamp })
		}
		return out, nil
	}

	keys := make([]int64, 0, len(byBucket))
	for key := range byBucket {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]WAFTimeseriesPoint, 0, len(keys))
	for _, key := range keys {
		out = append(out, *byBucket[key])
	}
	return out, nil
}

func GetWAFAnalyticsBreakdown(q WAFAnalyticsQuery, dimension string) ([]WAFBreakdownItem, error) {
	dimension = strings.ToLower(strings.TrimSpace(dimension))
	if err := ValidateWAFBreakdownDimension(dimension); err != nil {
		return nil, err
	}
	if DB == nil {
		return []WAFBreakdownItem{}, nil
	}
	switch dimension {
	case "categories":
		return getWAFArrayMetadataBreakdown(q, "categories")
	case "severities":
		return getWAFArrayMetadataBreakdown(q, "severities")
	}
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	expr, labelExpr := wafBreakdownExpression(dimension)
	limit := NormalizeWAFLimit(q.Limit, 10, 100)
	args = append(args, limit)
	rows, err := DB.Query(fmt.Sprintf(`
		SELECT
			%s AS key,
			%s AS label,
			count(),
			countIf(%s = 'block'),
			countIf(%s = 'detect'),
			toUnixTimestamp(max(timestamp)),
			COALESCE(avg(score), 0),
			COALESCE(avg(latency_ms), 0)
		FROM section_events %s AND %s != ''
		GROUP BY key, label
		ORDER BY count() DESC
		LIMIT ?`, expr, labelExpr, normalizedActionSQL(), normalizedActionSQL(), where, expr), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]WAFBreakdownItem, 0, limit)
	var total int64
	for rows.Next() {
		var item WAFBreakdownItem
		var count, blocked, detected uint64
		var lastSeen uint32
		if err := rows.Scan(&item.Key, &item.Label, &count, &blocked, &detected, &lastSeen, &item.AvgScore, &item.AvgLatencyMs); err != nil {
			return nil, err
		}
		item.Count = int64(count)
		item.Blocked = int64(blocked)
		item.Detected = int64(detected)
		item.LastSeen = int64(lastSeen)
		if count > 0 {
			item.BlockRate = float64(blocked) / float64(count) * 100
		}
		item.AvgScore = finiteFloat(item.AvgScore)
		item.AvgLatencyMs = finiteFloat(item.AvgLatencyMs)
		total += item.Count
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range items {
		if total > 0 {
			items[i].Percent = float64(items[i].Count) / float64(total) * 100
		}
	}
	return items, nil
}

func GetWAFAnomalyScoreBands(q WAFAnalyticsQuery) ([]WAFBreakdownItem, error) {
	if DB == nil {
		return []WAFBreakdownItem{}, nil
	}
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	rows, err := DB.Query(`
		SELECT band_key, band_label, count(), countIf(action = 'block'), countIf(action = 'detect')
		FROM (
			SELECT
				`+normalizedActionSQL()+` AS action,
				multiIf(score >= 20, 'critical', score >= 10, 'high', score >= 5, 'elevated', 'low') AS band_key,
				multiIf(score >= 20, '20+ Critical', score >= 10, '10-19 High', score >= 5, '5-9 Elevated', '0-4 Low') AS band_label
			FROM section_events `+where+`
		)
		GROUP BY band_key, band_label
		ORDER BY multiIf(band_key = 'critical', 1, band_key = 'high', 2, band_key = 'elevated', 3, 4)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []WAFBreakdownItem{}
	var total int64
	for rows.Next() {
		var item WAFBreakdownItem
		var count, blocked, detected uint64
		if err := rows.Scan(&item.Key, &item.Label, &count, &blocked, &detected); err != nil {
			return nil, err
		}
		item.Count = int64(count)
		item.Blocked = int64(blocked)
		item.Detected = int64(detected)
		if count > 0 {
			item.BlockRate = float64(blocked) / float64(count) * 100
		}
		total += item.Count
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range items {
		if total > 0 {
			items[i].Percent = float64(items[i].Count) / float64(total) * 100
		}
	}
	return items, nil
}

func GetWAFMatchedFieldsBreakdown(q WAFAnalyticsQuery) ([]WAFBreakdownItem, error) {
	if DB == nil {
		return []WAFBreakdownItem{}, nil
	}
	return getWAFArrayMetadataBreakdown(q, "matched_fields")
}

func GetWAFInspectionCoverage(q WAFAnalyticsQuery, health WAFAnalyticsHealth) (WAFInspectionCoverage, error) {
	coverage := WAFInspectionCoverage{
		DroppedEvents:   health.DroppedEvents,
		FreshnessStatus: health.FreshnessStatus,
		Message:         health.Message,
	}
	if DB == nil {
		return coverage, nil
	}
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return coverage, err
	}
	row := DB.QueryRow(`
		SELECT
			count(),
			countIf(lower(JSONExtractString(metadata, 'response_inspected')) IN ('true', '1', 'yes')),
			countIf(lower(JSONExtractString(metadata, 'response_inspection_coverage')) = 'partial'),
			countIf(lower(JSONExtractString(metadata, 'request_truncated')) IN ('true', '1', 'yes')),
			countIf(lower(JSONExtractString(metadata, 'response_truncated')) IN ('true', '1', 'yes'))
		FROM section_events `+where, args...)
	var total, responseInspected, partialResponses, truncatedRequests, truncatedResponses uint64
	if err := row.Scan(&total, &responseInspected, &partialResponses, &truncatedRequests, &truncatedResponses); err != nil {
		return coverage, err
	}
	coverage.RequestInspectedCount = int64(total)
	coverage.ResponseInspectedCount = int64(responseInspected)
	coverage.PartialResponseCount = int64(partialResponses)
	coverage.TruncatedRequestCount = int64(truncatedRequests)
	coverage.TruncatedResponseCount = int64(truncatedResponses)
	if total > 0 {
		coverage.TruncatedRequestRate = float64(truncatedRequests) / float64(total) * 100
		coverage.TruncatedResponseRate = float64(truncatedResponses) / float64(total) * 100
	}
	return coverage, nil
}

func GetWAFAnalyticsEvents(q WAFAnalyticsQuery) (WAFAnalyticsEventsPage, error) {
	page := WAFAnalyticsEventsPage{Events: []WAFAnalyticsEvent{}}
	if DB == nil {
		return page, nil
	}
	limit := NormalizeWAFLimit(q.Limit, 50, 500)
	q.Limit = limit + 1
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return page, err
	}
	if q.Cursor != "" {
		cursor, err := strconv.ParseInt(q.Cursor, 10, 64)
		if err != nil {
			return page, fmt.Errorf("invalid cursor")
		}
		if strings.EqualFold(q.Sort, "asc") {
			where += " AND timestamp > ?"
		} else {
			where += " AND timestamp < ?"
		}
		args = append(args, time.Unix(cursor, 0).UTC())
	}
	order := "DESC"
	if strings.EqualFold(q.Sort, "asc") {
		order = "ASC"
	}
	args = append(args, q.Limit)
	rows, err := DB.Query(`
		SELECT id, toUnixTimestamp(timestamp), client_ip, country, method, path, status_code, `+normalizedActionSQL()+`, user_agent,
		       rule_id, rule_name, score, latency_ms, request_id, user_agent_family, metadata
		FROM section_events `+where+`
		ORDER BY timestamp `+order+`
		LIMIT ?`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()

	for rows.Next() {
		event, err := scanWAFAnalyticsEvent(rows)
		if err != nil {
			return page, err
		}
		page.Events = append(page.Events, event)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(page.Events) > limit {
		page.NextCursor = strconv.FormatInt(page.Events[limit-1].Timestamp, 10)
		page.Events = page.Events[:limit]
	}
	page.Count = len(page.Events)
	return page, nil
}

func GetWAFAnalyticsEvent(id string) (*WAFAnalyticsEvent, error) {
	if DB == nil {
		return nil, nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("missing event id")
	}
	row := DB.QueryRow(`
		SELECT id, toUnixTimestamp(timestamp), client_ip, country, method, path, status_code, `+normalizedActionSQL()+`, user_agent,
		       rule_id, rule_name, score, latency_ms, request_id, user_agent_family, metadata
		FROM section_events
		WHERE section = 'waf_core' AND id = ?
		LIMIT 1`, id)
	event, err := scanWAFAnalyticsEvent(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func GetWAFAnalyticsHealth() WAFAnalyticsHealth {
	health := WAFAnalyticsHealth{
		DBAvailable:     DB != nil,
		DroppedEvents:   WAFDroppedEvents(),
		FreshnessStatus: "unavailable",
		Message:         "",
	}
	if DB == nil {
		return health
	}
	health.Message = "No WAF analytics events have been recorded yet"
	var count uint64
	var last uint32
	err := DB.QueryRow(`
		SELECT count(), toUnixTimestamp(max(timestamp))
		FROM section_events
		WHERE section = 'waf_core'`).Scan(&count, &last)
	if err != nil {
		health.Message = "Unable to read WAF analytics freshness"
		return health
	}
	if count == 0 || last == 0 {
		health.FreshnessStatus = "empty"
		return health
	}
	health.LastEventTimestamp = int64(last)
	health.IngestionLagSeconds = int64(time.Since(time.Unix(int64(last), 0).UTC()).Seconds())
	switch {
	case health.IngestionLagSeconds <= 120:
		health.FreshnessStatus = "fresh"
		health.Message = "WAF analytics are current"
	case health.IngestionLagSeconds <= 900:
		health.FreshnessStatus = "delayed"
		health.Message = "WAF analytics are slightly delayed"
	default:
		health.FreshnessStatus = "stale"
		health.Message = "WAF analytics have not received recent events"
	}
	return health
}

func ValidateWAFBreakdownDimension(dimension string) error {
	switch strings.ToLower(strings.TrimSpace(dimension)) {
	case "rules", "categories", "countries", "ips", "paths", "methods", "actions", "hosts", "status", "severities", "sections", "user_agent_families", "user_agents":
		return nil
	default:
		return fmt.Errorf("unsupported breakdown dimension %q", dimension)
	}
}

func ResolveWAFAnalyticsInterval(window, interval string) (string, error) {
	interval = strings.ToLower(strings.TrimSpace(interval))
	if interval == "" || interval == "auto" {
		normalizedWindow := defaultWindow(window)
		switch normalizedWindow {
		case "15m", "1h":
			return "1m", nil
		case "24h":
			return "1h", nil
		case "7d":
			return "1h", nil
		case "30d":
			return "1d", nil
		default:
			duration, err := time.ParseDuration(normalizedWindow)
			if err != nil {
				return "", fmt.Errorf("invalid window %q", window)
			}
			switch {
			case duration <= time.Hour:
				return "1m", nil
			case duration <= 24*time.Hour:
				return "1h", nil
			case duration <= 7*24*time.Hour:
				return "1h", nil
			default:
				return "1d", nil
			}
		}
	}
	switch interval {
	case "1m", "5m", "1h", "1d":
		return interval, nil
	default:
		return "", fmt.Errorf("invalid interval %q", interval)
	}
}

func NormalizeWAFLimit(limit, fallback, max int) int {
	if limit <= 0 {
		return fallback
	}
	if limit > max {
		return max
	}
	return limit
}

func buildWAFAnalyticsWhere(q WAFAnalyticsQuery) (string, []any, error) {
	since, err := windowStart(defaultWindow(q.Window))
	if err != nil {
		return "", nil, err
	}
	if value := strings.TrimSpace(q.Since); value != "" {
		parsed, parseErr := time.Parse(time.RFC3339, value)
		if parseErr != nil {
			return "", nil, fmt.Errorf("invalid since")
		}
		since = parsed.UTC()
	}
	sections := normalizedWAFAnalyticsSections(q.Sections)
	clauses := []string{"timestamp >= ?"}
	args := []any{since}
	add := func(clause string, value any) {
		clauses = append(clauses, clause)
		args = append(args, value)
	}
	if value := strings.TrimSpace(q.Until); value != "" {
		parsed, parseErr := time.Parse(time.RFC3339, value)
		if parseErr != nil {
			return "", nil, fmt.Errorf("invalid until")
		}
		add("timestamp <= ?", parsed.UTC())
	}
	if len(q.Sections) == 0 && strings.TrimSpace(q.Section) == "" {
		clauses = append(clauses, "section = 'waf_core'")
	} else if section := strings.TrimSpace(q.Section); section != "" {
		if len(q.Sections) > 0 && !containsWAFAnalyticsSection(sections, section) {
			return "", nil, fmt.Errorf("unsupported section %q", section)
		}
		add("section = ?", section)
	} else if len(sections) == 1 {
		add("section = ?", sections[0])
	} else {
		placeholders := make([]string, 0, len(sections))
		for _, section := range sections {
			placeholders = append(placeholders, "?")
			args = append(args, section)
		}
		clauses = append(clauses, "section IN ("+strings.Join(placeholders, ", ")+")")
	}

	if action := strings.TrimSpace(q.Action); action != "" {
		action = normalizeWAFAction(action)
		add(normalizedActionSQL()+" = ?", action)
	}
	if q.Category != "" {
		add("lower(JSONExtractString(metadata, 'categories')) LIKE ?", "%"+strings.ToLower(strings.TrimSpace(q.Category))+"%")
	}
	if q.RuleID != "" {
		ruleID := strings.TrimSpace(q.RuleID)
		clauses = append(clauses, "(rule_id = ? OR JSONExtractString(metadata, 'rule_ids') LIKE ?)")
		args = append(args, ruleID, "%\""+ruleID+"\"%")
	}
	if q.RuleName != "" {
		ruleName := strings.ToLower(strings.TrimSpace(q.RuleName))
		clauses = append(clauses, "(lower(rule_name) LIKE ? OR lower(JSONExtractString(metadata, 'rule_messages')) LIKE ?)")
		args = append(args, "%"+ruleName+"%", "%"+ruleName+"%")
	}
	if q.IP != "" {
		add("client_ip = ?", strings.TrimSpace(q.IP))
	}
	if q.Path != "" {
		add("path LIKE ?", "%"+strings.TrimSpace(q.Path)+"%")
	}
	if q.Method != "" {
		add("method = ?", strings.ToUpper(strings.TrimSpace(q.Method)))
	}
	if q.Host != "" {
		add("JSONExtractString(metadata, 'host') = ?", strings.TrimSpace(q.Host))
	}
	if q.Country != "" {
		add("country = ?", strings.ToUpper(strings.TrimSpace(q.Country)))
	}
	if q.Status != "" {
		status, err := strconv.Atoi(strings.TrimSpace(q.Status))
		if err != nil || status < 100 || status > 599 {
			return "", nil, fmt.Errorf("invalid status")
		}
		add("status_code = ?", status)
	}
	if q.StatusClass != "" {
		switch strings.ToLower(strings.TrimSpace(q.StatusClass)) {
		case "2xx":
			clauses = append(clauses, "status_code >= 200 AND status_code < 300")
		case "3xx":
			clauses = append(clauses, "status_code >= 300 AND status_code < 400")
		case "4xx":
			clauses = append(clauses, "status_code >= 400 AND status_code < 500")
		case "5xx":
			clauses = append(clauses, "status_code >= 500 AND status_code < 600")
		}
	}
	if q.Severity != "" {
		add("lower(JSONExtractString(metadata, 'severities')) LIKE ?", "%"+strings.ToLower(strings.TrimSpace(q.Severity))+"%")
	}
	if q.MatchedField != "" {
		add("lower(JSONExtractString(metadata, 'matched_fields')) LIKE ?", "%"+strings.ToLower(strings.TrimSpace(q.MatchedField))+"%")
	}
	if q.UserAgent != "" {
		add("user_agent LIKE ?", "%"+strings.TrimSpace(q.UserAgent)+"%")
	}
	if q.UserAgentFamily != "" {
		add("user_agent_family = ?", strings.TrimSpace(q.UserAgentFamily))
	}
	if q.RequestID != "" {
		add("request_id = ?", strings.TrimSpace(q.RequestID))
	}
	if q.JA3 != "" {
		add("JSONExtractString(metadata, 'ja3') = ?", strings.TrimSpace(q.JA3))
	}
	if q.JA4 != "" {
		add("JSONExtractString(metadata, 'ja4') = ?", strings.TrimSpace(q.JA4))
	}
	if q.ASN != "" {
		add("JSONExtractString(metadata, 'asn') = ?", strings.ToUpper(strings.TrimSpace(q.ASN)))
	}
	if q.Policy != "" {
		policy := strings.TrimSpace(q.Policy)
		clauses = append(clauses, "(policy_name = ? OR policy_id = ? OR JSONExtractString(metadata, 'policy_name') = ? OR JSONExtractString(metadata, 'policy_id') = ?)")
		args = append(args, policy, policy, policy, policy)
	}
	if q.MinScore != nil {
		add("score >= ?", *q.MinScore)
	}
	if q.MaxScore != nil {
		add("score <= ?", *q.MaxScore)
	}
	return "WHERE " + strings.Join(clauses, " AND "), args, nil
}

func normalizedWAFAnalyticsSections(sections []string) []string {
	if len(sections) == 0 {
		return []string{"waf_core"}
	}
	seen := make(map[string]struct{}, len(sections))
	out := make([]string, 0, len(sections))
	for _, section := range sections {
		section = strings.TrimSpace(section)
		if section == "" {
			continue
		}
		if _, exists := seen[section]; exists {
			continue
		}
		seen[section] = struct{}{}
		out = append(out, section)
	}
	if len(out) == 0 {
		return []string{"waf_core"}
	}
	return out
}

func containsWAFAnalyticsSection(sections []string, target string) bool {
	for _, section := range sections {
		if section == target {
			return true
		}
	}
	return false
}

func defaultWindow(window string) string {
	window = strings.ToLower(strings.TrimSpace(window))
	if window == "" {
		return "24h"
	}
	return window
}

func normalizedActionSQL() string {
	return "CASE WHEN action = 'pass' THEN 'allow' WHEN action = 'log' THEN 'detect' ELSE action END"
}

func bucketExpression(interval string) string {
	switch interval {
	case "1m":
		return "toStartOfMinute(timestamp)"
	case "5m":
		return "toStartOfInterval(timestamp, INTERVAL 5 minute)"
	case "1h":
		return "toStartOfHour(timestamp)"
	case "1d":
		return "toStartOfDay(timestamp)"
	default:
		return "toStartOfHour(timestamp)"
	}
}

func wafBreakdownExpression(dimension string) (string, string) {
	switch dimension {
	case "rules":
		return "rule_id", "rule_name"
	case "countries":
		return "country", "country"
	case "ips":
		return "client_ip", "client_ip"
	case "paths":
		return "path", "path"
	case "methods":
		return "method", "method"
	case "actions":
		expr := normalizedActionSQL()
		return expr, expr
	case "sections":
		return "section", "section"
	case "hosts":
		expr := "JSONExtractString(metadata, 'host')"
		return expr, expr
	case "status":
		expr := "toString(status_code)"
		return expr, expr
	case "user_agent_families", "user_agents":
		return "user_agent", "user_agent"
	default:
		return "path", "path"
	}
}

func getWAFArrayMetadataBreakdown(q WAFAnalyticsQuery, metadataKey string) ([]WAFBreakdownItem, error) {
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	rows, err := DB.Query(`
		SELECT `+normalizedActionSQL()+`, toUnixTimestamp(timestamp), score, latency_ms, JSONExtractString(metadata, '`+metadataKey+`')
		FROM section_events `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := map[string]*WAFBreakdownItem{}
	var total int64
	for rows.Next() {
		var action, rawValues string
		var ts uint32
		var score int32
		var latency int64
		if err := rows.Scan(&action, &ts, &score, &latency, &rawValues); err != nil {
			return nil, err
		}
		for _, value := range parseStringJSONArray(rawValues) {
			key := strings.ToLower(strings.TrimSpace(value))
			if key == "" {
				continue
			}
			item := items[key]
			if item == nil {
				item = &WAFBreakdownItem{Key: key, Label: formatWAFBreakdownLabel(metadataKey, key)}
				items[key] = item
			}
			item.Count++
			if action == "block" {
				item.Blocked++
			}
			if action == "detect" {
				item.Detected++
			}
			if int64(ts) > item.LastSeen {
				item.LastSeen = int64(ts)
			}
			item.AvgScore += float64(score)
			item.AvgLatencyMs += float64(latency)
			total++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]WAFBreakdownItem, 0, len(items))
	for _, item := range items {
		if item.Count > 0 {
			item.BlockRate = float64(item.Blocked) / float64(item.Count) * 100
			item.AvgScore = item.AvgScore / float64(item.Count)
			item.AvgLatencyMs = item.AvgLatencyMs / float64(item.Count)
		}
		item.AvgScore = finiteFloat(item.AvgScore)
		item.AvgLatencyMs = finiteFloat(item.AvgLatencyMs)
		if total > 0 {
			item.Percent = float64(item.Count) / float64(total) * 100
		}
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	limit := NormalizeWAFLimit(q.Limit, 10, 100)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func topBreakdownKey(items []WAFBreakdownItem) string {
	if len(items) == 0 {
		return ""
	}
	if items[0].Label != "" {
		return items[0].Label
	}
	return items[0].Key
}

func scanWAFAnalyticsEvent(row sqlScanner) (WAFAnalyticsEvent, error) {
	var event WAFAnalyticsEvent
	var ts uint32
	var status uint16
	var score int32
	var metadata string
	if err := row.Scan(&event.ID, &ts, &event.ClientIP, &event.Country, &event.Method, &event.Path, &status, &event.Action, &event.UserAgent, &event.RuleID, &event.RuleName, &score, &event.LatencyMs, &event.RequestID, &event.UserAgentFamily, &metadata); err != nil {
		return event, err
	}
	event.Timestamp = int64(ts)
	event.StatusCode = int(status)
	event.AnomalyScore = int(score)
	applyWAFEventMetadata(&event, metadata)
	return event, nil
}

func applyWAFEventMetadata(event *WAFAnalyticsEvent, raw string) {
	var meta map[string]string
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return
	}
	event.Metadata = meta
	event.Host = meta["host"]
	event.QueryString = meta["query_string"]
	event.City = meta["city"]
	event.RuleIDs = parseStringJSONArray(meta["rule_ids"])
	event.RuleMessages = parseStringJSONArray(meta["rule_messages"])
	event.Categories = parseStringJSONArray(meta["categories"])
	event.Severities = parseStringJSONArray(meta["severities"])
	event.MatchedFields = parseStringJSONArray(meta["matched_fields"])
	event.RuleCount = len(event.RuleIDs)
	event.RequestSize = parseInt64(meta["request_size"])
	event.ResponseSize = parseInt64(meta["response_size"])
	event.RuleSource = meta["rule_source"]
	event.PolicyID = meta["policy_id"]
	event.PolicyName = meta["policy_name"]
	event.ClientIPSource = meta["client_ip_source"]
	event.RequestTruncated = parseBool(meta["request_truncated"])
	event.ResponseInspected = parseBool(meta["response_inspected"])
	event.ResponseInspectionCoverage = meta["response_inspection_coverage"]
	event.ResponseTruncated = parseBool(meta["response_truncated"])
	event.ExclusionIDs = parseStringJSONArray(meta["exclusion_ids"])
	event.ReloadID = meta["reload_id"]
}

func buildWAFProtectionSummary(summary WAFAnalyticsSummary, breakdowns map[string][]WAFBreakdownItem) WAFProtectionSummary {
	var ruleMatches int64
	for _, item := range breakdowns["rules"] {
		ruleMatches += item.Count
	}
	var criticalHigh int64
	for _, item := range breakdowns["severities"] {
		key := strings.ToLower(item.Key)
		if key == "critical" || key == "high" {
			criticalHigh += item.Count
		}
	}
	return WAFProtectionSummary{
		BlockedAttacks:    summary.BlockedRequests,
		DetectedOnly:      summary.DetectedRequests,
		RuleMatches:       ruleMatches,
		CriticalHigh:      criticalHigh,
		AvgAnomalyScore:   summary.AvgAnomalyScore,
		MaxAnomalyScore:   summary.MaxAnomalyScore,
		EnforcedBlockRate: summary.BlockRate,
		TopAttackCategory: summary.TopAttackCategory,
		Window:            summary.Window,
	}
}

func topWAFRulesByMode(items []WAFBreakdownItem, mode string, limit int) []WAFBreakdownItem {
	out := []WAFBreakdownItem{}
	for _, item := range items {
		switch mode {
		case "block":
			if item.Blocked > 0 {
				out = append(out, item)
			}
		case "detect":
			if item.Detected > 0 && item.Blocked == 0 {
				out = append(out, item)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if mode == "block" {
			return out[i].Blocked > out[j].Blocked
		}
		return out[i].Detected > out[j].Detected
	})
	return trimWAFBreakdownItems(out, limit)
}

func noisyWAFRules(items []WAFBreakdownItem, limit int) []WAFBreakdownItem {
	out := []WAFBreakdownItem{}
	for _, item := range items {
		if item.Count >= 3 && item.BlockRate < 10 {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AvgScore == out[j].AvgScore {
			return out[i].Count > out[j].Count
		}
		return out[i].AvgScore < out[j].AvgScore
	})
	return trimWAFBreakdownItems(out, limit)
}

func trimWAFBreakdownItems(items []WAFBreakdownItem, limit int) []WAFBreakdownItem {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func buildWAFPolicyHealth(events []WAFAnalyticsEvent) WAFPolicyHealth {
	health := WAFPolicyHealth{
		Status:  "unavailable",
		Message: "Policy telemetry has not been observed in the selected WAF events",
	}
	for _, event := range events {
		if event.PolicyID != "" && health.PolicyID == "" {
			health.PolicyID = event.PolicyID
		}
		if event.PolicyName != "" && health.PolicyName == "" {
			health.PolicyName = event.PolicyName
		}
		if event.RuleSource != "" && health.RuleSource == "" {
			health.RuleSource = event.RuleSource
		}
		if event.ReloadID != "" && health.ReloadID == "" {
			health.ReloadID = event.ReloadID
		}
		health.ExclusionCount += int64(len(event.ExclusionIDs))
	}
	if health.PolicyID != "" || health.PolicyName != "" || health.RuleSource != "" || health.ReloadID != "" {
		health.Status = "observed"
		health.Message = "Policy telemetry was observed in recent WAF detections"
	}
	return health
}

func buildWAFTuningRecommendations(effectiveness WAFRuleEffectiveness) []WAFTuningRecommendation {
	recommendations := []WAFTuningRecommendation{}
	for _, rule := range effectiveness.NoisyRules {
		recommendations = append(recommendations, WAFTuningRecommendation{
			Kind:     "noise",
			Title:    "Review noisy detect-only rule",
			Detail:   fmt.Sprintf("%s produced %d low-enforcement matches with %.1f average score.", firstNonEmpty(rule.Label, rule.Key, "Rule"), rule.Count, rule.AvgScore),
			RuleID:   rule.Key,
			RuleName: rule.Label,
			Count:    rule.Count,
		})
	}
	for _, field := range trimWAFBreakdownItems(effectiveness.MatchedFields, 3) {
		recommendations = append(recommendations, WAFTuningRecommendation{
			Kind:         "matched_field",
			Title:        "Inspect repeated matched field",
			Detail:       fmt.Sprintf("%s appeared in %d WAF matches.", firstNonEmpty(field.Label, field.Key, "Matched field"), field.Count),
			Count:        field.Count,
			MatchedField: field.Key,
		})
	}
	if len(recommendations) > 6 {
		return recommendations[:6]
	}
	return recommendations
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func finiteFloat(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return value
}

func parseInt64(value string) int64 {
	parsed, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return parsed
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}

func formatWAFCategoryLabel(category string) string {
	switch category {
	case "sqli":
		return "SQL Injection"
	case "xss":
		return "Cross-Site Scripting"
	case "rce":
		return "Remote Code Execution"
	case "lfi":
		return "Local File Inclusion"
	case "rfi":
		return "Remote File Inclusion"
	case "protocol":
		return "Protocol Violation"
	case "scanner":
		return "Scanner Detection"
	case "path_traversal":
		return "Path Traversal"
	default:
		return strings.Title(strings.ReplaceAll(category, "_", " "))
	}
}

func formatWAFBreakdownLabel(metadataKey, value string) string {
	if metadataKey == "categories" {
		return formatWAFCategoryLabel(value)
	}
	switch value {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "info", "informational":
		return "Informational"
	default:
		return strings.Title(strings.ReplaceAll(value, "_", " "))
	}
}
