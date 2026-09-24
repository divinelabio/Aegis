package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type TrafficAnalyticsQuery struct {
	Window    string
	Interval  string
	Action    string
	Reason    string
	RuleType  string
	RuleID    string
	IP        string
	Path      string
	Method    string
	Country   string
	Status    string
	UserAgent string
	RequestID string
	Limit     int
	Cursor    string
	Sort      string
}

type TrafficAnalyticsSummary struct {
	TotalRequests      int64   `json:"total_requests"`
	BlockedRequests    int64   `json:"blocked_requests"`
	AllowedRequests    int64   `json:"allowed_requests"`
	ChallengedRequests int64   `json:"challenged_requests"`
	RateLimited        int64   `json:"rate_limited"`
	ErrorRequests      int64   `json:"error_requests"`
	BlockRate          float64 `json:"block_rate"`
	AvgLatencyMs       float64 `json:"avg_latency_ms"`
	P95LatencyMs       float64 `json:"p95_latency_ms"`
	UniqueSourceIPs    int64   `json:"unique_source_ips"`
	UniqueCountries    int64   `json:"unique_countries"`
	TopReason          string  `json:"top_reason"`
	ActiveBans         int64   `json:"active_bans"`
	ActiveConnections  int64   `json:"active_connections"`
	DroppedEvents      int64   `json:"dropped_events"`
	Window             string  `json:"window"`
}

type TrafficTimeseriesPoint struct {
	Timestamp    int64            `json:"timestamp"`
	Counts       map[string]int64 `json:"counts"`
	AvgLatencyMs float64          `json:"avg_latency_ms"`
	P95LatencyMs float64          `json:"p95_latency_ms"`
}

type TrafficBreakdownItem struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	Count        int64   `json:"count"`
	Blocked      int64   `json:"blocked"`
	Challenged   int64   `json:"challenged"`
	RateLimited  int64   `json:"rate_limited"`
	BlockRate    float64 `json:"block_rate"`
	Percent      float64 `json:"percent"`
	LastSeen     int64   `json:"last_seen"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

type TrafficAnalyticsEvent struct {
	ID              string            `json:"id"`
	Timestamp       int64             `json:"timestamp"`
	ClientIP        string            `json:"client_ip"`
	Country         string            `json:"country"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	StatusCode      int               `json:"status_code"`
	Action          string            `json:"action"`
	UserAgent       string            `json:"user_agent"`
	UserAgentFamily string            `json:"user_agent_family"`
	RuleID          string            `json:"rule_id"`
	RuleName        string            `json:"rule_name"`
	RuleType        string            `json:"rule_type"`
	LatencyMs       int64             `json:"latency_ms"`
	RequestID       string            `json:"request_id"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type TrafficAnalyticsEventsPage struct {
	Events     []TrafficAnalyticsEvent `json:"events"`
	NextCursor string                  `json:"next_cursor,omitempty"`
	Count      int                     `json:"count"`
}

type TrafficAnalyticsHealth struct {
	DBAvailable         bool   `json:"db_available"`
	LastEventTimestamp  int64  `json:"last_event_timestamp"`
	IngestionLagSeconds int64  `json:"ingestion_lag_seconds"`
	DroppedEvents       int64  `json:"dropped_events"`
	FreshnessStatus     string `json:"freshness_status"`
	Message             string `json:"message"`
}

type TrafficEnforcementSummary struct {
	RequestsEnforced  int64   `json:"requests_enforced"`
	BlockedRequests   int64   `json:"blocked_requests"`
	RateLimited       int64   `json:"rate_limited"`
	Challenged        int64   `json:"challenged"`
	Allowed           int64   `json:"allowed"`
	EnforcementRate   float64 `json:"enforcement_rate"`
	ActiveBans        int64   `json:"active_bans"`
	ActiveConnections int64   `json:"active_connections"`
	Window            string  `json:"window"`
}

type TrafficModuleEffectiveness struct {
	Modules               []TrafficBreakdownItem `json:"modules"`
	TopRules              []TrafficBreakdownItem `json:"top_rules"`
	ApplicationFloodCount int64                  `json:"application_flood_count"`
	DDoSCount             int64                  `json:"ddos_count"` // Compatibility alias.
	RateLimitCount        int64                  `json:"rate_limit_count"`
	GeoCount              int64                  `json:"geo_count"`
	BlacklistCount        int64                  `json:"blacklist_count"`
	ReputationCount       int64                  `json:"reputation_count"`
	TrustedExceptionCount int64                  `json:"trusted_exception_count"`
	ChallengeCount        int64                  `json:"challenge_count"`
}

type TrafficPressureIntelligence struct {
	DDoSReasons          []TrafficBreakdownItem `json:"ddos_reasons"`
	RateLimitTriggers    []TrafficBreakdownItem `json:"rate_limit_triggers"`
	ReputationScoreBands []TrafficBreakdownItem `json:"reputation_score_bands"`
	ChallengeStrategies  []TrafficBreakdownItem `json:"challenge_strategies"`
	RepeatOffenders      []TrafficBreakdownItem `json:"repeat_offenders"`
}

type TrafficPolicyHealth struct {
	Status             string          `json:"status"`
	EnabledState       string          `json:"enabled_state"`
	ProtectionLevel    int             `json:"protection_level"`
	EnabledModules     map[string]bool `json:"enabled_modules"`
	GeoMode            string          `json:"geo_mode"`
	BlacklistEntries   int             `json:"blacklist_entries"`
	RateLimitAction    string          `json:"rate_limit_action"`
	ChallengeState     string          `json:"challenge_state"`
	TelemetryFreshness string          `json:"telemetry_freshness"`
	DroppedEvents      int64           `json:"dropped_events"`
	ConfigMessage      string          `json:"config_message"`
}

type TrafficActiveControls struct {
	ActiveBans             int64  `json:"active_bans"`
	ActiveConnections      int64  `json:"active_connections"`
	ActiveBlocklistEntries int    `json:"active_blocklist_entries"`
	GeoScope               string `json:"geo_scope"`
	PriorityBypassSummary  string `json:"priority_bypass_summary"`
}

type TrafficAnalyticsDashboard struct {
	Summary              TrafficAnalyticsSummary           `json:"summary"`
	Timeseries           []TrafficTimeseriesPoint          `json:"timeseries"`
	Breakdowns           map[string][]TrafficBreakdownItem `json:"breakdowns"`
	Events               TrafficAnalyticsEventsPage        `json:"events"`
	Health               TrafficAnalyticsHealth            `json:"health"`
	EnforcementSummary   TrafficEnforcementSummary         `json:"enforcement_summary"`
	ModuleEffectiveness  TrafficModuleEffectiveness        `json:"module_effectiveness"`
	PressureIntelligence TrafficPressureIntelligence       `json:"pressure_intelligence"`
	PolicyHealth         TrafficPolicyHealth               `json:"policy_health"`
	ActiveControls       TrafficActiveControls             `json:"active_controls"`
	Warnings             []string                          `json:"warnings"`
}

func GetTrafficAnalyticsDashboard(q TrafficAnalyticsQuery) (TrafficAnalyticsDashboard, error) {
	dashboard := TrafficAnalyticsDashboard{
		Timeseries: []TrafficTimeseriesPoint{},
		Breakdowns: map[string][]TrafficBreakdownItem{},
		Events:     TrafficAnalyticsEventsPage{Events: []TrafficAnalyticsEvent{}},
		Warnings:   []string{},
	}
	if _, _, err := buildTrafficAnalyticsWhere(q); err != nil {
		return dashboard, err
	}
	if _, err := ResolveWAFAnalyticsInterval(q.Window, q.Interval); err != nil {
		return dashboard, err
	}

	if summary, err := GetTrafficAnalyticsSummary(q); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "summary unavailable")
	} else {
		dashboard.Summary = summary
	}
	if points, err := GetTrafficAnalyticsTimeseries(q); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "timeseries unavailable")
	} else {
		dashboard.Timeseries = points
	}

	breakdownQuery := q
	breakdownQuery.Limit = NormalizeWAFLimit(q.Limit, 10, 100)
	for _, dimension := range []string{
		"actions", "reasons", "ips", "paths",
		"blacklist_reasons", "application_flood_reasons", "application_flood_objects",
		"ratelimit_triggers", "ratelimit_rules", "geo_countries", "geo_reasons",
		"reputation_scores", "reputation_reasons", "challenge_strategies",
		"trusted_exception_controls", "trusted_exception_ids",
	} {
		items, err := GetTrafficAnalyticsBreakdown(breakdownQuery, dimension)
		if err != nil {
			dashboard.Warnings = append(dashboard.Warnings, dimension+" breakdown unavailable")
			dashboard.Breakdowns[dimension] = []TrafficBreakdownItem{}
			continue
		}
		dashboard.Breakdowns[dimension] = items
	}

	eventQuery := q
	eventQuery.Limit = NormalizeWAFLimit(q.Limit, 50, 500)
	if events, err := GetTrafficAnalyticsEvents(eventQuery); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "events unavailable")
	} else {
		dashboard.Events = events
	}
	if dashboard.Summary.TopReason == "" {
		dashboard.Summary.TopReason = topTrafficBreakdownKey(dashboard.Breakdowns["reasons"])
	}
	dashboard.Health = GetTrafficAnalyticsHealth()
	PopulateTrafficAnalyticsDashboardGroups(&dashboard)
	return dashboard, nil
}

func PopulateTrafficAnalyticsDashboardGroups(dashboard *TrafficAnalyticsDashboard) {
	if dashboard == nil {
		return
	}
	breakdowns := dashboard.Breakdowns
	if breakdowns == nil {
		breakdowns = map[string][]TrafficBreakdownItem{}
		dashboard.Breakdowns = breakdowns
	}
	enforced := dashboard.Summary.BlockedRequests + dashboard.Summary.RateLimited
	if dashboard.Summary.TotalRequests > 0 {
		dashboard.Summary.BlockRate = finiteFloat(float64(enforced) / float64(dashboard.Summary.TotalRequests) * 100)
	}
	dashboard.EnforcementSummary = TrafficEnforcementSummary{
		RequestsEnforced:  enforced,
		BlockedRequests:   dashboard.Summary.BlockedRequests,
		RateLimited:       dashboard.Summary.RateLimited,
		Challenged:        dashboard.Summary.ChallengedRequests,
		Allowed:           dashboard.Summary.AllowedRequests,
		EnforcementRate:   dashboard.Summary.BlockRate,
		ActiveBans:        dashboard.Summary.ActiveBans,
		ActiveConnections: dashboard.Summary.ActiveConnections,
		Window:            dashboard.Summary.Window,
	}
	applicationFloodCount := countTrafficBreakdownKeys(breakdowns["reasons"], "ddos", "application_flood")
	dashboard.ModuleEffectiveness = TrafficModuleEffectiveness{
		Modules:               safeTrafficBreakdown(breakdowns, "reasons"),
		TopRules:              safeTrafficBreakdown(breakdowns, "rules"),
		ApplicationFloodCount: applicationFloodCount,
		DDoSCount:             applicationFloodCount,
		RateLimitCount:        countTrafficBreakdownKey(breakdowns["reasons"], "ratelimit"),
		GeoCount:              countTrafficBreakdownKey(breakdowns["reasons"], "geo"),
		BlacklistCount:        countTrafficBreakdownKey(breakdowns["reasons"], "blacklist"),
		ReputationCount:       countTrafficBreakdownKey(breakdowns["reasons"], "reputation"),
		TrustedExceptionCount: countTrafficBreakdownKey(breakdowns["reasons"], "trusted_exception"),
		ChallengeCount:        dashboard.Summary.ChallengedRequests,
	}
	dashboard.PressureIntelligence = TrafficPressureIntelligence{
		DDoSReasons:          safeTrafficBreakdown(breakdowns, "ddos_reasons"),
		RateLimitTriggers:    safeTrafficBreakdown(breakdowns, "ratelimit_triggers"),
		ReputationScoreBands: safeTrafficBreakdown(breakdowns, "reputation_scores"),
		ChallengeStrategies:  safeTrafficBreakdown(breakdowns, "challenge_strategies"),
		RepeatOffenders:      safeTrafficBreakdown(breakdowns, "ips"),
	}
	dashboard.PolicyHealth.Status = trafficPolicyStatus(dashboard.Health)
	dashboard.PolicyHealth.TelemetryFreshness = dashboard.Health.FreshnessStatus
	dashboard.PolicyHealth.DroppedEvents = dashboard.Health.DroppedEvents
	if dashboard.PolicyHealth.ConfigMessage == "" {
		dashboard.PolicyHealth.ConfigMessage = dashboard.Health.Message
	}
	dashboard.ActiveControls.ActiveBans = dashboard.Summary.ActiveBans
	dashboard.ActiveControls.ActiveConnections = dashboard.Summary.ActiveConnections
	if dashboard.ActiveControls.GeoScope == "" {
		dashboard.ActiveControls.GeoScope = "unavailable"
	}
	if dashboard.ActiveControls.PriorityBypassSummary == "" {
		dashboard.ActiveControls.PriorityBypassSummary = "Priority bypass telemetry unavailable"
	}
}

func safeTrafficBreakdown(breakdowns map[string][]TrafficBreakdownItem, key string) []TrafficBreakdownItem {
	if breakdowns == nil || breakdowns[key] == nil {
		return []TrafficBreakdownItem{}
	}
	return breakdowns[key]
}

func countTrafficBreakdownKey(items []TrafficBreakdownItem, key string) int64 {
	var total int64
	for _, item := range items {
		if strings.EqualFold(item.Key, key) || strings.EqualFold(item.Label, key) {
			total += item.Count
		}
	}
	return total
}

func countTrafficBreakdownKeys(items []TrafficBreakdownItem, keys ...string) int64 {
	var total int64
	for _, key := range keys {
		total += countTrafficBreakdownKey(items, key)
	}
	return total
}

func trafficPolicyStatus(health TrafficAnalyticsHealth) string {
	if !health.DBAvailable {
		return "unavailable"
	}
	if health.FreshnessStatus == "fresh" {
		return "healthy"
	}
	return health.FreshnessStatus
}

func GetTrafficAnalyticsSummary(q TrafficAnalyticsQuery) (TrafficAnalyticsSummary, error) {
	summary := TrafficAnalyticsSummary{
		Window:        defaultWindow(q.Window),
		DroppedEvents: DroppedEvents(),
	}
	if DB == nil {
		return summary, nil
	}
	where, args, err := buildTrafficAnalyticsWhere(q)
	if err != nil {
		return summary, err
	}
	row := DB.QueryRow(`
		SELECT
			count(),
			countIf(`+normalizedTrafficActionSQL()+` = 'block'),
			countIf(`+normalizedTrafficActionSQL()+` = 'allow'),
			countIf(`+normalizedTrafficActionSQL()+` = 'challenge'),
			countIf(`+normalizedTrafficActionSQL()+` = 'ratelimit'),
			countIf(`+normalizedTrafficActionSQL()+` = 'error'),
			COALESCE(avg(latency_ms), 0),
			COALESCE(quantile(0.95)(latency_ms), 0),
			uniqExact(client_ip),
			uniqExactIf(country, country != '')
		FROM section_events `+where, args...)

	var total, blocked, allowed, challenged, rateLimited, errors, uniqueIPs, uniqueCountries uint64
	if err := row.Scan(&total, &blocked, &allowed, &challenged, &rateLimited, &errors, &summary.AvgLatencyMs, &summary.P95LatencyMs, &uniqueIPs, &uniqueCountries); err != nil {
		return summary, err
	}
	summary.TotalRequests = int64(total)
	summary.BlockedRequests = int64(blocked)
	summary.AllowedRequests = int64(allowed)
	summary.ChallengedRequests = int64(challenged)
	summary.RateLimited = int64(rateLimited)
	summary.ErrorRequests = int64(errors)
	summary.UniqueSourceIPs = int64(uniqueIPs)
	summary.UniqueCountries = int64(uniqueCountries)
	if total > 0 {
		summary.BlockRate = float64(blocked+rateLimited) / float64(total) * 100
	}
	summary.AvgLatencyMs = finiteFloat(summary.AvgLatencyMs)
	summary.P95LatencyMs = finiteFloat(summary.P95LatencyMs)
	return summary, nil
}

func GetTrafficAnalyticsTimeseries(q TrafficAnalyticsQuery) ([]TrafficTimeseriesPoint, error) {
	if DB == nil {
		return []TrafficTimeseriesPoint{}, nil
	}
	where, args, err := buildTrafficAnalyticsWhere(q)
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
			COALESCE(quantile(0.95)(latency_ms), 0)
		FROM (
			SELECT
				`+bucketExpression(interval)+` AS bucket,
				`+normalizedTrafficActionSQL()+` AS action,
				latency_ms
			FROM section_events `+where+`
		)
		GROUP BY bucket, action
		ORDER BY bucket ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byBucket := map[int64]*TrafficTimeseriesPoint{}
	for rows.Next() {
		var ts uint32
		var action string
		var count uint64
		var avgLatency, p95Latency float64
		if err := rows.Scan(&ts, &action, &count, &avgLatency, &p95Latency); err != nil {
			return nil, err
		}
		key := int64(ts)
		point := byBucket[key]
		if point == nil {
			point = &TrafficTimeseriesPoint{Timestamp: key, Counts: map[string]int64{}}
			byBucket[key] = point
		}
		point.Counts[action] = int64(count)
		point.AvgLatencyMs = finiteFloat(avgLatency)
		point.P95LatencyMs = finiteFloat(p95Latency)
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
		until := time.Now().UTC()

		startBucket := since.Truncate(step)
		endBucket := until.Truncate(step)
		out := make([]TrafficTimeseriesPoint, 0)
		for t := startBucket; !t.After(endBucket); t = t.Add(step) {
			key := t.Unix()
			if pt, ok := byBucket[key]; ok {
				out = append(out, *pt)
				delete(byBucket, key)
			} else {
				out = append(out, TrafficTimeseriesPoint{
					Timestamp: key,
					Counts: map[string]int64{
						"total": 0,
						"allow": 0,
						"block": 0,
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
	out := make([]TrafficTimeseriesPoint, 0, len(keys))
	for _, key := range keys {
		out = append(out, *byBucket[key])
	}
	return out, nil
}

func GetTrafficAnalyticsBreakdown(q TrafficAnalyticsQuery, dimension string) ([]TrafficBreakdownItem, error) {
	dimension = strings.ToLower(strings.TrimSpace(dimension))
	if err := ValidateTrafficBreakdownDimension(dimension); err != nil {
		return nil, err
	}
	if DB == nil {
		return []TrafficBreakdownItem{}, nil
	}
	where, args, err := buildTrafficAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	expr, labelExpr := trafficBreakdownExpression(dimension)
	limit := NormalizeWAFLimit(q.Limit, 10, 100)
	args = append(args, limit)
	rows, err := DB.Query(fmt.Sprintf(`
		SELECT
			%s AS key,
			%s AS label,
			count(),
			countIf(%s = 'block'),
			countIf(%s = 'challenge'),
			countIf(%s = 'ratelimit'),
			toUnixTimestamp(max(timestamp)),
			COALESCE(avg(latency_ms), 0)
		FROM section_events %s AND %s != ''
		GROUP BY key, label
		ORDER BY count() DESC
		LIMIT ?`, expr, labelExpr, normalizedTrafficActionSQL(), normalizedTrafficActionSQL(), normalizedTrafficActionSQL(), where, expr), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]TrafficBreakdownItem, 0, limit)
	var total int64
	for rows.Next() {
		var item TrafficBreakdownItem
		var count, blocked, challenged, rateLimited uint64
		var lastSeen uint32
		if err := rows.Scan(&item.Key, &item.Label, &count, &blocked, &challenged, &rateLimited, &lastSeen, &item.AvgLatencyMs); err != nil {
			return nil, err
		}
		item.Count = int64(count)
		item.Blocked = int64(blocked)
		item.Challenged = int64(challenged)
		item.RateLimited = int64(rateLimited)
		item.LastSeen = int64(lastSeen)
		if count > 0 {
			item.BlockRate = float64(blocked+rateLimited) / float64(count) * 100
		}
		item.AvgLatencyMs = finiteFloat(item.AvgLatencyMs)
		item.Label = formatTrafficBreakdownLabel(dimension, item.Label)
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

func GetTrafficAnalyticsEvents(q TrafficAnalyticsQuery) (TrafficAnalyticsEventsPage, error) {
	page := TrafficAnalyticsEventsPage{Events: []TrafficAnalyticsEvent{}}
	if DB == nil {
		return page, nil
	}
	limit := NormalizeWAFLimit(q.Limit, 50, 500)
	q.Limit = limit + 1
	where, args, err := buildTrafficAnalyticsWhere(q)
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
		SELECT id, toUnixTimestamp(timestamp), client_ip, country, method, path, status_code, `+normalizedTrafficActionSQL()+`, user_agent,
		       user_agent_family, rule_id, rule_name, rule_type, latency_ms, request_id, metadata
		FROM section_events `+where+`
		ORDER BY timestamp `+order+`
		LIMIT ?`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()

	for rows.Next() {
		event, err := scanTrafficAnalyticsEvent(rows)
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

func GetTrafficAnalyticsEvent(id string) (*TrafficAnalyticsEvent, error) {
	if DB == nil {
		return nil, nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("missing event id")
	}
	row := DB.QueryRow(`
		SELECT id, toUnixTimestamp(timestamp), client_ip, country, method, path, status_code, `+normalizedTrafficActionSQL()+`, user_agent,
		       user_agent_family, rule_id, rule_name, rule_type, latency_ms, request_id, metadata
		FROM section_events
		WHERE section = 'traffic_control' AND id = ?
		LIMIT 1`, id)
	event, err := scanTrafficAnalyticsEvent(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func GetTrafficAnalyticsHealth() TrafficAnalyticsHealth {
	health := TrafficAnalyticsHealth{
		DBAvailable:     DB != nil,
		DroppedEvents:   DroppedEvents(),
		FreshnessStatus: "unavailable",
		Message:         "",
	}
	if DB == nil {
		return health
	}
	health.Message = "No Traffic Control analytics events have been recorded yet"
	var count uint64
	var last uint32
	err := DB.QueryRow(`
		SELECT count(), toUnixTimestamp(max(timestamp))
		FROM section_events
		WHERE section = 'traffic_control'`).Scan(&count, &last)
	if err != nil {
		health.Message = "Unable to read Traffic Control analytics freshness"
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
		health.Message = "Traffic Control analytics are current"
	case health.IngestionLagSeconds <= 900:
		health.FreshnessStatus = "delayed"
		health.Message = "Traffic Control analytics are slightly delayed"
	default:
		health.FreshnessStatus = "stale"
		health.Message = "Traffic Control analytics have not received recent events"
	}
	return health
}

func ValidateTrafficBreakdownDimension(dimension string) error {
	switch strings.ToLower(strings.TrimSpace(dimension)) {
	case "actions", "reasons", "rules", "countries", "ips", "paths", "methods", "status", "user_agent_families", "user_agents", "ddos_reasons", "application_flood_reasons", "application_flood_objects", "blacklist_reasons", "ratelimit_triggers", "ratelimit_rules", "geo_countries", "geo_reasons", "reputation_scores", "reputation_reasons", "challenge_strategies", "trusted_exception_controls", "trusted_exception_ids":
		return nil
	default:
		return fmt.Errorf("unsupported breakdown dimension %q", dimension)
	}
}

func buildTrafficAnalyticsWhere(q TrafficAnalyticsQuery) (string, []any, error) {
	since, err := windowStart(defaultWindow(q.Window))
	if err != nil {
		return "", nil, err
	}
	clauses := []string{"section = 'traffic_control'", "timestamp >= ?"}
	args := []any{since}
	add := func(clause string, value any) {
		clauses = append(clauses, clause)
		args = append(args, value)
	}
	if action := strings.TrimSpace(q.Action); action != "" {
		add(normalizedTrafficActionSQL()+" = ?", normalizeTrafficAction(action))
	}
	if reason := strings.TrimSpace(q.Reason); reason != "" {
		if strings.EqualFold(reason, "application_flood") || strings.EqualFold(reason, "ddos") {
			clauses = append(clauses, "rule_type IN ('ddos', 'application_flood')")
		} else {
			clauses = append(clauses, "(rule_type = ? OR rule_id = ? OR lower(JSONExtractString(metadata, 'reason')) LIKE ?)")
			args = append(args, reason, reason, "%"+strings.ToLower(reason)+"%")
		}
	}
	if q.RuleType != "" {
		add("rule_type = ?", strings.TrimSpace(q.RuleType))
	}
	if q.RuleID != "" {
		add("rule_id = ?", strings.TrimSpace(q.RuleID))
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
	if q.UserAgent != "" {
		add("user_agent LIKE ?", "%"+strings.TrimSpace(q.UserAgent)+"%")
	}
	if q.RequestID != "" {
		add("request_id = ?", strings.TrimSpace(q.RequestID))
	}
	return "WHERE " + strings.Join(clauses, " AND "), args, nil
}

func normalizedTrafficActionSQL() string {
	return "if(action = 'pass', 'allow', if(action = 'rate_limit', 'ratelimit', action))"
}

func normalizeTrafficAction(action string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "pass":
		return "allow"
	case "rate_limit", "rate-limited", "rate_limited":
		return "ratelimit"
	default:
		return action
	}
}

func trafficBreakdownExpression(dimension string) (string, string) {
	switch dimension {
	case "actions":
		expr := normalizedTrafficActionSQL()
		return expr, expr
	case "reasons":
		return "rule_type", "rule_type"
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
	case "status":
		expr := "toString(status_code)"
		return expr, expr
	case "user_agent_families", "user_agents":
		return "user_agent", "user_agent"
	case "ddos_reasons":
		expr := "if(rule_type IN ('ddos', 'application_flood'), JSONExtractString(metadata, 'reason'), '')"
		return expr, expr
	case "application_flood_reasons":
		expr := "if(rule_type IN ('ddos', 'application_flood'), JSONExtractString(metadata, 'reason'), '')"
		return expr, expr
	case "application_flood_objects":
		expr := "if(rule_type IN ('ddos', 'application_flood'), JSONExtractString(metadata, 'protected_object'), '')"
		return expr, expr
	case "blacklist_reasons":
		expr := "if(rule_type = 'blacklist', JSONExtractString(metadata, 'reason'), '')"
		return expr, expr
	case "ratelimit_triggers":
		expr := "if(rule_type = 'ratelimit', JSONExtractString(metadata, 'reason'), '')"
		return expr, expr
	case "ratelimit_rules":
		expr := "if(rule_type = 'ratelimit', JSONExtractString(metadata, 'matched_rule'), '')"
		return expr, expr
	case "geo_countries":
		expr := "if(rule_type = 'geo', if(country = '', JSONExtractString(metadata, 'country'), country), '')"
		return expr, expr
	case "geo_reasons":
		expr := "if(rule_type = 'geo', JSONExtractString(metadata, 'reason'), '')"
		return expr, expr
	case "reputation_scores":
		expr := "if(rule_type != 'reputation' OR JSONExtractString(metadata, 'score') = '', '', if(toInt32OrZero(JSONExtractString(metadata, 'score')) < 40, '0-39', if(toInt32OrZero(JSONExtractString(metadata, 'score')) < 70, '40-69', '70-100')))"
		return expr, expr
	case "reputation_reasons":
		expr := "if(rule_type = 'reputation', JSONExtractString(metadata, 'reason'), '')"
		return expr, expr
	case "challenge_strategies":
		expr := "if(" + normalizedTrafficActionSQL() + " = 'challenge', JSONExtractString(metadata, 'strategy'), '')"
		return expr, expr
	case "trusted_exception_controls":
		expr := "if(rule_type = 'trusted_exception', JSONExtractString(metadata, 'control'), '')"
		return expr, expr
	case "trusted_exception_ids":
		expr := "if(rule_type = 'trusted_exception', JSONExtractString(metadata, 'exception_id'), '')"
		return expr, expr
	default:
		return "path", "path"
	}
}

func scanTrafficAnalyticsEvent(row sqlScanner) (TrafficAnalyticsEvent, error) {
	var event TrafficAnalyticsEvent
	var ts uint32
	var status uint16
	var metadata string
	if err := row.Scan(&event.ID, &ts, &event.ClientIP, &event.Country, &event.Method, &event.Path, &status, &event.Action, &event.UserAgent, &event.UserAgentFamily, &event.RuleID, &event.RuleName, &event.RuleType, &event.LatencyMs, &event.RequestID, &metadata); err != nil {
		return event, err
	}
	event.Timestamp = int64(ts)
	event.StatusCode = int(status)
	applyTrafficEventMetadata(&event, metadata)
	return event, nil
}

func applyTrafficEventMetadata(event *TrafficAnalyticsEvent, raw string) {
	var meta map[string]string
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return
	}
	event.Metadata = meta
}

func formatTrafficBreakdownLabel(dimension, value string) string {
	if value == "" {
		return value
	}
	switch dimension {
	case "actions":
		switch normalizeTrafficAction(value) {
		case "allow":
			return "Allowed"
		case "block":
			return "Blocked"
		case "challenge":
			return "Challenged"
		case "ratelimit":
			return "Rate Limited"
		case "error":
			return "Errors"
		}
	case "reasons":
		switch value {
		case "blacklist":
			return "IP Blacklist"
		case "ddos", "application_flood":
			return "Application Flood"
		case "geo":
			return "Geo Blocking"
		case "reputation":
			return "IP Reputation"
		case "ratelimit":
			return "Rate Limiting"
		case "trusted_exception":
			return "Trusted Exceptions"
		}
	}
	return strings.Title(strings.ReplaceAll(value, "_", " "))
}

func topTrafficBreakdownKey(items []TrafficBreakdownItem) string {
	if len(items) == 0 {
		return ""
	}
	if items[0].Label != "" {
		return items[0].Label
	}
	return items[0].Key
}

func GetTrafficBlockedRequests(limit int) ([]RequestLog, error) {
	return getSectionBlockedRequests("traffic_control", limit)
}

func GetTrafficTopBlockedIPs(limit int) ([]map[string]interface{}, error) {
	return topSectionBlocked("traffic_control", "client_ip", "ip", limit)
}

func GetTrafficTopBlockedCountries(limit int) ([]map[string]interface{}, error) {
	return topSectionBlocked("traffic_control", "country", "country", limit)
}
