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

type HTTPSecurityAnalyticsQuery struct {
	Window    string
	Interval  string
	Action    string
	Function  string
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

type HTTPSecurityAnalyticsSummary struct {
	TotalRequests     int64   `json:"total_requests"`
	BlockedRequests   int64   `json:"blocked_requests"`
	AllowedRequests   int64   `json:"allowed_requests"`
	Redirects         int64   `json:"redirects"`
	ModifiedResponses int64   `json:"modified_responses"`
	Compressed        int64   `json:"compressed_responses"`
	Injected          int64   `json:"injected_responses"`
	ErrorRequests     int64   `json:"error_requests"`
	BlockRate         float64 `json:"block_rate"`
	ModificationRate  float64 `json:"modification_rate"`
	AvgLatencyMs      float64 `json:"avg_latency_ms"`
	P95LatencyMs      float64 `json:"p95_latency_ms"`
	UniqueSourceIPs   int64   `json:"unique_source_ips"`
	UniqueCountries   int64   `json:"unique_countries"`
	TopFunction       string  `json:"top_function"`
	DroppedEvents     int64   `json:"dropped_events"`
	Window            string  `json:"window"`
}

type HTTPSecurityTimeseriesPoint struct {
	Timestamp    int64            `json:"timestamp"`
	Counts       map[string]int64 `json:"counts"`
	AvgLatencyMs float64          `json:"avg_latency_ms"`
	P95LatencyMs float64          `json:"p95_latency_ms"`
}

type HTTPSecurityBreakdownItem struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	Count        int64   `json:"count"`
	Blocked      int64   `json:"blocked"`
	Modified     int64   `json:"modified"`
	BlockRate    float64 `json:"block_rate"`
	Percent      float64 `json:"percent"`
	LastSeen     int64   `json:"last_seen"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

type HTTPSecurityAnalyticsEvent struct {
	ID               string            `json:"id"`
	Timestamp        int64             `json:"timestamp"`
	ClientIP         string            `json:"client_ip"`
	Country          string            `json:"country"`
	Method           string            `json:"method"`
	Path             string            `json:"path"`
	StatusCode       int               `json:"status_code"`
	Action           string            `json:"action"`
	UserAgent        string            `json:"user_agent"`
	UserAgentFamily  string            `json:"user_agent_family"`
	RuleID           string            `json:"rule_id"`
	RuleName         string            `json:"rule_name"`
	RuleType         string            `json:"rule_type"`
	LatencyMs        int64             `json:"latency_ms"`
	RequestID        string            `json:"request_id"`
	Function         string            `json:"function"`
	Reason           string            `json:"reason"`
	Host             string            `json:"host"`
	QueryString      string            `json:"query_string"`
	ContentType      string            `json:"content_type"`
	HeaderName       string            `json:"header_name"`
	HeaderCount      int               `json:"header_count"`
	ContentLength    int64             `json:"content_length"`
	ResponseModified bool              `json:"response_modified"`
	RequestModified  bool              `json:"request_modified"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type HTTPSecurityAnalyticsEventsPage struct {
	Events     []HTTPSecurityAnalyticsEvent `json:"events"`
	NextCursor string                       `json:"next_cursor,omitempty"`
	Count      int                          `json:"count"`
}

type HTTPSecurityAnalyticsHealth struct {
	DBAvailable         bool   `json:"db_available"`
	LastEventTimestamp  int64  `json:"last_event_timestamp"`
	IngestionLagSeconds int64  `json:"ingestion_lag_seconds"`
	DroppedEvents       int64  `json:"dropped_events"`
	FreshnessStatus     string `json:"freshness_status"`
	Message             string `json:"message"`
}

type HTTPSecurityHardeningSummary struct {
	BlockedRequests     int64   `json:"blocked_requests"`
	RedirectedRequests  int64   `json:"redirected_requests"`
	ModifiedResponses   int64   `json:"modified_responses"`
	CompressedResponses int64   `json:"compressed_responses"`
	InjectedResponses   int64   `json:"injected_responses"`
	RuleMatches         int64   `json:"rule_matches"`
	EnforcementRate     float64 `json:"enforcement_rate"`
	Window              string  `json:"window"`
}

type HTTPSecurityRequestProtection struct {
	Functions          []HTTPSecurityBreakdownItem `json:"functions"`
	MethodEnforcement  int64                       `json:"method_enforcement"`
	HostValidation     int64                       `json:"host_validation"`
	ContentTypeChecks  int64                       `json:"content_type_checks"`
	BodyUploadLimits   int64                       `json:"body_upload_limits"`
	ExtensionFiltering int64                       `json:"extension_filtering"`
	ContentLengthBands []HTTPSecurityBreakdownItem `json:"content_length_bands"`
}

type HTTPSecurityResponseHardening struct {
	Functions             []HTTPSecurityBreakdownItem `json:"functions"`
	SecurityHeaders       int64                       `json:"security_headers"`
	CookieHardening       int64                       `json:"cookie_hardening"`
	InfoHiding            int64                       `json:"info_hiding"`
	Compression           int64                       `json:"compression"`
	HTMLInjection         int64                       `json:"html_injection"`
	Redirects             int64                       `json:"redirects"`
	ResponseModifications []HTTPSecurityBreakdownItem `json:"response_modifications"`
}

type HTTPSecurityRuleEffectiveness struct {
	Rules          []HTTPSecurityBreakdownItem `json:"rules"`
	TopBlocking    []HTTPSecurityBreakdownItem `json:"top_blocking"`
	TopModifying   []HTTPSecurityBreakdownItem `json:"top_modifying"`
	NoisyFunctions []HTTPSecurityBreakdownItem `json:"noisy_functions"`
}

type HTTPSecurityHTTPIntelligence struct {
	Functions             []HTTPSecurityBreakdownItem `json:"functions"`
	Actions               []HTTPSecurityBreakdownItem `json:"actions"`
	Reasons               []HTTPSecurityBreakdownItem `json:"reasons"`
	ContentTypes          []HTTPSecurityBreakdownItem `json:"content_types"`
	HeaderNames           []HTTPSecurityBreakdownItem `json:"header_names"`
	ContentLengthBands    []HTTPSecurityBreakdownItem `json:"content_length_bands"`
	RequestModifications  []HTTPSecurityBreakdownItem `json:"request_modifications"`
	ResponseModifications []HTTPSecurityBreakdownItem `json:"response_modifications"`
}

type HTTPSecurityPolicyHealth struct {
	Status             string `json:"status"`
	ConfigState        string `json:"config_state"`
	FunctionState      string `json:"function_state"`
	TelemetryFreshness string `json:"telemetry_freshness"`
	DroppedEvents      int64  `json:"dropped_events"`
	ConfigMessage      string `json:"config_message"`
}

type HTTPSecurityAnalyticsDashboard struct {
	Summary           HTTPSecurityAnalyticsSummary           `json:"summary"`
	Timeseries        []HTTPSecurityTimeseriesPoint          `json:"timeseries"`
	Breakdowns        map[string][]HTTPSecurityBreakdownItem `json:"breakdowns"`
	Events            HTTPSecurityAnalyticsEventsPage        `json:"events"`
	Health            HTTPSecurityAnalyticsHealth            `json:"health"`
	HardeningSummary  HTTPSecurityHardeningSummary           `json:"hardening_summary"`
	RequestProtection HTTPSecurityRequestProtection          `json:"request_protection"`
	ResponseHardening HTTPSecurityResponseHardening          `json:"response_hardening"`
	RuleEffectiveness HTTPSecurityRuleEffectiveness          `json:"rule_effectiveness"`
	HTTPIntelligence  HTTPSecurityHTTPIntelligence           `json:"http_intelligence"`
	PolicyHealth      HTTPSecurityPolicyHealth               `json:"policy_health"`
	Warnings          []string                               `json:"warnings"`
}

func GetHTTPSecurityAnalyticsDashboard(q HTTPSecurityAnalyticsQuery) (HTTPSecurityAnalyticsDashboard, error) {
	dashboard := HTTPSecurityAnalyticsDashboard{
		Timeseries: []HTTPSecurityTimeseriesPoint{},
		Breakdowns: map[string][]HTTPSecurityBreakdownItem{},
		Events:     HTTPSecurityAnalyticsEventsPage{Events: []HTTPSecurityAnalyticsEvent{}},
		Warnings:   []string{},
	}
	if _, _, err := buildHTTPSecurityAnalyticsWhere(q); err != nil {
		return dashboard, err
	}
	if _, err := ResolveWAFAnalyticsInterval(q.Window, q.Interval); err != nil {
		return dashboard, err
	}
	if summary, err := GetHTTPSecurityAnalyticsSummary(q); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "summary unavailable")
	} else {
		dashboard.Summary = summary
	}
	if points, err := GetHTTPSecurityAnalyticsTimeseries(q); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "timeseries unavailable")
	} else {
		dashboard.Timeseries = points
	}
	breakdownQuery := q
	breakdownQuery.Limit = NormalizeWAFLimit(q.Limit, 10, 100)
	for _, dimension := range []string{"actions", "functions", "rules", "countries", "ips", "paths", "methods", "status", "user_agent_families", "reasons", "content_types", "header_names", "content_length_bands", "request_modifications", "response_modifications"} {
		items, err := GetHTTPSecurityAnalyticsBreakdown(breakdownQuery, dimension)
		if err != nil {
			dashboard.Warnings = append(dashboard.Warnings, dimension+" breakdown unavailable")
			dashboard.Breakdowns[dimension] = []HTTPSecurityBreakdownItem{}
			continue
		}
		dashboard.Breakdowns[dimension] = items
	}
	eventQuery := q
	eventQuery.Limit = NormalizeWAFLimit(q.Limit, 50, 500)
	if events, err := GetHTTPSecurityAnalyticsEvents(eventQuery); err != nil {
		dashboard.Warnings = append(dashboard.Warnings, "events unavailable")
	} else {
		dashboard.Events = events
	}
	if dashboard.Summary.TopFunction == "" {
		dashboard.Summary.TopFunction = topHTTPSecurityBreakdownKey(dashboard.Breakdowns["functions"])
	}
	dashboard.Health = GetHTTPSecurityAnalyticsHealth()
	PopulateHTTPSecurityAnalyticsDashboardGroups(&dashboard)
	return dashboard, nil
}

func PopulateHTTPSecurityAnalyticsDashboardGroups(dashboard *HTTPSecurityAnalyticsDashboard) {
	if dashboard == nil {
		return
	}
	breakdowns := dashboard.Breakdowns
	if breakdowns == nil {
		breakdowns = map[string][]HTTPSecurityBreakdownItem{}
		dashboard.Breakdowns = breakdowns
	}
	summary := dashboard.Summary
	responseChanges := summary.Redirects + summary.ModifiedResponses + summary.Compressed + summary.Injected
	rules := safeHTTPSecurityBreakdown(breakdowns, "rules")
	functions := safeHTTPSecurityBreakdown(breakdowns, "functions")

	dashboard.HardeningSummary = HTTPSecurityHardeningSummary{
		BlockedRequests:     summary.BlockedRequests,
		RedirectedRequests:  summary.Redirects,
		ModifiedResponses:   summary.ModifiedResponses,
		CompressedResponses: summary.Compressed,
		InjectedResponses:   summary.Injected,
		RuleMatches:         sumHTTPSecurityBreakdown(rules),
		EnforcementRate:     summary.BlockRate,
		Window:              summary.Window,
	}
	dashboard.RequestProtection = HTTPSecurityRequestProtection{
		Functions:          filterHTTPSecurityFunctionBreakdowns(functions, "upload_limit", "extension_filter", "method_enforcer", "host_validator", "content_type_validator", "request_size_guard"),
		MethodEnforcement:  countHTTPSecurityFunction(functions, "method_enforcer"),
		HostValidation:     countHTTPSecurityFunction(functions, "host_validator"),
		ContentTypeChecks:  countHTTPSecurityFunction(functions, "content_type_validator"),
		BodyUploadLimits:   countHTTPSecurityFunction(functions, "upload_limit", "request_size_guard"),
		ExtensionFiltering: countHTTPSecurityFunction(functions, "extension_filter"),
		ContentLengthBands: safeHTTPSecurityBreakdown(breakdowns, "content_length_bands"),
	}
	dashboard.ResponseHardening = HTTPSecurityResponseHardening{
		Functions:             filterHTTPSecurityFunctionBreakdowns(functions, "security_headers", "header_manager", "info_hiding", "cookie_hardener", "https_redirect", "gzip", "html_injector"),
		SecurityHeaders:       countHTTPSecurityFunction(functions, "security_headers", "header_manager"),
		CookieHardening:       countHTTPSecurityFunction(functions, "cookie_hardener"),
		InfoHiding:            countHTTPSecurityFunction(functions, "info_hiding"),
		Compression:           summary.Compressed,
		HTMLInjection:         summary.Injected,
		Redirects:             summary.Redirects,
		ResponseModifications: safeHTTPSecurityBreakdown(breakdowns, "response_modifications"),
	}
	dashboard.RuleEffectiveness = HTTPSecurityRuleEffectiveness{
		Rules:        rules,
		TopBlocking:  filterHTTPSecurityBreakdowns(rules, func(item HTTPSecurityBreakdownItem) bool { return item.Blocked > 0 }),
		TopModifying: filterHTTPSecurityBreakdowns(rules, func(item HTTPSecurityBreakdownItem) bool { return item.Modified > 0 }),
		NoisyFunctions: filterHTTPSecurityBreakdowns(functions, func(item HTTPSecurityBreakdownItem) bool {
			return item.Count > 0 && item.Blocked == 0 && item.Modified == 0
		}),
	}
	dashboard.HTTPIntelligence = HTTPSecurityHTTPIntelligence{
		Functions:             functions,
		Actions:               safeHTTPSecurityBreakdown(breakdowns, "actions"),
		Reasons:               safeHTTPSecurityBreakdown(breakdowns, "reasons"),
		ContentTypes:          safeHTTPSecurityBreakdown(breakdowns, "content_types"),
		HeaderNames:           safeHTTPSecurityBreakdown(breakdowns, "header_names"),
		ContentLengthBands:    safeHTTPSecurityBreakdown(breakdowns, "content_length_bands"),
		RequestModifications:  safeHTTPSecurityBreakdown(breakdowns, "request_modifications"),
		ResponseModifications: safeHTTPSecurityBreakdown(breakdowns, "response_modifications"),
	}
	dashboard.PolicyHealth = HTTPSecurityPolicyHealth{
		Status:             httpSecurityPolicyStatus(dashboard.Health),
		ConfigState:        "unavailable",
		FunctionState:      httpSecurityFunctionState(functions, responseChanges),
		TelemetryFreshness: dashboard.Health.FreshnessStatus,
		DroppedEvents:      dashboard.Health.DroppedEvents,
		ConfigMessage:      dashboard.Health.Message,
	}
}

func safeHTTPSecurityBreakdown(breakdowns map[string][]HTTPSecurityBreakdownItem, key string) []HTTPSecurityBreakdownItem {
	if breakdowns == nil || breakdowns[key] == nil {
		return []HTTPSecurityBreakdownItem{}
	}
	return breakdowns[key]
}

func sumHTTPSecurityBreakdown(items []HTTPSecurityBreakdownItem) int64 {
	var total int64
	for _, item := range items {
		total += item.Count
	}
	return total
}

func countHTTPSecurityFunction(items []HTTPSecurityBreakdownItem, keys ...string) int64 {
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[strings.ToLower(key)] = true
	}
	var total int64
	for _, item := range items {
		if allowed[strings.ToLower(firstNonEmptyString(item.Key, item.Label))] {
			total += item.Count
		}
	}
	return total
}

func filterHTTPSecurityFunctionBreakdowns(items []HTTPSecurityBreakdownItem, keys ...string) []HTTPSecurityBreakdownItem {
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[strings.ToLower(key)] = true
	}
	return filterHTTPSecurityBreakdowns(items, func(item HTTPSecurityBreakdownItem) bool {
		return allowed[strings.ToLower(firstNonEmptyString(item.Key, item.Label))]
	})
}

func filterHTTPSecurityBreakdowns(items []HTTPSecurityBreakdownItem, keep func(HTTPSecurityBreakdownItem) bool) []HTTPSecurityBreakdownItem {
	out := []HTTPSecurityBreakdownItem{}
	for _, item := range items {
		if keep(item) {
			out = append(out, item)
		}
	}
	return out
}

func httpSecurityPolicyStatus(health HTTPSecurityAnalyticsHealth) string {
	if !health.DBAvailable {
		return "unavailable"
	}
	if health.FreshnessStatus == "fresh" {
		return "healthy"
	}
	return health.FreshnessStatus
}

func httpSecurityFunctionState(functions []HTTPSecurityBreakdownItem, responseChanges int64) string {
	if len(functions) == 0 && responseChanges == 0 {
		return "unavailable"
	}
	return "observed"
}

func GetHTTPSecurityAnalyticsSummary(q HTTPSecurityAnalyticsQuery) (HTTPSecurityAnalyticsSummary, error) {
	summary := HTTPSecurityAnalyticsSummary{Window: defaultWindow(q.Window), DroppedEvents: DroppedEvents()}
	if DB == nil {
		return summary, nil
	}
	where, args, err := buildHTTPSecurityAnalyticsWhere(q)
	if err != nil {
		return summary, err
	}
	row := DB.QueryRow(`
		SELECT count(),
			countIf(`+normalizedHTTPSecurityActionSQL()+` = 'block'),
			countIf(`+normalizedHTTPSecurityActionSQL()+` = 'allow'),
			countIf(`+normalizedHTTPSecurityActionSQL()+` = 'redirect'),
			countIf(`+normalizedHTTPSecurityActionSQL()+` = 'modify'),
			countIf(`+normalizedHTTPSecurityActionSQL()+` = 'compress'),
			countIf(`+normalizedHTTPSecurityActionSQL()+` = 'inject'),
			countIf(`+normalizedHTTPSecurityActionSQL()+` = 'error'),
			COALESCE(avg(latency_ms), 0),
			COALESCE(quantile(0.95)(latency_ms), 0),
			uniqExact(client_ip),
			uniqExactIf(country, country != '')
		FROM section_events `+where, args...)
	var total, blocked, allowed, redirects, modified, compressed, injected, errors, uniqueIPs, uniqueCountries uint64
	if err := row.Scan(&total, &blocked, &allowed, &redirects, &modified, &compressed, &injected, &errors, &summary.AvgLatencyMs, &summary.P95LatencyMs, &uniqueIPs, &uniqueCountries); err != nil {
		return summary, err
	}
	summary.TotalRequests = int64(total)
	summary.BlockedRequests = int64(blocked)
	summary.AllowedRequests = int64(allowed)
	summary.Redirects = int64(redirects)
	summary.ModifiedResponses = int64(modified)
	summary.Compressed = int64(compressed)
	summary.Injected = int64(injected)
	summary.ErrorRequests = int64(errors)
	summary.UniqueSourceIPs = int64(uniqueIPs)
	summary.UniqueCountries = int64(uniqueCountries)
	if total > 0 {
		summary.BlockRate = float64(blocked) / float64(total) * 100
		summary.ModificationRate = float64(redirects+modified+compressed+injected) / float64(total) * 100
	}
	summary.AvgLatencyMs = finiteFloat(summary.AvgLatencyMs)
	summary.P95LatencyMs = finiteFloat(summary.P95LatencyMs)
	return summary, nil
}

func GetHTTPSecurityAnalyticsTimeseries(q HTTPSecurityAnalyticsQuery) ([]HTTPSecurityTimeseriesPoint, error) {
	if DB == nil {
		return []HTTPSecurityTimeseriesPoint{}, nil
	}
	where, args, err := buildHTTPSecurityAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	interval, err := ResolveWAFAnalyticsInterval(q.Window, q.Interval)
	if err != nil {
		return nil, err
	}
	rows, err := DB.Query(`
		SELECT toUnixTimestamp(bucket), action, count(), COALESCE(avg(latency_ms), 0), COALESCE(quantile(0.95)(latency_ms), 0)
		FROM (
			SELECT `+bucketExpression(interval)+` AS bucket, `+normalizedHTTPSecurityActionSQL()+` AS action, latency_ms
			FROM section_events `+where+`
		)
		GROUP BY bucket, action
		ORDER BY bucket ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byBucket := map[int64]*HTTPSecurityTimeseriesPoint{}
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
			point = &HTTPSecurityTimeseriesPoint{Timestamp: key, Counts: map[string]int64{}}
			byBucket[key] = point
		}
		point.Counts[action] = int64(count)
		point.AvgLatencyMs = finiteFloat(avgLatency)
		point.P95LatencyMs = finiteFloat(p95Latency)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	keys := make([]int64, 0, len(byBucket))
	for key := range byBucket {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]HTTPSecurityTimeseriesPoint, 0, len(keys))
	for _, key := range keys {
		out = append(out, *byBucket[key])
	}
	return out, nil
}

func GetHTTPSecurityAnalyticsBreakdown(q HTTPSecurityAnalyticsQuery, dimension string) ([]HTTPSecurityBreakdownItem, error) {
	dimension = strings.ToLower(strings.TrimSpace(dimension))
	if err := ValidateHTTPSecurityBreakdownDimension(dimension); err != nil {
		return nil, err
	}
	if DB == nil {
		return []HTTPSecurityBreakdownItem{}, nil
	}
	where, args, err := buildHTTPSecurityAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	expr, labelExpr := httpSecurityBreakdownExpression(dimension)
	limit := NormalizeWAFLimit(q.Limit, 10, 100)
	args = append(args, limit)
	rows, err := DB.Query(fmt.Sprintf(`
		SELECT %s AS key, %s AS label, count(),
			countIf(%s = 'block'),
			countIf(%s IN ('redirect', 'modify', 'compress', 'inject')),
			toUnixTimestamp(max(timestamp)),
			COALESCE(avg(latency_ms), 0)
		FROM section_events %s AND %s != ''
		GROUP BY key, label
		ORDER BY count() DESC
		LIMIT ?`, expr, labelExpr, normalizedHTTPSecurityActionSQL(), normalizedHTTPSecurityActionSQL(), where, expr), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]HTTPSecurityBreakdownItem, 0, limit)
	var total int64
	for rows.Next() {
		var item HTTPSecurityBreakdownItem
		var count, blocked, modified uint64
		var lastSeen uint32
		if err := rows.Scan(&item.Key, &item.Label, &count, &blocked, &modified, &lastSeen, &item.AvgLatencyMs); err != nil {
			return nil, err
		}
		item.Count = int64(count)
		item.Blocked = int64(blocked)
		item.Modified = int64(modified)
		item.LastSeen = int64(lastSeen)
		if count > 0 {
			item.BlockRate = float64(blocked) / float64(count) * 100
		}
		item.AvgLatencyMs = finiteFloat(item.AvgLatencyMs)
		item.Label = formatHTTPSecurityBreakdownLabel(dimension, item.Label)
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

func GetHTTPSecurityAnalyticsEvents(q HTTPSecurityAnalyticsQuery) (HTTPSecurityAnalyticsEventsPage, error) {
	page := HTTPSecurityAnalyticsEventsPage{Events: []HTTPSecurityAnalyticsEvent{}}
	if DB == nil {
		return page, nil
	}
	limit := NormalizeWAFLimit(q.Limit, 50, 500)
	q.Limit = limit + 1
	where, args, err := buildHTTPSecurityAnalyticsWhere(q)
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
		SELECT id, toUnixTimestamp(timestamp), client_ip, country, method, path, status_code, `+normalizedHTTPSecurityActionSQL()+`, user_agent,
		       user_agent_family, rule_id, rule_name, rule_type, latency_ms, request_id, metadata
		FROM section_events `+where+`
		ORDER BY timestamp `+order+`
		LIMIT ?`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		event, err := scanHTTPSecurityAnalyticsEvent(rows)
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

func GetHTTPSecurityAnalyticsEvent(id string) (*HTTPSecurityAnalyticsEvent, error) {
	if DB == nil {
		return nil, nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("missing event id")
	}
	row := DB.QueryRow(`
		SELECT id, toUnixTimestamp(timestamp), client_ip, country, method, path, status_code, `+normalizedHTTPSecurityActionSQL()+`, user_agent,
		       user_agent_family, rule_id, rule_name, rule_type, latency_ms, request_id, metadata
		FROM section_events
		WHERE section = 'http_security' AND id = ?
		LIMIT 1`, id)
	event, err := scanHTTPSecurityAnalyticsEvent(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func GetHTTPSecurityAnalyticsHealth() HTTPSecurityAnalyticsHealth {
	health := HTTPSecurityAnalyticsHealth{DBAvailable: DB != nil, DroppedEvents: DroppedEvents(), FreshnessStatus: "unavailable", Message: ""}
	if DB == nil {
		return health
	}
	health.Message = "No HTTP Security analytics events have been recorded yet"
	var count uint64
	var last uint32
	err := DB.QueryRow(`SELECT count(), toUnixTimestamp(max(timestamp)) FROM section_events WHERE section = 'http_security'`).Scan(&count, &last)
	if err != nil {
		health.Message = "Unable to read HTTP Security analytics freshness"
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
		health.Message = "HTTP Security analytics are current"
	case health.IngestionLagSeconds <= 900:
		health.FreshnessStatus = "delayed"
		health.Message = "HTTP Security analytics are slightly delayed"
	default:
		health.FreshnessStatus = "stale"
		health.Message = "HTTP Security analytics have not received recent events"
	}
	return health
}

func ValidateHTTPSecurityBreakdownDimension(dimension string) error {
	switch strings.ToLower(strings.TrimSpace(dimension)) {
	case "actions", "functions", "rules", "countries", "ips", "paths", "methods", "status", "user_agent_families", "user_agents", "reasons", "content_types", "header_names", "content_length_bands", "request_modifications", "response_modifications":
		return nil
	default:
		return fmt.Errorf("unsupported breakdown dimension %q", dimension)
	}
}

func buildHTTPSecurityAnalyticsWhere(q HTTPSecurityAnalyticsQuery) (string, []any, error) {
	since, err := windowStart(defaultWindow(q.Window))
	if err != nil {
		return "", nil, err
	}
	clauses := []string{"section = 'http_security'", "timestamp >= ?"}
	args := []any{since}
	add := func(clause string, value any) { clauses = append(clauses, clause); args = append(args, value) }
	if q.Action != "" {
		add(normalizedHTTPSecurityActionSQL()+" = ?", normalizeHTTPSecurityAction(q.Action))
	}
	if q.Function != "" {
		add("JSONExtractString(metadata, 'function') = ?", strings.TrimSpace(q.Function))
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

func normalizedHTTPSecurityActionSQL() string {
	return "if(action = 'pass', 'allow', if(action = 'modified', 'modify', action))"
}

func normalizeHTTPSecurityAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "pass", "allowed":
		return "allow"
	case "blocked", "deny":
		return "block"
	case "modified":
		return "modify"
	default:
		return strings.ToLower(strings.TrimSpace(action))
	}
}

func httpSecurityBreakdownExpression(dimension string) (string, string) {
	switch dimension {
	case "actions":
		expr := normalizedHTTPSecurityActionSQL()
		return expr, expr
	case "functions":
		expr := "JSONExtractString(metadata, 'function')"
		return expr, expr
	case "rules":
		return "rule_id", "rule_name"
	case "reasons":
		expr := "JSONExtractString(metadata, 'reason')"
		return expr, expr
	case "content_types":
		expr := "JSONExtractString(metadata, 'content_type')"
		return expr, expr
	case "header_names":
		expr := "JSONExtractString(metadata, 'header_name')"
		return expr, expr
	case "content_length_bands":
		expr := "if(JSONExtractString(metadata, 'content_length') = '', '', if(toInt64OrZero(JSONExtractString(metadata, 'content_length')) < 1024, '<1KB', if(toInt64OrZero(JSONExtractString(metadata, 'content_length')) < 102400, '1KB-100KB', if(toInt64OrZero(JSONExtractString(metadata, 'content_length')) < 1048576, '100KB-1MB', '>1MB'))))"
		return expr, expr
	case "request_modifications":
		expr := "if(JSONExtractString(metadata, 'request_modified') = 'true', 'request modified', '')"
		return expr, expr
	case "response_modifications":
		expr := "if(JSONExtractString(metadata, 'response_modified') = 'true', 'response modified', '')"
		return expr, expr
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
	default:
		return "path", "path"
	}
}

func scanHTTPSecurityAnalyticsEvent(row sqlScanner) (HTTPSecurityAnalyticsEvent, error) {
	var event HTTPSecurityAnalyticsEvent
	var ts uint32
	var status uint16
	var metadata string
	if err := row.Scan(&event.ID, &ts, &event.ClientIP, &event.Country, &event.Method, &event.Path, &status, &event.Action, &event.UserAgent, &event.UserAgentFamily, &event.RuleID, &event.RuleName, &event.RuleType, &event.LatencyMs, &event.RequestID, &metadata); err != nil {
		return event, err
	}
	event.Timestamp = int64(ts)
	event.StatusCode = int(status)
	applyHTTPSecurityEventMetadata(&event, metadata)
	return event, nil
}

func applyHTTPSecurityEventMetadata(event *HTTPSecurityAnalyticsEvent, raw string) {
	var meta map[string]string
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return
	}
	event.Metadata = meta
	event.Function = firstMetadataValue(meta, "function")
	event.Reason = firstMetadataValue(meta, "reason")
	event.Host = firstMetadataValue(meta, "host")
	event.QueryString = firstMetadataValue(meta, "query_string")
	event.ContentType = firstMetadataValue(meta, "content_type")
	event.HeaderName = firstMetadataValue(meta, "header_name")
	event.HeaderCount = int(parseInt64(firstMetadataValue(meta, "header_count")))
	event.ContentLength = parseInt64(firstMetadataValue(meta, "content_length"))
	event.ResponseModified = parseMetadataBool(firstMetadataValue(meta, "response_modified"))
	event.RequestModified = parseMetadataBool(firstMetadataValue(meta, "request_modified"))
}

func formatHTTPSecurityBreakdownLabel(dimension, value string) string {
	if value == "" {
		return value
	}
	switch dimension {
	case "actions":
		switch normalizeHTTPSecurityAction(value) {
		case "allow":
			return "Allowed"
		case "block":
			return "Blocked"
		case "redirect":
			return "Redirected"
		case "modify":
			return "Modified"
		case "compress":
			return "Compressed"
		case "inject":
			return "Injected"
		case "error":
			return "Errors"
		}
	case "functions":
		return strings.Title(strings.ReplaceAll(value, "_", " "))
	case "content_length_bands":
		return value
	case "request_modifications", "response_modifications":
		return strings.Title(value)
	}
	return strings.Title(strings.ReplaceAll(value, "_", " "))
}

func topHTTPSecurityBreakdownKey(items []HTTPSecurityBreakdownItem) string {
	if len(items) == 0 {
		return ""
	}
	if items[0].Label != "" {
		return items[0].Label
	}
	return items[0].Key
}
