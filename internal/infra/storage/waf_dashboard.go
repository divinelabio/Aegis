package storage

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var wafDashboardQueryExecutions atomic.Uint64

var wafDashboardBreakdownDimensions = []string{
	"actions",
	"categories",
	"rules",
	"countries",
	"ips",
	"paths",
	"hosts",
	"methods",
	"status",
	"severities",
	"user_agent_families",
	"user_agents",
}

type wafDashboardSummaryResult struct {
	summary  WAFAnalyticsSummary
	health   WAFAnalyticsHealth
	coverage WAFInspectionCoverage
}

// GetWAFAnalyticsDashboard runs the complete dashboard contract with a bounded
// four-query fan-out: summary/health/coverage, timeseries, all breakdowns, and
// the event page.
func GetWAFAnalyticsDashboard(q WAFAnalyticsQuery) (WAFAnalyticsDashboard, error) {
	return GetWAFAnalyticsDashboardContext(context.Background(), q)
}

func GetWAFAnalyticsDashboardContext(ctx context.Context, q WAFAnalyticsQuery) (WAFAnalyticsDashboard, error) {
	dashboard := emptyWAFAnalyticsDashboard(q)
	if _, _, err := buildWAFAnalyticsWhere(q); err != nil {
		return dashboard, err
	}
	if _, err := ResolveWAFAnalyticsInterval(q.Window, q.Interval); err != nil {
		return dashboard, err
	}
	if DB == nil {
		return finalizeWAFAnalyticsDashboard(dashboard), nil
	}

	var (
		summaryResult wafDashboardSummaryResult
		timeseries    []WAFTimeseriesPoint
		breakdowns    map[string][]WAFBreakdownItem
		events        WAFAnalyticsEventsPage
		summaryErr    error
		timeseriesErr error
		breakdownsErr error
		eventsErr     error
	)

	var wait sync.WaitGroup
	wait.Add(4)
	go func() {
		defer wait.Done()
		summaryResult, summaryErr = getWAFDashboardSummaryContext(ctx, q)
	}()
	go func() {
		defer wait.Done()
		timeseries, timeseriesErr = getWAFDashboardTimeseriesContext(ctx, q)
	}()
	go func() {
		defer wait.Done()
		breakdowns, breakdownsErr = getWAFDashboardBreakdownsContext(ctx, q)
	}()
	go func() {
		defer wait.Done()
		events, eventsErr = getWAFDashboardEventsContext(ctx, q)
	}()
	wait.Wait()

	if err := ctx.Err(); err != nil {
		return dashboard, err
	}
	if summaryErr != nil {
		dashboard.Warnings = append(dashboard.Warnings, "summary unavailable")
	} else {
		dashboard.Summary = summaryResult.summary
		dashboard.Health = summaryResult.health
		dashboard.InspectionCoverage = summaryResult.coverage
	}
	if timeseriesErr != nil {
		dashboard.Warnings = append(dashboard.Warnings, "timeseries unavailable")
	} else {
		dashboard.Timeseries = timeseries
	}
	if breakdownsErr != nil {
		dashboard.Warnings = append(dashboard.Warnings, "breakdowns unavailable")
	} else {
		for dimension, items := range breakdowns {
			switch dimension {
			case "anomaly_score_bands":
				dashboard.AttackIntelligence.AnomalyScoreBands = items
			case "matched_fields":
				dashboard.RuleEffectiveness.MatchedFields = items
			default:
				dashboard.Breakdowns[dimension] = items
			}
		}
	}
	if eventsErr != nil {
		dashboard.Warnings = append(dashboard.Warnings, "events unavailable")
	} else {
		dashboard.Events = events
	}
	return finalizeWAFAnalyticsDashboard(dashboard), nil
}

func emptyWAFAnalyticsDashboard(q WAFAnalyticsQuery) WAFAnalyticsDashboard {
	dashboard := WAFAnalyticsDashboard{
		Summary: WAFAnalyticsSummary{
			Window:        defaultWindow(q.Window),
			DroppedEvents: WAFDroppedEvents(),
		},
		Timeseries: []WAFTimeseriesPoint{},
		Breakdowns: map[string][]WAFBreakdownItem{},
		Events:     WAFAnalyticsEventsPage{Events: []WAFAnalyticsEvent{}},
		Health: WAFAnalyticsHealth{
			DBAvailable:     DB != nil,
			DroppedEvents:   WAFDroppedEvents(),
			FreshnessStatus: "unavailable",
			Message:         "",
		},
		AttackIntelligence: WAFAttackIntelligence{
			Categories:        []WAFBreakdownItem{},
			Severities:        []WAFBreakdownItem{},
			AnomalyScoreBands: []WAFBreakdownItem{},
			Trend:             []WAFTimeseriesPoint{},
		},
		RuleEffectiveness: WAFRuleEffectiveness{
			TopBlockingRules:   []WAFBreakdownItem{},
			TopDetectOnlyRules: []WAFBreakdownItem{},
			NoisyRules:         []WAFBreakdownItem{},
			MatchedFields:      []WAFBreakdownItem{},
		},
		TuningRecommendations: []WAFTuningRecommendation{},
		Warnings:              []string{},
	}
	for _, dimension := range wafDashboardBreakdownDimensions {
		dashboard.Breakdowns[dimension] = []WAFBreakdownItem{}
	}
	return dashboard
}

func finalizeWAFAnalyticsDashboard(dashboard WAFAnalyticsDashboard) WAFAnalyticsDashboard {
	if dashboard.Summary.TopAttackCategory == "" {
		dashboard.Summary.TopAttackCategory = topBreakdownKey(dashboard.Breakdowns["categories"])
	}
	dashboard.ProtectionSummary = buildWAFProtectionSummary(dashboard.Summary, dashboard.Breakdowns)
	dashboard.AttackIntelligence.Categories = dashboard.Breakdowns["categories"]
	dashboard.AttackIntelligence.Severities = dashboard.Breakdowns["severities"]
	dashboard.AttackIntelligence.Trend = dashboard.Timeseries
	dashboard.RuleEffectiveness.TopBlockingRules = topWAFRulesByMode(dashboard.Breakdowns["rules"], "block", 5)
	dashboard.RuleEffectiveness.TopDetectOnlyRules = topWAFRulesByMode(dashboard.Breakdowns["rules"], "detect", 5)
	dashboard.RuleEffectiveness.NoisyRules = noisyWAFRules(dashboard.Breakdowns["rules"], 5)
	dashboard.PolicyHealth = buildWAFPolicyHealth(dashboard.Events.Events)
	dashboard.TuningRecommendations = buildWAFTuningRecommendations(dashboard.RuleEffectiveness)
	return dashboard
}

func getWAFDashboardSummaryContext(ctx context.Context, q WAFAnalyticsQuery) (wafDashboardSummaryResult, error) {
	result := wafDashboardSummaryResult{
		summary: WAFAnalyticsSummary{
			Window:        defaultWindow(q.Window),
			DroppedEvents: WAFDroppedEvents(),
		},
		health: WAFAnalyticsHealth{
			DBAvailable:     DB != nil,
			DroppedEvents:   WAFDroppedEvents(),
			FreshnessStatus: "empty",
			Message:         "No WAF analytics events have been recorded yet",
		},
	}
	result.coverage.DroppedEvents = result.health.DroppedEvents
	if DB == nil {
		return result, nil
	}
	where, args, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return result, err
	}
	p95Expression := "COALESCE(quantile(0.95)(latency_ms), 0)"
	wafDashboardQueryExecutions.Add(1)
	row := DB.QueryRowContext(ctx, `
		SELECT total, blocked, detected, allowed, errors, avg_latency, p95_latency,
		       avg_score, max_score, unique_ips, unique_countries,
		       response_inspected, partial_responses, truncated_requests, truncated_responses,
		       COALESCE(toUnixTimestamp(last_seen), 0)
		FROM (
			SELECT
				COUNT(*) AS total,
				COALESCE(SUM(CASE WHEN `+normalizedActionSQL()+` = 'block' THEN 1 ELSE 0 END), 0) AS blocked,
				COALESCE(SUM(CASE WHEN `+normalizedActionSQL()+` = 'detect' THEN 1 ELSE 0 END), 0) AS detected,
				COALESCE(SUM(CASE WHEN `+normalizedActionSQL()+` = 'allow' THEN 1 ELSE 0 END), 0) AS allowed,
				COALESCE(SUM(CASE WHEN `+normalizedActionSQL()+` = 'error' THEN 1 ELSE 0 END), 0) AS errors,
				COALESCE(AVG(latency_ms), 0) AS avg_latency,
				`+p95Expression+` AS p95_latency,
				COALESCE(AVG(score), 0) AS avg_score,
				COALESCE(MAX(score), 0) AS max_score,
				COUNT(DISTINCT client_ip) AS unique_ips,
				COUNT(DISTINCT CASE WHEN country != '' THEN country END) AS unique_countries,
				COALESCE(SUM(CASE WHEN lower(JSONExtractString(metadata, 'response_inspected')) IN ('true', '1', 'yes') THEN 1 ELSE 0 END), 0) AS response_inspected,
				COALESCE(SUM(CASE WHEN lower(JSONExtractString(metadata, 'response_inspection_coverage')) = 'partial' THEN 1 ELSE 0 END), 0) AS partial_responses,
				COALESCE(SUM(CASE WHEN lower(JSONExtractString(metadata, 'request_truncated')) IN ('true', '1', 'yes') THEN 1 ELSE 0 END), 0) AS truncated_requests,
				COALESCE(SUM(CASE WHEN lower(JSONExtractString(metadata, 'response_truncated')) IN ('true', '1', 'yes') THEN 1 ELSE 0 END), 0) AS truncated_responses,
				MAX(timestamp) AS last_seen
			FROM section_events `+where+`
		)`, args...)

	var total, blocked, detected, allowed, errorCount, uniqueIPs, uniqueCountries uint64
	var responseInspected, partialResponses, truncatedRequests, truncatedResponses uint64
	var maxScore int32
	var lastSeen uint32
	if err := row.Scan(
		&total,
		&blocked,
		&detected,
		&allowed,
		&errorCount,
		&result.summary.AvgLatencyMs,
		&result.summary.P95LatencyMs,
		&result.summary.AvgAnomalyScore,
		&maxScore,
		&uniqueIPs,
		&uniqueCountries,
		&responseInspected,
		&partialResponses,
		&truncatedRequests,
		&truncatedResponses,
		&lastSeen,
	); err != nil {
		return result, err
	}

	result.summary.TotalRequests = int64(total)
	result.summary.BlockedRequests = int64(blocked)
	result.summary.DetectedRequests = int64(detected)
	result.summary.AllowedRequests = int64(allowed)
	result.summary.ErrorRequests = int64(errorCount)
	result.summary.MaxAnomalyScore = int(maxScore)
	result.summary.UniqueSourceIPs = int64(uniqueIPs)
	result.summary.UniqueCountries = int64(uniqueCountries)
	if total > 0 {
		result.summary.BlockRate = float64(blocked) / float64(total) * 100
		result.summary.DetectionRate = float64(blocked+detected) / float64(total) * 100
	}
	result.summary.AvgLatencyMs = finiteFloat(result.summary.AvgLatencyMs)
	result.summary.P95LatencyMs = finiteFloat(result.summary.P95LatencyMs)
	result.summary.AvgAnomalyScore = finiteFloat(result.summary.AvgAnomalyScore)

	result.coverage.RequestInspectedCount = int64(total)
	result.coverage.ResponseInspectedCount = int64(responseInspected)
	result.coverage.PartialResponseCount = int64(partialResponses)
	result.coverage.TruncatedRequestCount = int64(truncatedRequests)
	result.coverage.TruncatedResponseCount = int64(truncatedResponses)
	if total > 0 {
		result.coverage.TruncatedRequestRate = float64(truncatedRequests) / float64(total) * 100
		result.coverage.TruncatedResponseRate = float64(truncatedResponses) / float64(total) * 100
	}
	result.health = wafAnalyticsHealthFromLastEvent(total, lastSeen)
	result.coverage.DroppedEvents = result.health.DroppedEvents
	result.coverage.FreshnessStatus = result.health.FreshnessStatus
	result.coverage.Message = result.health.Message
	return result, nil
}

func wafAnalyticsHealthFromLastEvent(total uint64, lastSeen uint32) WAFAnalyticsHealth {
	health := WAFAnalyticsHealth{
		DBAvailable:     DB != nil,
		DroppedEvents:   WAFDroppedEvents(),
		FreshnessStatus: "empty",
		Message:         "No WAF analytics events have been recorded yet",
	}
	if total == 0 || lastSeen == 0 {
		return health
	}
	health.LastEventTimestamp = int64(lastSeen)
	health.IngestionLagSeconds = int64(time.Since(time.Unix(int64(lastSeen), 0).UTC()).Seconds())
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

func getWAFDashboardTimeseriesContext(ctx context.Context, q WAFAnalyticsQuery) ([]WAFTimeseriesPoint, error) {
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
	p95Expression := "COALESCE(quantile(0.95)(latency_ms), 0)"
	wafDashboardQueryExecutions.Add(1)
	rows, err := DB.QueryContext(ctx, `
		SELECT
			toUnixTimestamp(bucket),
			action,
			COUNT(*),
			COALESCE(AVG(latency_ms), 0),
			`+p95Expression+`,
			COALESCE(AVG(score), 0)
		FROM (
			SELECT
				`+wafDashboardBucketExpression(interval)+` AS bucket,
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
		point.AvgLatencyMs = finiteFloat(avgLatency)
		point.P95LatencyMs = finiteFloat(p95Latency)
		point.AvgAnomalyScore = finiteFloat(avgScore)
	}
	if err := rows.Err(); err != nil {
		return nil, err
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

func wafDashboardBucketExpression(interval string) string {
	return bucketExpression(interval)
}

type wafDashboardBreakdownSpec struct {
	dimension string
	key       string
	label     string
	rawArray  bool
	limit     int
}

type wafBreakdownAccumulator struct {
	item         WAFBreakdownItem
	scoreTotal   float64
	latencyTotal float64
}

func getWAFDashboardBreakdownsContext(ctx context.Context, q WAFAnalyticsQuery) (map[string][]WAFBreakdownItem, error) {
	out := make(map[string][]WAFBreakdownItem)
	for _, dimension := range wafDashboardBreakdownDimensions {
		out[dimension] = []WAFBreakdownItem{}
	}
	out["anomaly_score_bands"] = []WAFBreakdownItem{}
	out["matched_fields"] = []WAFBreakdownItem{}
	if DB == nil {
		return out, nil
	}
	where, whereArgs, err := buildWAFAnalyticsWhere(q)
	if err != nil {
		return nil, err
	}
	limit := NormalizeWAFLimit(q.Limit, 10, 100)
	specs := []wafDashboardBreakdownSpec{
		{dimension: "actions", key: normalizedActionSQL(), label: normalizedActionSQL(), limit: limit},
		{dimension: "countries", key: "country", label: "country", limit: limit},
		{dimension: "ips", key: "client_ip", label: "client_ip", limit: limit},
		{dimension: "paths", key: "path", label: "path", limit: limit},
		{dimension: "hosts", key: "JSONExtractString(metadata, 'host')", label: "JSONExtractString(metadata, 'host')", limit: limit},
		{dimension: "methods", key: "method", label: "method", limit: limit},
		{dimension: "status", key: "toString(status_code)", label: "toString(status_code)", limit: limit},
		{dimension: "user_agent_families", key: "CASE WHEN user_agent = '' THEN 'Unknown' ELSE user_agent END", label: "CASE WHEN user_agent = '' THEN 'Unknown' ELSE user_agent END", limit: limit},
		{dimension: "user_agents", key: "CASE WHEN user_agent = '' THEN 'Unknown' ELSE user_agent END", label: "CASE WHEN user_agent = '' THEN 'Unknown' ELSE user_agent END", limit: limit},
		{dimension: "rules", key: "rule_id", label: "rule_name", limit: limit},
		{dimension: "categories_raw", key: "JSONExtractString(metadata, 'categories')", label: "JSONExtractString(metadata, 'categories')", rawArray: true, limit: 1000},
		{dimension: "severities_raw", key: "JSONExtractString(metadata, 'severities')", label: "JSONExtractString(metadata, 'severities')", rawArray: true, limit: 1000},
		{dimension: "matched_fields_raw", key: "JSONExtractString(metadata, 'matched_fields')", label: "JSONExtractString(metadata, 'matched_fields')", rawArray: true, limit: 1000},
		{dimension: "anomaly_score_bands", key: wafAnomalyScoreBandExpression(), label: wafAnomalyScoreBandExpression(), limit: limit},
	}

	branches := make([]string, 0, len(specs))
	args := make([]any, 0, len(specs)*(len(whereArgs)+1))
	for _, spec := range specs {
		keyExpression := "COALESCE(" + spec.key + ", '')"
		labelExpression := "COALESCE(" + spec.label + ", '')"
		branches = append(branches, `
			SELECT * FROM (
				SELECT
					'`+spec.dimension+`' AS dimension,
					`+keyExpression+` AS item_key,
					`+labelExpression+` AS item_label,
					COUNT(*) AS item_count,
					COALESCE(SUM(CASE WHEN `+normalizedActionSQL()+` = 'block' THEN 1 ELSE 0 END), 0) AS blocked,
					COALESCE(SUM(CASE WHEN `+normalizedActionSQL()+` = 'detect' THEN 1 ELSE 0 END), 0) AS detected,
					MAX(timestamp) AS last_seen,
					COALESCE(AVG(score), 0) AS avg_score,
					COALESCE(AVG(latency_ms), 0) AS avg_latency,
					SUM(COUNT(*)) OVER () AS dimension_total
				FROM section_events `+where+`
				GROUP BY item_key, item_label
				ORDER BY item_count DESC
				LIMIT ?
			)`)
		args = append(args, whereArgs...)
		args = append(args, spec.limit)
	}
	query := `
		SELECT dimension, item_key, item_label, item_count, blocked, detected,
		       COALESCE(toUnixTimestamp(last_seen), 0), avg_score, avg_latency, dimension_total
		FROM (` + strings.Join(branches, "\nUNION ALL\n") + `)
		ORDER BY dimension ASC, item_count DESC`
	wafDashboardQueryExecutions.Add(1)
	rows, err := DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accumulators := make(map[string]map[string]*wafBreakdownAccumulator)
	dimensionTotals := make(map[string]int64)
	for rows.Next() {
		var dimension, key, label string
		var count, blocked, detected, lastSeen, dimensionTotal int64
		var avgScore, avgLatency float64
		if err := rows.Scan(&dimension, &key, &label, &count, &blocked, &detected, &lastSeen, &avgScore, &avgLatency, &dimensionTotal); err != nil {
			return nil, err
		}
		keys := []string{strings.TrimSpace(key)}
		targetDimension := dimension
		rawArray := false
		switch dimension {
		case "categories_raw":
			targetDimension = "categories"
			rawArray = true
		case "severities_raw":
			targetDimension = "severities"
			rawArray = true
		case "matched_fields_raw":
			targetDimension = "matched_fields"
			rawArray = true
		}
		if rawArray {
			keys = parseStringJSONArray(key)
			dimensionTotals[targetDimension] += count * int64(len(keys))
		} else if dimensionTotal > dimensionTotals[targetDimension] {
			dimensionTotals[targetDimension] = dimensionTotal
		}
		if accumulators[targetDimension] == nil {
			accumulators[targetDimension] = make(map[string]*wafBreakdownAccumulator)
		}
		for _, itemKey := range keys {
			itemKey = strings.TrimSpace(itemKey)
			if rawArray {
				itemKey = strings.ToLower(itemKey)
			}
			if itemKey == "" {
				continue
			}
			itemLabel := label
			if rawArray {
				itemLabel = formatWAFBreakdownLabel(targetDimension, itemKey)
			} else if strings.TrimSpace(itemLabel) == "" {
				itemLabel = itemKey
			}
			accumulator := accumulators[targetDimension][itemKey]
			if accumulator == nil {
				accumulator = &wafBreakdownAccumulator{
					item: WAFBreakdownItem{Key: itemKey, Label: itemLabel},
				}
				accumulators[targetDimension][itemKey] = accumulator
			}
			accumulator.item.Count += count
			accumulator.item.Blocked += blocked
			accumulator.item.Detected += detected
			if lastSeen > accumulator.item.LastSeen {
				accumulator.item.LastSeen = lastSeen
			}
			accumulator.scoreTotal += avgScore * float64(count)
			accumulator.latencyTotal += avgLatency * float64(count)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for dimension, byKey := range accumulators {
		items := make([]WAFBreakdownItem, 0, len(byKey))
		for _, accumulator := range byKey {
			item := accumulator.item
			if item.Count > 0 {
				item.BlockRate = float64(item.Blocked) / float64(item.Count) * 100
				item.AvgScore = finiteFloat(accumulator.scoreTotal / float64(item.Count))
				item.AvgLatencyMs = finiteFloat(accumulator.latencyTotal / float64(item.Count))
			}
			if total := dimensionTotals[dimension]; total > 0 {
				item.Percent = float64(item.Count) / float64(total) * 100
			}
			items = append(items, item)
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Count == items[j].Count {
				return items[i].Key < items[j].Key
			}
			return items[i].Count > items[j].Count
		})
		finalLimit := limit
		if dimension == "matched_fields" {
			finalLimit = NormalizeWAFLimit(q.Limit, 10, 100)
		}
		if len(items) > finalLimit {
			items = items[:finalLimit]
		}
		out[dimension] = items
	}
	return out, nil
}

func wafAnomalyScoreBandExpression() string {
	return "CASE WHEN score <= 0 THEN '0' WHEN score <= 4 THEN '1-4' WHEN score <= 9 THEN '5-9' WHEN score <= 19 THEN '10-19' ELSE '20+' END"
}

func getWAFDashboardEventsContext(ctx context.Context, q WAFAnalyticsQuery) (WAFAnalyticsEventsPage, error) {
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
	wafDashboardQueryExecutions.Add(1)
	rows, err := DB.QueryContext(ctx, `
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
