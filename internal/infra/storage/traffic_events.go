package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TrafficEventsQuery struct {
	Window      string
	Interval    string
	Since       string
	Until       string
	Status      string
	StatusClass string
	IP          string
	Country     string
	Method      string
	Host        string
	Path        string
	UserAgent   string
	JA3         string
	JA4         string
	ASN         string
	Route       string
	Upstream    string
	HTTPVersion string
	TLSVersion  string
	IPVersion   string
	ContentType string
	RequestID   string
	Limit       int
	Cursor      string
	Sort        string
}

type TrafficEventsSummary struct {
	TotalRequests   int64   `json:"total_requests"`
	Status2xx       int64   `json:"status_2xx"`
	Status3xx       int64   `json:"status_3xx"`
	Status4xx       int64   `json:"status_4xx"`
	Status5xx       int64   `json:"status_5xx"`
	Status403       int64   `json:"status_403"`
	Status404       int64   `json:"status_404"`
	Status500       int64   `json:"status_500"`
	AvgLatencyMs    float64 `json:"avg_latency_ms"`
	P95LatencyMs    float64 `json:"p95_latency_ms"`
	UniqueSourceIPs int64   `json:"unique_source_ips"`
	UniqueCountries int64   `json:"unique_countries"`
	TotalBytesSent  int64   `json:"total_bytes_sent"`
	LastEventTs     int64   `json:"last_event_timestamp"`
	CurrentRPS      float64 `json:"current_rps"`
	DroppedEvents   int64   `json:"dropped_events"`
	Window          string  `json:"window"`
}

type TrafficEventsTimeseriesPoint struct {
	Timestamp    int64            `json:"timestamp"`
	Counts       map[string]int64 `json:"counts"`
	AvgLatencyMs float64          `json:"avg_latency_ms"`
	P95LatencyMs float64          `json:"p95_latency_ms"`
}

type TrafficEventsBreakdownItem struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	Count        int64   `json:"count"`
	ErrorCount   int64   `json:"error_count"`
	DeniedCount  int64   `json:"denied_count"`
	Percent      float64 `json:"percent"`
	LastSeen     int64   `json:"last_seen"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

type TrafficEventsMapItem struct {
	Country     string  `json:"country"`
	Count       int64   `json:"count"`
	ErrorCount  int64   `json:"error_count"`
	DeniedCount int64   `json:"denied_count"`
	Percent     float64 `json:"percent"`
}

type TrafficEventsEvent struct {
	ID                  string            `json:"id"`
	Timestamp           int64             `json:"timestamp"`
	ClientIP            string            `json:"client_ip"`
	Country             string            `json:"country"`
	Host                string            `json:"host"`
	Method              string            `json:"method"`
	Path                string            `json:"path"`
	StatusCode          int               `json:"status_code"`
	StatusClass         string            `json:"status_class"`
	Action              string            `json:"action"`
	UserAgent           string            `json:"user_agent"`
	UserAgentFamily     string            `json:"user_agent_family"`
	LatencyMs           int64             `json:"latency_ms"`
	RequestID           string            `json:"request_id"`
	Upstream            string            `json:"upstream,omitempty"`
	RouteName           string            `json:"route_name,omitempty"`
	BytesSent           int64             `json:"bytes_sent,omitempty"`
	ASN                 string            `json:"asn,omitempty"`
	ASNOrg              string            `json:"asn_org,omitempty"`
	JA3                 string            `json:"ja3,omitempty"`
	JA4                 string            `json:"ja4,omitempty"`
	HTTPVersion         string            `json:"http_version,omitempty"`
	TLSVersion          string            `json:"tls_version,omitempty"`
	IPVersion           string            `json:"ip_version,omitempty"`
	ResponseContentType string            `json:"response_content_type,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

type TrafficEventsPage struct {
	Events     []TrafficEventsEvent `json:"events"`
	NextCursor string               `json:"next_cursor,omitempty"`
	Count      int                  `json:"count"`
}

type TrafficEventsDashboard struct {
	Summary    TrafficEventsSummary                    `json:"summary"`
	Timeseries []TrafficEventsTimeseriesPoint          `json:"timeseries"`
	Breakdowns map[string][]TrafficEventsBreakdownItem `json:"breakdowns"`
	Map        []TrafficEventsMapItem                  `json:"map"`
	Events     TrafficEventsPage                       `json:"events"`
	Health     TrafficAnalyticsHealth                  `json:"health"`
	Warnings   []string                                `json:"warnings"`
}

var trafficEventsDashboardBreakdownDimensions = []string{
	"ips", "hosts", "routes", "upstreams", "paths", "methods", "http_versions", "status", "content_types", "user_agents", "countries", "ip_versions", "ja3", "ja4", "tls_versions", "asn",
}

func GetTrafficEventsDashboard(q TrafficEventsQuery) (TrafficEventsDashboard, error) {
	return GetTrafficEventsDashboardContext(context.Background(), q)
}

// GetTrafficEventsDashboardContext executes the dashboard's independent reads
// concurrently. The breakdowns share a single ClickHouse statement so a cold
// dashboard uses six database round trips instead of fifteen.
func GetTrafficEventsDashboardContext(ctx context.Context, q TrafficEventsQuery) (TrafficEventsDashboard, error) {
	dashboard := emptyTrafficEventsDashboard()
	if err := ctx.Err(); err != nil {
		return dashboard, err
	}
	if _, _, err := buildTrafficEventsWhere(q); err != nil {
		return dashboard, err
	}
	if _, err := ResolveWAFAnalyticsInterval(q.Window, q.Interval); err != nil {
		return dashboard, err
	}
	if DB == nil {
		return dashboard, nil
	}

	var (
		summary       TrafficEventsSummary
		timeseries    []TrafficEventsTimeseriesPoint
		breakdowns    map[string][]TrafficEventsBreakdownItem
		mapItems      []TrafficEventsMapItem
		events        TrafficEventsPage
		health        TrafficAnalyticsHealth
		summaryErr    error
		timeseriesErr error
		breakdownsErr error
		mapErr        error
		eventsErr     error
	)

	var wait sync.WaitGroup
	wait.Add(6)
	go func() {
		defer wait.Done()
		summary, summaryErr = getTrafficEventsSummaryContext(ctx, q)
	}()
	go func() {
		defer wait.Done()
		timeseries, timeseriesErr = getTrafficEventsTimeseriesContext(ctx, q)
	}()
	go func() {
		defer wait.Done()
		breakdowns, breakdownsErr = getTrafficEventsDashboardBreakdownsContext(ctx, q)
	}()
	go func() {
		defer wait.Done()
		mapItems, mapErr = getTrafficEventsMapContext(ctx, q)
	}()
	go func() {
		defer wait.Done()
		events, eventsErr = getTrafficEventsContext(ctx, q)
	}()
	go func() {
		defer wait.Done()
		health = getTrafficEventsHealthContext(ctx)
	}()
	wait.Wait()

	if err := ctx.Err(); err != nil {
		return dashboard, err
	}
	if summaryErr != nil {
		dashboard.Warnings = append(dashboard.Warnings, "summary unavailable")
	} else {
		dashboard.Summary = summary
	}
	if timeseriesErr != nil {
		dashboard.Warnings = append(dashboard.Warnings, "timeseries unavailable")
	} else {
		dashboard.Timeseries = timeseries
	}
	if breakdownsErr != nil {
		dashboard.Warnings = append(dashboard.Warnings, "breakdowns unavailable")
	} else {
		dashboard.Breakdowns = breakdowns
	}
	if mapErr != nil {
		dashboard.Warnings = append(dashboard.Warnings, "map unavailable")
	} else {
		dashboard.Map = mapItems
	}
	if eventsErr != nil {
		dashboard.Warnings = append(dashboard.Warnings, "events unavailable")
	} else {
		dashboard.Events = events
	}
	dashboard.Health = health
	return dashboard, nil
}

func emptyTrafficEventsDashboard() TrafficEventsDashboard {
	dashboard := TrafficEventsDashboard{
		Timeseries: []TrafficEventsTimeseriesPoint{},
		Breakdowns: map[string][]TrafficEventsBreakdownItem{},
		Map:        []TrafficEventsMapItem{},
		Events:     TrafficEventsPage{Events: []TrafficEventsEvent{}},
		Warnings:   []string{},
	}
	for _, dimension := range trafficEventsDashboardBreakdownDimensions {
		dashboard.Breakdowns[dimension] = []TrafficEventsBreakdownItem{}
	}
	return dashboard
}

func GetTrafficEventsSummary(q TrafficEventsQuery) (TrafficEventsSummary, error) {
	return getTrafficEventsSummaryContext(context.Background(), q)
}

func getTrafficEventsSummaryContext(ctx context.Context, q TrafficEventsQuery) (TrafficEventsSummary, error) {
	summary := TrafficEventsSummary{Window: defaultWindow(q.Window), DroppedEvents: DroppedEvents()}
	if DB == nil {
		return summary, nil
	}
	where, args, err := buildTrafficEventsWhere(q)
	if err != nil {
		return summary, err
	}
	args = append([]any{time.Now().UTC().Add(-time.Minute)}, args...)
	row := DB.QueryRowContext(ctx, `
		SELECT
			count(),
			COALESCE(sum(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END), 0),
			COALESCE(sum(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END), 0),
			COALESCE(sum(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END), 0),
			COALESCE(sum(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END), 0),
			COALESCE(sum(CASE WHEN status_code = 403 THEN 1 ELSE 0 END), 0),
			COALESCE(sum(CASE WHEN status_code = 404 THEN 1 ELSE 0 END), 0),
			COALESCE(sum(CASE WHEN status_code = 500 THEN 1 ELSE 0 END), 0),
			COALESCE(avg(latency_ms), 0),
			COALESCE(quantile(0.95)(latency_ms), 0),
			count(DISTINCT client_ip),
			count(DISTINCT CASE WHEN country != '' THEN country END),
			COALESCE(sum(toInt64OrZero(JSONExtractString(metadata, 'bytes_sent'))), 0),
			COALESCE(toUnixTimestamp(max(timestamp)), 0),
			(SELECT count() FROM section_events WHERE section = 'traffic' AND timestamp >= ?)
		FROM section_events `+where, args...)
	var total, s2, s3, s4, s5, s403, s404, s500, uniqueIPs, uniqueCountries, totalBytes uint64
	var currentRPSCount uint64
	var lastEvent uint32
	if err := row.Scan(&total, &s2, &s3, &s4, &s5, &s403, &s404, &s500, &summary.AvgLatencyMs, &summary.P95LatencyMs, &uniqueIPs, &uniqueCountries, &totalBytes, &lastEvent, &currentRPSCount); err != nil {
		return summary, err
	}
	summary.TotalRequests = int64(total)
	summary.Status2xx = int64(s2)
	summary.Status3xx = int64(s3)
	summary.Status4xx = int64(s4)
	summary.Status5xx = int64(s5)
	summary.Status403 = int64(s403)
	summary.Status404 = int64(s404)
	summary.Status500 = int64(s500)
	summary.UniqueSourceIPs = int64(uniqueIPs)
	summary.UniqueCountries = int64(uniqueCountries)
	summary.TotalBytesSent = int64(totalBytes)
	summary.LastEventTs = int64(lastEvent)
	summary.AvgLatencyMs = finiteFloat(summary.AvgLatencyMs)
	summary.P95LatencyMs = finiteFloat(summary.P95LatencyMs)
	summary.CurrentRPS = float64(currentRPSCount) / 60.0
	return summary, nil
}

func GetTrafficEventsTimeseries(q TrafficEventsQuery) ([]TrafficEventsTimeseriesPoint, error) {
	return getTrafficEventsTimeseriesContext(context.Background(), q)
}

func getTrafficEventsTimeseriesContext(ctx context.Context, q TrafficEventsQuery) ([]TrafficEventsTimeseriesPoint, error) {
	if DB == nil {
		return []TrafficEventsTimeseriesPoint{}, nil
	}
	where, args, err := buildTrafficEventsWhere(q)
	if err != nil {
		return nil, err
	}
	interval, err := ResolveWAFAnalyticsInterval(q.Window, q.Interval)
	if err != nil {
		return nil, err
	}
	rows, err := DB.QueryContext(ctx, `
		SELECT toUnixTimestamp(bucket), status_class, count(), COALESCE(avg(latency_ms), 0), COALESCE(quantile(0.95)(latency_ms), 0)
		FROM (
			SELECT `+bucketExpression(interval)+` AS bucket, `+trafficStatusClassSQL()+` AS status_class, latency_ms
			FROM section_events `+where+`
		)
		GROUP BY bucket, status_class
		ORDER BY bucket ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byBucket := map[int64]*TrafficEventsTimeseriesPoint{}
	for rows.Next() {
		var ts uint32
		var class string
		var count uint64
		var avgLatency, p95Latency float64
		if err := rows.Scan(&ts, &class, &count, &avgLatency, &p95Latency); err != nil {
			return nil, err
		}
		key := int64(ts)
		point := byBucket[key]
		if point == nil {
			point = &TrafficEventsTimeseriesPoint{Timestamp: key, Counts: map[string]int64{}}
			byBucket[key] = point
		}
		point.Counts[class] = int64(count)
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
	out := make([]TrafficEventsTimeseriesPoint, 0, len(keys))
	for _, key := range keys {
		out = append(out, *byBucket[key])
	}
	return out, nil
}

func GetTrafficEventsBreakdown(q TrafficEventsQuery, dimension string) ([]TrafficEventsBreakdownItem, error) {
	return getTrafficEventsBreakdownContext(context.Background(), q, dimension)
}

func getTrafficEventsBreakdownContext(ctx context.Context, q TrafficEventsQuery, dimension string) ([]TrafficEventsBreakdownItem, error) {
	dimension = strings.ToLower(strings.TrimSpace(dimension))
	expr, labelExpr, err := trafficEventsBreakdownExpression(dimension)
	if err != nil {
		return nil, err
	}
	if DB == nil {
		return []TrafficEventsBreakdownItem{}, nil
	}
	where, args, err := buildTrafficEventsWhere(q)
	if err != nil {
		return nil, err
	}
	limit := NormalizeWAFLimit(q.Limit, 10, 100)
	args = append(args, limit)
	rows, err := DB.QueryContext(ctx, fmt.Sprintf(`
		SELECT %s AS key, %s AS label, count(), COALESCE(sum(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0), COALESCE(sum(CASE WHEN status_code = 403 THEN 1 ELSE 0 END), 0), COALESCE(toUnixTimestamp(max(timestamp)), 0), COALESCE(avg(latency_ms), 0)
		FROM section_events %s AND %s != ''
		GROUP BY key, label
		ORDER BY count() DESC
		LIMIT ?`, expr, labelExpr, where, expr), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]TrafficEventsBreakdownItem, 0, limit)
	var total int64
	for rows.Next() {
		var item TrafficEventsBreakdownItem
		var count, errors, denied uint64
		var lastSeen uint32
		if err := rows.Scan(&item.Key, &item.Label, &count, &errors, &denied, &lastSeen, &item.AvgLatencyMs); err != nil {
			return nil, err
		}
		item.Count = int64(count)
		item.ErrorCount = int64(errors)
		item.DeniedCount = int64(denied)
		item.LastSeen = int64(lastSeen)
		item.AvgLatencyMs = finiteFloat(item.AvgLatencyMs)
		item.Label = formatTrafficEventsBreakdownLabel(dimension, item.Label)
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

// getTrafficEventsDashboardBreakdownsContext folds the dashboard's fixed
// breakdown set into one ClickHouse request. Individual breakdown endpoints
// intentionally retain their single-dimension query path above.
func getTrafficEventsDashboardBreakdownsContext(ctx context.Context, q TrafficEventsQuery) (map[string][]TrafficEventsBreakdownItem, error) {
	out := make(map[string][]TrafficEventsBreakdownItem, len(trafficEventsDashboardBreakdownDimensions))
	for _, dimension := range trafficEventsDashboardBreakdownDimensions {
		out[dimension] = []TrafficEventsBreakdownItem{}
	}
	if DB == nil {
		return out, nil
	}
	where, whereArgs, err := buildTrafficEventsWhere(q)
	if err != nil {
		return nil, err
	}
	limit := NormalizeWAFLimit(q.Limit, 10, 100)
	branches := make([]string, 0, len(trafficEventsDashboardBreakdownDimensions))
	args := make([]any, 0, len(trafficEventsDashboardBreakdownDimensions)*(len(whereArgs)+1))
	for _, dimension := range trafficEventsDashboardBreakdownDimensions {
		expr, labelExpr, err := trafficEventsBreakdownExpression(dimension)
		if err != nil {
			return nil, err
		}
		branches = append(branches, fmt.Sprintf(`
			SELECT * FROM (
				SELECT
					'%s' AS dimension,
					%s AS item_key,
					%s AS item_label,
					count() AS item_count,
					COALESCE(sum(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0) AS error_count,
					COALESCE(sum(CASE WHEN status_code = 403 THEN 1 ELSE 0 END), 0) AS denied_count,
					COALESCE(toUnixTimestamp(max(timestamp)), 0) AS last_seen,
					COALESCE(avg(latency_ms), 0) AS avg_latency
				FROM section_events %s AND %s != ''
				GROUP BY item_key, item_label
				ORDER BY item_count DESC
				LIMIT ?
			)`, dimension, expr, labelExpr, where, expr))
		args = append(args, whereArgs...)
		args = append(args, limit)
	}
	rows, err := DB.QueryContext(ctx, `
		SELECT dimension, item_key, item_label, item_count, error_count, denied_count, last_seen, avg_latency
		FROM (`+strings.Join(branches, "\nUNION ALL\n")+`)
		ORDER BY dimension ASC, item_count DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	totals := make(map[string]int64, len(trafficEventsDashboardBreakdownDimensions))
	for rows.Next() {
		var dimension string
		var item TrafficEventsBreakdownItem
		var count, errors, denied uint64
		var lastSeen uint32
		if err := rows.Scan(&dimension, &item.Key, &item.Label, &count, &errors, &denied, &lastSeen, &item.AvgLatencyMs); err != nil {
			return nil, err
		}
		item.Count = int64(count)
		item.ErrorCount = int64(errors)
		item.DeniedCount = int64(denied)
		item.LastSeen = int64(lastSeen)
		item.AvgLatencyMs = finiteFloat(item.AvgLatencyMs)
		item.Label = formatTrafficEventsBreakdownLabel(dimension, item.Label)
		out[dimension] = append(out[dimension], item)
		totals[dimension] += item.Count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for dimension, items := range out {
		total := totals[dimension]
		if total == 0 {
			continue
		}
		for index := range items {
			items[index].Percent = float64(items[index].Count) / float64(total) * 100
		}
	}
	return out, nil
}

func GetTrafficEventsMap(q TrafficEventsQuery) ([]TrafficEventsMapItem, error) {
	return getTrafficEventsMapContext(context.Background(), q)
}

func getTrafficEventsMapContext(ctx context.Context, q TrafficEventsQuery) ([]TrafficEventsMapItem, error) {
	if DB == nil {
		return []TrafficEventsMapItem{}, nil
	}
	where, args, err := buildTrafficEventsWhere(q)
	if err != nil {
		return nil, err
	}
	rows, err := DB.QueryContext(ctx, `
		SELECT country, count(), COALESCE(sum(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0), COALESCE(sum(CASE WHEN status_code = 403 THEN 1 ELSE 0 END), 0)
		FROM section_events `+where+` AND country != ''
		GROUP BY country
		ORDER BY count() DESC
		LIMIT 80`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []TrafficEventsMapItem{}
	var total int64
	for rows.Next() {
		var item TrafficEventsMapItem
		var count, errors, denied uint64
		if err := rows.Scan(&item.Country, &count, &errors, &denied); err != nil {
			return nil, err
		}
		item.Count = int64(count)
		item.ErrorCount = int64(errors)
		item.DeniedCount = int64(denied)
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

func GetTrafficEvents(q TrafficEventsQuery) (TrafficEventsPage, error) {
	return getTrafficEventsContext(context.Background(), q)
}

func getTrafficEventsContext(ctx context.Context, q TrafficEventsQuery) (TrafficEventsPage, error) {
	page := TrafficEventsPage{Events: []TrafficEventsEvent{}}
	if DB == nil {
		return page, nil
	}
	limit := NormalizeWAFLimit(q.Limit, 50, 500)
	q.Limit = limit + 1
	where, args, err := buildTrafficEventsWhere(q)
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
	rows, err := DB.QueryContext(ctx, `
		SELECT id, toUnixTimestamp(timestamp), client_ip, country, JSONExtractString(metadata, 'host'), method, path, status_code,
		       `+trafficStatusClassSQL()+`, action, user_agent, user_agent_family, latency_ms, request_id, metadata
		FROM section_events `+where+`
		ORDER BY timestamp `+order+`
		LIMIT ?`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		event, err := scanTrafficEventsEvent(rows)
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

func GetTrafficEventsHealth() TrafficAnalyticsHealth {
	return getTrafficEventsHealthContext(context.Background())
}

func getTrafficEventsHealthContext(ctx context.Context) TrafficAnalyticsHealth {
	health := TrafficAnalyticsHealth{DBAvailable: DB != nil, DroppedEvents: DroppedEvents(), FreshnessStatus: "unavailable", Message: ""}
	if DB == nil {
		return health
	}
	health.Message = "No Traffic Events have been recorded yet"
	var count uint64
	var last uint32
	err := DB.QueryRowContext(ctx, `SELECT count(), toUnixTimestamp(max(timestamp)) FROM section_events WHERE section = 'traffic'`).Scan(&count, &last)
	if err != nil {
		health.Message = "Unable to read Traffic Events freshness"
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
		health.Message = "Traffic Events are current"
	case health.IngestionLagSeconds <= 900:
		health.FreshnessStatus = "delayed"
		health.Message = "Traffic Events are slightly delayed"
	default:
		health.FreshnessStatus = "stale"
		health.Message = "Traffic Events have not received recent requests"
	}
	return health
}

func buildTrafficEventsWhere(q TrafficEventsQuery) (string, []any, error) {
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
	clauses := []string{"section = 'traffic'", "timestamp >= ?"}
	args := []any{since}
	add := func(clause string, value any) {
		clauses = append(clauses, clause)
		args = append(args, value)
	}
	if q.Status != "" {
		status, err := strconv.Atoi(strings.TrimSpace(q.Status))
		if err != nil || status < 100 || status > 599 {
			return "", nil, fmt.Errorf("invalid status")
		}
		add("status_code = ?", status)
	}
	if q.StatusClass != "" {
		class := strings.ToLower(strings.TrimSpace(q.StatusClass))
		if !validTrafficStatusClass(class) {
			return "", nil, fmt.Errorf("invalid status_class")
		}
		add(trafficStatusClassSQL()+" = ?", class)
	}
	if q.IP != "" {
		add("client_ip = ?", strings.TrimSpace(q.IP))
	}
	if q.Country != "" {
		add("country = ?", strings.ToUpper(strings.TrimSpace(q.Country)))
	}
	if q.Method != "" {
		add("method = ?", strings.ToUpper(strings.TrimSpace(q.Method)))
	}
	if q.Host != "" {
		add("JSONExtractString(metadata, 'host') LIKE ?", "%"+strings.TrimSpace(q.Host)+"%")
	}
	if q.Path != "" {
		add("path LIKE ?", "%"+strings.TrimSpace(q.Path)+"%")
	}
	if q.UserAgent != "" {
		add("user_agent LIKE ?", "%"+strings.TrimSpace(q.UserAgent)+"%")
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
		asn := strings.TrimSpace(q.ASN)
		if index := strings.Index(asn, " - "); index >= 0 {
			asn = asn[:index]
		}
		add("JSONExtractString(metadata, 'asn') = ?", strings.ToUpper(strings.TrimSpace(asn)))
	}
	if q.Route != "" {
		add("JSONExtractString(metadata, 'route_name') = ?", strings.TrimSpace(q.Route))
	}
	if q.Upstream != "" {
		add("JSONExtractString(metadata, 'upstream') = ?", strings.TrimSpace(q.Upstream))
	}
	if q.HTTPVersion != "" {
		add("JSONExtractString(metadata, 'http_version') = ?", strings.TrimSpace(q.HTTPVersion))
	}
	if q.TLSVersion != "" {
		add("JSONExtractString(metadata, 'tls_version') = ?", strings.TrimSpace(q.TLSVersion))
	}
	if q.IPVersion != "" {
		add("JSONExtractString(metadata, 'ip_version') = ?", strings.TrimSpace(q.IPVersion))
	}
	if q.ContentType != "" {
		add("JSONExtractString(metadata, 'response_content_type') = ?", strings.ToLower(strings.TrimSpace(q.ContentType)))
	}
	if value := strings.TrimSpace(q.Until); value != "" {
		until, parseErr := time.Parse(time.RFC3339, value)
		if parseErr != nil {
			return "", nil, fmt.Errorf("invalid until")
		}
		if until.Before(since) {
			return "", nil, fmt.Errorf("invalid time range")
		}
		add("timestamp <= ?", until.UTC())
	}
	return "WHERE " + strings.Join(clauses, " AND "), args, nil
}

func trafficEventsBreakdownExpression(dimension string) (string, string, error) {
	switch dimension {
	case "countries":
		return "country", "country", nil
	case "ips":
		return "client_ip", "client_ip", nil
	case "hosts":
		expr := "JSONExtractString(metadata, 'host')"
		return expr, expr, nil
	case "routes":
		expr := "JSONExtractString(metadata, 'route_name')"
		return expr, expr, nil
	case "upstreams":
		expr := "JSONExtractString(metadata, 'upstream')"
		return expr, expr, nil
	case "http_versions":
		expr := "JSONExtractString(metadata, 'http_version')"
		return expr, expr, nil
	case "tls_versions":
		expr := "JSONExtractString(metadata, 'tls_version')"
		return expr, expr, nil
	case "ip_versions":
		expr := "JSONExtractString(metadata, 'ip_version')"
		return expr, expr, nil
	case "content_types":
		expr := "JSONExtractString(metadata, 'response_content_type')"
		return expr, expr, nil
	case "paths":
		return "path", "path", nil
	case "methods":
		return "method", "method", nil
	case "status":
		expr := "toString(status_code)"
		return expr, expr, nil
	case "status_class":
		expr := trafficStatusClassSQL()
		return expr, expr, nil
	case "user_agents":
		return "user_agent", "user_agent", nil
	case "user_agent_families":
		return "user_agent_family", "user_agent_family", nil
	case "ja3":
		expr := "JSONExtractString(metadata, 'ja3')"
		return expr, expr, nil
	case "ja4":
		expr := "JSONExtractString(metadata, 'ja4')"
		return expr, expr, nil
	case "asn":
		expr := "JSONExtractString(metadata, 'asn')"
		label := "if(JSONExtractString(metadata, 'asn_org') = '', " + expr + ", concat(" + expr + ", ' - ', JSONExtractString(metadata, 'asn_org')))"
		return expr, label, nil
	default:
		return "", "", fmt.Errorf("unsupported breakdown dimension %q", dimension)
	}
}

func trafficStatusClassSQL() string {
	return "CASE WHEN status_code >= 200 AND status_code < 300 THEN '2xx' WHEN status_code >= 300 AND status_code < 400 THEN '3xx' WHEN status_code >= 400 AND status_code < 500 THEN '4xx' WHEN status_code >= 500 AND status_code < 600 THEN '5xx' ELSE 'other' END"
}

func validTrafficStatusClass(class string) bool {
	switch class {
	case "2xx", "3xx", "4xx", "5xx":
		return true
	default:
		return false
	}
}

func scanTrafficEventsEvent(row sqlScanner) (TrafficEventsEvent, error) {
	var event TrafficEventsEvent
	var ts uint32
	var status uint16
	var metadata string
	if err := row.Scan(&event.ID, &ts, &event.ClientIP, &event.Country, &event.Host, &event.Method, &event.Path, &status, &event.StatusClass, &event.Action, &event.UserAgent, &event.UserAgentFamily, &event.LatencyMs, &event.RequestID, &metadata); err != nil {
		return event, err
	}
	event.Timestamp = int64(ts)
	event.StatusCode = int(status)
	applyTrafficEventsMetadata(&event, metadata)
	return event, nil
}

func applyTrafficEventsMetadata(event *TrafficEventsEvent, raw string) {
	var meta map[string]string
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return
	}
	event.Metadata = meta
	event.Upstream = meta["upstream"]
	event.RouteName = meta["route_name"]
	event.ASN = firstMetadataValue(meta, "asn")
	event.ASNOrg = firstMetadataValue(meta, "asn_org")
	event.JA3 = firstMetadataValue(meta, "ja3", "tls_ja3")
	event.JA4 = firstMetadataValue(meta, "ja4", "tls_ja4")
	event.HTTPVersion = firstMetadataValue(meta, "http_version")
	event.TLSVersion = firstMetadataValue(meta, "tls_version")
	event.IPVersion = firstMetadataValue(meta, "ip_version")
	event.ResponseContentType = firstMetadataValue(meta, "response_content_type")
	if event.Host == "" {
		event.Host = meta["host"]
	}
	if bytesSent, err := strconv.ParseInt(meta["bytes_sent"], 10, 64); err == nil {
		event.BytesSent = bytesSent
	}
}

func formatTrafficEventsBreakdownLabel(dimension, value string) string {
	if value == "" {
		return value
	}
	if dimension == "status_class" {
		switch value {
		case "2xx":
			return "2xx Success"
		case "3xx":
			return "3xx Redirect"
		case "4xx":
			return "4xx Client Error"
		case "5xx":
			return "5xx Server Error"
		}
	}
	if dimension == "countries" || dimension == "methods" {
		return strings.ToUpper(value)
	}
	return value
}
