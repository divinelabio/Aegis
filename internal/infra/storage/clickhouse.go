package storage

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

var DB *sql.DB

const (
	BatchSize    = 500
	BatchTimeout = 1 * time.Second
)

var (
	requestLogChan        chan RequestLog
	wafLogChan            chan WAFEventLog
	sectionLogChan        chan SectionEventLog
	droppedEvents         atomic.Int64
	wafDroppedEvents      atomic.Int64
	analyticsConfigMu     sync.RWMutex
	activeAnalyticsConfig AnalyticsConfig
)

// InitAnalytics resolves the ClickHouse secret reference, initializes the
// analytics schema, and starts the bounded telemetry writers. The returned
// availability lets the caller distinguish optional degradation from an active
// analytics plane without touching PostgreSQL control state.
func InitAnalytics(config AnalyticsConfig) (available bool, err error) {
	mode := config.EffectiveMode()
	if mode == AnalyticsModeDisabled {
		return false, nil
	}
	cfg, err := config.runtimeConfig()
	if err != nil {
		return false, err
	}
	if err := initClickHouseDB(config, cfg); err != nil {
		return false, err
	}
	return true, nil
}

func initClickHouseDB(config AnalyticsConfig, cfg clickHouseRuntimeConfig) error {

	admin := clickhouse.OpenDB(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: cfg.Username,
			Password: cfg.Password,
		},
		TLS:         clickhouseTLSConfig(cfg.Secure, cfg.Host),
		DialTimeout: 10 * time.Second,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
	})
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return fmt.Errorf("clickhouse is required but unavailable: %w", err)
	}
	if _, err := admin.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", quoteIdentifier(cfg.Database))); err != nil {
		return fmt.Errorf("failed to create clickhouse database %q: %w", cfg.Database, err)
	}

	candidate := clickhouse.OpenDB(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)},
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		TLS:         clickhouseTLSConfig(cfg.Secure, cfg.Host),
		DialTimeout: 10 * time.Second,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
	})
	candidate.SetMaxOpenConns(cfg.MaxOpenConns)
	candidate.SetMaxIdleConns(cfg.MaxIdleConns)
	candidate.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	if err := candidate.Ping(); err != nil {
		_ = candidate.Close()
		return fmt.Errorf("failed to connect to clickhouse database %q: %w", cfg.Database, err)
	}
	if err := applyMigrations(candidate); err != nil {
		_ = candidate.Close()
		return err
	}
	DB = candidate
	analyticsConfigMu.Lock()
	activeAnalyticsConfig = config
	analyticsConfigMu.Unlock()

	requestLogChan = make(chan RequestLog, 10000)
	wafLogChan = make(chan WAFEventLog, 10000)
	sectionLogChan = make(chan SectionEventLog, 20000)
	go processRequestLogs()
	go processWAFLogs()
	go processSectionEvents()
	go pruneOldData()
	return nil
}

// AnalyticsConfigIsActive reports whether the active ClickHouse client was
// started from this configuration. Configuration persistence never hot-swaps
// the client, so a mismatch is a truthful restart-required signal.
func AnalyticsConfigIsActive(config AnalyticsConfig) bool {
	analyticsConfigMu.RLock()
	defer analyticsConfigMu.RUnlock()
	return DB != nil && activeAnalyticsConfig == config
}

// clickhouseTLSConfig keeps certificate hostname verification tied to the
// operator-configured endpoint whenever TLS is enabled.
func clickhouseTLSConfig(secure bool, serverName string) *tls.Config {
	if !secure {
		return nil
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: strings.TrimSpace(serverName)}
}

func quoteIdentifier(name string) string {
	out := "`"
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			out += string(r)
		}
	}
	return out + "`"
}

func applyMigrations(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version UInt32,
			name String,
			applied_at DateTime64(3, 'UTC')
		) ENGINE = MergeTree ORDER BY version`,
		`CREATE TABLE IF NOT EXISTS access_events (
			timestamp DateTime64(3, 'UTC'),
			ip String,
			path String,
			method LowCardinality(String),
			status UInt16,
			latency_ms Int64,
			user_agent String,
			referer String,
			country LowCardinality(String),
			blocked UInt8,
			rule_id String
		) ENGINE = MergeTree
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (timestamp, path, ip)`,
		`CREATE TABLE IF NOT EXISTS section_events (
			id String,
			timestamp DateTime64(3, 'UTC'),
			section LowCardinality(String),
			event_type LowCardinality(String),
			action LowCardinality(String),
			client_ip String,
			method LowCardinality(String),
			path String,
			status_code UInt16,
			latency_ms Int64,
			country LowCardinality(String),
			user_agent String,
			user_agent_family LowCardinality(String),
			rule_id String,
			rule_name String,
			rule_type LowCardinality(String),
			score Int32,
			request_id String,
			metadata String
		) ENGINE = MergeTree
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (section, timestamp, action, path)
		TTL timestamp + INTERVAL 30 DAY`,
		`CREATE TABLE IF NOT EXISTS section_event_rollups_hourly (
			bucket DateTime('UTC'),
			section LowCardinality(String),
			action LowCardinality(String),
			status_code UInt16,
			country LowCardinality(String),
			path String,
			rule_id String,
			rule_name String,
			user_agent_family LowCardinality(String),
			events UInt64,
			latency_sum Int64
		) ENGINE = SummingMergeTree
		PARTITION BY toYYYYMM(bucket)
		ORDER BY (section, bucket, action, status_code, country, path, rule_id)
		TTL bucket + INTERVAL 90 DAY`,
		`CREATE MATERIALIZED VIEW IF NOT EXISTS section_event_rollups_hourly_mv
		TO section_event_rollups_hourly AS
		SELECT
			toStartOfHour(timestamp) AS bucket,
			section,
			action,
			status_code,
			country,
			path,
			rule_id,
			rule_name,
			user_agent_family,
			count() AS events,
			sum(latency_ms) AS latency_sum
		FROM section_events
		GROUP BY bucket, section, action, status_code, country, path, rule_id, rule_name, user_agent_family`,
		`CREATE TABLE IF NOT EXISTS waf_event_rollups_hourly (
			bucket DateTime('UTC'),
			action LowCardinality(String),
			status_code UInt16,
			country LowCardinality(String),
			host String,
			path String,
			rule_id String,
			rule_name String,
			events UInt64,
			latency_sum Int64,
			score_sum Int64
		) ENGINE = SummingMergeTree
		PARTITION BY toYYYYMM(bucket)
		ORDER BY (bucket, action, country, host, path, rule_id)
		TTL bucket + INTERVAL 90 DAY`,
		`CREATE MATERIALIZED VIEW IF NOT EXISTS waf_event_rollups_hourly_mv
		TO waf_event_rollups_hourly AS
		SELECT
			toStartOfHour(timestamp) AS bucket,
			if(action = 'pass', 'allow', if(action = 'log', 'detect', action)) AS action,
			status_code,
			country,
			JSONExtractString(metadata, 'host') AS host,
			path,
			rule_id,
			rule_name,
			count() AS events,
			sum(latency_ms) AS latency_sum,
			sum(score) AS score_sum
		FROM section_events
		WHERE section = 'waf_core'
		GROUP BY bucket, action, status_code, country, host, path, rule_id, rule_name`,
		`CREATE TABLE IF NOT EXISTS waf_events (
			timestamp DateTime64(3, 'UTC'),
			ip String,
			method LowCardinality(String),
			path String,
			query_string String,
			user_agent String,
			host String,
			action LowCardinality(String),
			anomaly_score Int32,
			rule_ids String,
			rule_messages String,
			categories String,
			status_code UInt16,
			latency_ms Int64,
			request_size Int64,
			response_size Int64,
			country LowCardinality(String),
			city String
		) ENGINE = MergeTree
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (timestamp, action, ip, path)`,
		`CREATE TABLE IF NOT EXISTS security_events (
			id String,
			timestamp DateTime64(3, 'UTC'),
			rule_id String,
			rule_name String,
			rule_type LowCardinality(String),
			action LowCardinality(String),
			client_ip String,
			country LowCardinality(String),
			path String,
			method LowCardinality(String),
			user_agent String,
			score Int32,
			section LowCardinality(String),
			matched_fields String,
			response_code UInt16,
			latency_ms Int64
		) ENGINE = MergeTree
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (timestamp, section, action, client_ip)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to apply clickhouse migration: %w", err)
		}
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, name, applied_at) SELECT 1, 'initial_clickhouse_schema', now64(3) WHERE NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 1)`); err != nil {
		return fmt.Errorf("failed to record initial schema migration: %w", err)
	}
	return nil
}

func pruneOldData() {
	if DB == nil {
		return
	}
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)
	_, _ = DB.Exec("ALTER TABLE access_events DELETE WHERE timestamp < ?", cutoff)
	_, _ = DB.Exec("ALTER TABLE waf_events DELETE WHERE timestamp < ?", cutoff)
	_, _ = DB.Exec("ALTER TABLE section_events DELETE WHERE timestamp < ?", cutoff)
}

type RequestLog struct {
	Timestamp           int64
	Section             string
	IP                  string
	Host                string
	Path                string
	Method              string
	Status              int
	LatencyMs           int64
	UserAgent           string
	Referer             string
	Country             string
	Blocked             bool
	RuleID              string
	RuleName            string
	RuleType            string
	RequestID           string
	Upstream            string
	RouteName           string
	BytesSent           int64
	ASN                 string
	ASNOrg              string
	JA3                 string
	JA4                 string
	HTTPVersion         string
	TLSVersion          string
	IPVersion           string
	ResponseContentType string
}

func LogRequest(l RequestLog) {
	section := strings.TrimSpace(l.Section)
	if section == "" {
		section = "traffic"
	}
	metadata := map[string]string{}
	if l.Host != "" {
		metadata["host"] = l.Host
	}
	if l.Referer != "" {
		metadata["referer"] = l.Referer
	}
	if l.Upstream != "" {
		metadata["upstream"] = l.Upstream
	}
	if l.RouteName != "" {
		metadata["route_name"] = l.RouteName
	}
	if l.BytesSent > 0 {
		metadata["bytes_sent"] = strconv.FormatInt(l.BytesSent, 10)
	}
	if l.ASN != "" {
		metadata["asn"] = strings.ToUpper(strings.TrimSpace(l.ASN))
	}
	if l.ASNOrg != "" {
		metadata["asn_org"] = strings.TrimSpace(l.ASNOrg)
	}
	if l.JA3 != "" {
		metadata["ja3"] = strings.TrimSpace(l.JA3)
	}
	if l.JA4 != "" {
		metadata["ja4"] = strings.TrimSpace(l.JA4)
	}
	if l.HTTPVersion != "" {
		metadata["http_version"] = strings.TrimSpace(l.HTTPVersion)
	}
	if l.TLSVersion != "" {
		metadata["tls_version"] = strings.TrimSpace(l.TLSVersion)
	}
	if l.IPVersion != "" {
		metadata["ip_version"] = strings.TrimSpace(l.IPVersion)
	}
	if l.ResponseContentType != "" {
		metadata["response_content_type"] = strings.ToLower(strings.TrimSpace(l.ResponseContentType))
	}
	rawMetadata, _ := json.Marshal(metadata)
	LogSectionEvent(SectionEventLog{
		Timestamp:       l.Timestamp,
		Section:         section,
		EventType:       "http_request",
		Action:          requestAction(l.Status, l.Blocked),
		ClientIP:        l.IP,
		Method:          l.Method,
		Path:            l.Path,
		StatusCode:      l.Status,
		LatencyMs:       l.LatencyMs,
		Country:         l.Country,
		UserAgent:       l.UserAgent,
		UserAgentFamily: userAgentFamily(l.UserAgent),
		RuleID:          l.RuleID,
		RuleName:        l.RuleName,
		RuleType:        l.RuleType,
		RequestID:       l.RequestID,
		Metadata:        string(rawMetadata),
	})
}

func processRequestLogs() {
	var batch []RequestLog
	ticker := time.NewTicker(BatchTimeout)
	defer ticker.Stop()
	for {
		select {
		case l := <-requestLogChan:
			batch = append(batch, l)
			if len(batch) >= BatchSize {
				flushRequestLogs(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				flushRequestLogs(batch)
				batch = batch[:0]
			}
		}
	}
}

func flushRequestLogs(batch []RequestLog) {
	if DB == nil {
		return
	}
	tx, err := DB.Begin()
	if err != nil {
		log.Printf("Failed to begin ClickHouse request batch: %v", err)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO access_events")
	if err != nil {
		_ = tx.Rollback()
		log.Printf("Failed to prepare ClickHouse request batch: %v", err)
		return
	}
	for _, l := range batch {
		_, err = stmt.Exec(time.Unix(l.Timestamp, 0).UTC(), l.IP, l.Path, l.Method, uint16(l.Status), l.LatencyMs, l.UserAgent, l.Referer, l.Country, boolToUInt8(l.Blocked), l.RuleID)
		if err != nil {
			log.Printf("Failed to append ClickHouse request event: %v", err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit ClickHouse request batch: %v", err)
	}
}

type WAFEventLog struct {
	EventID                    string
	Timestamp                  int64
	IP                         string
	Method                     string
	Path                       string
	QueryString                string
	UserAgent                  string
	Host                       string
	Action                     string
	AnomalyScore               int
	RuleIDs                    string
	RuleMessages               string
	Categories                 string
	StatusCode                 int
	LatencyMs                  int64
	LatencyUs                  int64
	BodySpoolUs                int64
	CoreInspectionUs           int64
	AuxInspectionUs            int64
	ResponseInspectionUs       int64
	RequestSize                int64
	ResponseSize               int64
	Country                    string
	City                       string
	RequestID                  string
	Severities                 string
	MatchedFields              string
	ClientIPSource             string
	RuleSource                 string
	RuleSources                string
	PolicyID                   string
	PolicyName                 string
	RequestTruncated           bool
	ResponseInspected          bool
	ResponseInspectionCoverage string
	ResponseTruncated          bool
	ExclusionIDs               string
	ReloadID                   string
	AuxLayer                   string
	AuxCategory                string
	AuxAction                  string
	AuxRuleID                  string
	AuxConfidence              int
	BytesInspected             int64
	AuxTruncated               bool
	AuxPolicyID                string
	AuxPolicyVersion           int
	AuxRiskScore               int
	AuxEvidenceHash            string
	AuxRulePack                string
	AuxLayers                  string
	AuxSkipped                 string
	AuxFindings                int
	CustomRuleBudgetExceeded   bool
}

func LogWAFEvent(l WAFEventLog) {
	l.Action = normalizeWAFAction(l.Action)
	meta, _ := json.Marshal(sanitizedWAFMetadata(l))
	if !LogSectionEvent(SectionEventLog{
		ID:              l.EventID,
		Timestamp:       l.Timestamp,
		Section:         "waf_core",
		EventType:       "waf",
		Action:          l.Action,
		ClientIP:        l.IP,
		Method:          l.Method,
		Path:            l.Path,
		StatusCode:      l.StatusCode,
		LatencyMs:       l.LatencyMs,
		Country:         l.Country,
		UserAgent:       l.UserAgent,
		UserAgentFamily: userAgentFamily(l.UserAgent),
		RuleID:          firstJSONValue(l.RuleIDs),
		RuleName:        firstJSONValue(l.RuleMessages),
		Score:           l.AnomalyScore,
		RequestID:       l.RequestID,
		Metadata:        string(meta),
	}) {
		wafDroppedEvents.Add(1)
	}
	if wafLogChan == nil {
		return
	}
	select {
	case wafLogChan <- l:
	default:
		droppedEvents.Add(1)
	}
}

func sanitizedWAFMetadata(l WAFEventLog) map[string]string {
	meta := make(map[string]string, 12)
	add := func(key, value string) {
		if value != "" && value != "[]" {
			meta[key] = value
		}
	}
	add("query_string", l.QueryString)
	add("host", l.Host)
	add("rule_ids", l.RuleIDs)
	add("rule_messages", l.RuleMessages)
	add("categories", l.Categories)
	add("severities", l.Severities)
	add("matched_fields", l.MatchedFields)
	if l.RequestSize > 0 {
		meta["request_size"] = strconv.FormatInt(l.RequestSize, 10)
	}
	if l.ResponseSize > 0 {
		meta["response_size"] = strconv.FormatInt(l.ResponseSize, 10)
	}
	if l.LatencyUs > 0 {
		meta["latency_us"] = strconv.FormatInt(l.LatencyUs, 10)
	}
	if l.BodySpoolUs > 0 {
		meta["body_spool_us"] = strconv.FormatInt(l.BodySpoolUs, 10)
	}
	if l.CoreInspectionUs > 0 {
		meta["core_inspection_us"] = strconv.FormatInt(l.CoreInspectionUs, 10)
	}
	if l.AuxInspectionUs > 0 {
		meta["aux_inspection_us"] = strconv.FormatInt(l.AuxInspectionUs, 10)
	}
	if l.ResponseInspectionUs > 0 {
		meta["response_inspection_us"] = strconv.FormatInt(l.ResponseInspectionUs, 10)
	}
	add("city", l.City)
	add("client_ip_source", l.ClientIPSource)
	add("rule_source", l.RuleSource)
	add("rule_sources", l.RuleSources)
	add("policy_id", l.PolicyID)
	add("policy_name", l.PolicyName)
	if l.RequestTruncated {
		meta["request_truncated"] = "true"
	}
	if l.ResponseInspected {
		meta["response_inspected"] = "true"
	}
	add("response_inspection_coverage", l.ResponseInspectionCoverage)
	if l.ResponseTruncated {
		meta["response_truncated"] = "true"
	}
	add("exclusion_ids", l.ExclusionIDs)
	add("reload_id", l.ReloadID)
	add("aux_layer", l.AuxLayer)
	add("aux_category", l.AuxCategory)
	add("aux_action", l.AuxAction)
	add("aux_rule_id", l.AuxRuleID)
	if l.AuxConfidence > 0 {
		meta["aux_confidence"] = strconv.Itoa(l.AuxConfidence)
	}
	if l.BytesInspected > 0 {
		meta["bytes_inspected"] = strconv.FormatInt(l.BytesInspected, 10)
	}
	if l.AuxTruncated {
		meta["aux_truncated"] = "true"
	}
	add("aux_policy_id", l.AuxPolicyID)
	if l.AuxPolicyVersion > 0 {
		meta["aux_policy_version"] = strconv.Itoa(l.AuxPolicyVersion)
	}
	if l.AuxRiskScore > 0 {
		meta["aux_risk_score"] = strconv.Itoa(l.AuxRiskScore)
	}
	add("aux_evidence_hash", l.AuxEvidenceHash)
	add("aux_rule_pack", l.AuxRulePack)
	add("aux_layers", l.AuxLayers)
	add("aux_skipped", l.AuxSkipped)
	if l.AuxFindings > 0 {
		meta["aux_findings"] = strconv.Itoa(l.AuxFindings)
	}
	if l.CustomRuleBudgetExceeded {
		meta["custom_rule_budget_exceeded"] = "true"
	}
	return meta
}

func normalizeWAFAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "pass", "allow", "allowed":
		return "allow"
	case "block", "blocked", "deny", "denied":
		return "block"
	case "detect", "detected", "log", "logged":
		return "detect"
	case "redact", "redacted":
		return "detect"
	case "error":
		return "error"
	default:
		return "allow"
	}
}

func processWAFLogs() {
	var batch []WAFEventLog
	ticker := time.NewTicker(BatchTimeout)
	defer ticker.Stop()
	for {
		select {
		case l := <-wafLogChan:
			batch = append(batch, l)
			if len(batch) >= BatchSize {
				flushWAFLogs(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				flushWAFLogs(batch)
				batch = batch[:0]
			}
		}
	}
}

func flushWAFLogs(batch []WAFEventLog) {
	if DB == nil {
		return
	}
	tx, err := DB.Begin()
	if err != nil {
		log.Printf("Failed to begin ClickHouse WAF batch: %v", err)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO waf_events")
	if err != nil {
		_ = tx.Rollback()
		log.Printf("Failed to prepare ClickHouse WAF batch: %v", err)
		return
	}
	for _, l := range batch {
		_, err = stmt.Exec(time.Unix(l.Timestamp, 0).UTC(), l.IP, l.Method, l.Path, l.QueryString, l.UserAgent, l.Host, l.Action, int32(l.AnomalyScore), l.RuleIDs, l.RuleMessages, l.Categories, uint16(l.StatusCode), l.LatencyMs, l.RequestSize, l.ResponseSize, l.Country, l.City)
		if err != nil {
			log.Printf("Failed to append ClickHouse WAF event: %v", err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit ClickHouse WAF batch: %v", err)
	}
}

func GetBlockedRequests(limit int) ([]RequestLog, error) {
	return getSectionBlockedRequests("", limit)
}

func getSectionBlockedRequests(section string, limit int) ([]RequestLog, error) {
	if DB == nil {
		return []RequestLog{}, nil
	}
	where := "WHERE action = 'block'"
	args := []any{}
	if strings.TrimSpace(section) != "" {
		where += " AND section = ?"
		args = append(args, strings.TrimSpace(section))
	}
	args = append(args, limit)
	rows, err := DB.Query(`
		SELECT toUnixTimestamp(timestamp), client_ip, path, method, country, rule_id, user_agent
		FROM section_events
		`+where+`
		ORDER BY timestamp DESC
		LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []RequestLog
	for rows.Next() {
		var l RequestLog
		if err := rows.Scan(&l.Timestamp, &l.IP, &l.Path, &l.Method, &l.Country, &l.RuleID, &l.UserAgent); err == nil {
			l.Blocked = true
			logs = append(logs, l)
		}
	}
	return logs, rows.Err()
}

func GetTopBlockedIPs(limit int) ([]map[string]interface{}, error) {
	return topSectionBlocked("", "client_ip", "ip", limit)
}

func GetTopBlockedCountries(limit int) ([]map[string]interface{}, error) {
	return topSectionBlocked("", "country", "country", limit)
}

func topSectionBlocked(section, column, key string, limit int) ([]map[string]interface{}, error) {
	if DB == nil {
		return []map[string]interface{}{}, nil
	}
	where := fmt.Sprintf("WHERE action = 'block' AND %s != ''", column)
	args := []any{}
	if strings.TrimSpace(section) != "" {
		where += " AND section = ?"
		args = append(args, strings.TrimSpace(section))
	}
	args = append(args, limit)
	rows, err := DB.Query(fmt.Sprintf(`
		SELECT %s, count()
		FROM section_events
		%s
		GROUP BY %s
		ORDER BY count() DESC
		LIMIT ?`, column, where, column), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []map[string]interface{}
	for rows.Next() {
		var value string
		var count uint64
		if err := rows.Scan(&value, &count); err == nil {
			results = append(results, map[string]interface{}{key: value, "count": int64(count)})
		}
	}
	return results, rows.Err()
}

func DroppedEvents() int64 {
	return droppedEvents.Load()
}

func WAFDroppedEvents() int64 {
	return wafDroppedEvents.Load()
}

type SectionEventLog struct {
	ID              string
	Timestamp       int64
	Section         string
	EventType       string
	Action          string
	ClientIP        string
	Method          string
	Path            string
	StatusCode      int
	LatencyMs       int64
	Country         string
	UserAgent       string
	UserAgentFamily string
	RuleID          string
	RuleName        string
	RuleType        string
	Score           int
	RequestID       string
	Metadata        string
}

func LogSectionEvent(l SectionEventLog) bool {
	if sectionLogChan == nil {
		return false
	}
	if l.ID == "" {
		l.ID = uuid.NewString()
	}
	if l.Timestamp == 0 {
		l.Timestamp = time.Now().Unix()
	}
	if l.EventType == "" {
		l.EventType = "security"
	}
	if l.UserAgentFamily == "" {
		l.UserAgentFamily = userAgentFamily(l.UserAgent)
	}
	select {
	case sectionLogChan <- l:
		return true
	default:
		droppedEvents.Add(1)
		return false
	}
}

func processSectionEvents() {
	var batch []SectionEventLog
	ticker := time.NewTicker(BatchTimeout)
	defer ticker.Stop()
	for {
		select {
		case l := <-sectionLogChan:
			batch = append(batch, l)
			if len(batch) >= BatchSize {
				flushSectionEvents(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				flushSectionEvents(batch)
				batch = batch[:0]
			}
		}
	}
}

func flushSectionEvents(batch []SectionEventLog) {
	if DB == nil {
		return
	}
	tx, err := DB.Begin()
	if err != nil {
		log.Printf("Failed to begin ClickHouse section event batch: %v", err)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO section_events")
	if err != nil {
		_ = tx.Rollback()
		log.Printf("Failed to prepare ClickHouse section event batch: %v", err)
		return
	}
	for _, l := range batch {
		_, err = stmt.Exec(
			l.ID,
			time.Unix(l.Timestamp, 0).UTC(),
			l.Section,
			l.EventType,
			l.Action,
			l.ClientIP,
			l.Method,
			l.Path,
			uint16(l.StatusCode),
			l.LatencyMs,
			l.Country,
			l.UserAgent,
			l.UserAgentFamily,
			l.RuleID,
			l.RuleName,
			l.RuleType,
			int32(l.Score),
			l.RequestID,
			l.Metadata,
		)
		if err != nil {
			log.Printf("Failed to append ClickHouse section event: %v", err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit ClickHouse section event batch: %v", err)
	}
}

func requestAction(status int, blocked bool) string {
	if blocked || status == 403 {
		return "block"
	}
	if status >= 400 {
		return "error"
	}
	return "allow"
}

func userAgentFamily(ua string) string {
	switch {
	case ua == "":
		return "unknown"
	case containsFold(ua, "bot"), containsFold(ua, "crawler"), containsFold(ua, "spider"):
		return "bot"
	case containsFold(ua, "firefox"):
		return "firefox"
	case containsFold(ua, "edg/"), containsFold(ua, "edge"):
		return "edge"
	case containsFold(ua, "chrome"):
		return "chrome"
	case containsFold(ua, "safari"):
		return "safari"
	default:
		return "other"
	}
}

func containsFold(value, needle string) bool {
	return len(value) >= len(needle) && (value == needle || strings.Contains(strings.ToLower(value), strings.ToLower(needle)))
}

func firstJSONValue(raw string) string {
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err == nil && len(values) > 0 {
		return values[0]
	}
	return ""
}

func boolToUInt8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

func EnsureDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0755)
}
