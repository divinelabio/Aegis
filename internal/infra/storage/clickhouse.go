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
	analyticsWorkersOnce  sync.Once
)

// InitAnalytics initializes the configured analytics store (PostgreSQL by
// default, or ClickHouse when selected), applies its schema, and starts the
// bounded telemetry writers and 30-day retention worker.
func InitAnalytics(config AnalyticsConfig) (available bool, err error) {
	config.Mode = config.EffectiveMode()
	config.Driver = config.EffectiveDriver()
	config.RetentionDays = config.EffectiveRetentionDays()
	if config.Mode == AnalyticsModeDisabled {
		return false, nil
	}
	if err := config.Validate(); err != nil {
		return false, err
	}
	if config.Driver == DriverPostgreSQL {
		if err := initPostgresAnalyticsDB(config); err != nil {
			return false, err
		}
		return true, nil
	}
	cfg, err := config.runtimeConfig()
	if err != nil {
		if config.Mode == AnalyticsModeOptional {
			fallback := config
			fallback.Driver = DriverPostgreSQL
			if pgErr := initPostgresAnalyticsDB(fallback); pgErr == nil {
				return true, nil
			}
		}
		return false, err
	}
	if err := initClickHouseDB(config, cfg); err != nil {
		if config.Mode == AnalyticsModeOptional {
			fallback := config
			fallback.Driver = DriverPostgreSQL
			if pgErr := initPostgresAnalyticsDB(fallback); pgErr == nil {
				return true, nil
			}
		}
		return false, err
	}
	return true, nil
}

// ActiveAnalyticsDriver returns the currently active analytics driver (defaulting to PostgreSQL).
func ActiveAnalyticsDriver() DBDriver {
	analyticsConfigMu.RLock()
	defer analyticsConfigMu.RUnlock()
	return activeAnalyticsConfig.EffectiveDriver()
}

func startAnalyticsWorkers(retentionDays int) {
	analyticsWorkersOnce.Do(func() {
		requestLogChan = make(chan RequestLog, 10000)
		wafLogChan = make(chan WAFEventLog, 10000)
		sectionLogChan = make(chan SectionEventLog, 20000)
		go processRequestLogs()
		go processWAFLogs()
		go processSectionEvents()
		go runRetentionWorker(retentionDays)
	})
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

	startAnalyticsWorkers(config.EffectiveRetentionDays())
	return nil
}

// AnalyticsConfigIsActive reports whether the active analytics client was
// started from this configuration. Configuration persistence never hot-swaps
// the client, so a mismatch is a truthful restart-required signal.
func AnalyticsConfigIsActive(config AnalyticsConfig) bool {
	analyticsConfigMu.RLock()
	defer analyticsConfigMu.RUnlock()
	if DB == nil {
		return false
	}
	active := activeAnalyticsConfig
	active.Mode = active.EffectiveMode()
	active.Driver = active.EffectiveDriver()
	active.RetentionDays = active.EffectiveRetentionDays()

	candidate := config
	candidate.Mode = candidate.EffectiveMode()
	candidate.Driver = candidate.EffectiveDriver()
	candidate.RetentionDays = candidate.EffectiveRetentionDays()
	if active.Driver == DriverPostgreSQL && candidate.Driver == DriverPostgreSQL {
		return active.Mode == candidate.Mode &&
			active.Driver == candidate.Driver &&
			active.RetentionDays == candidate.RetentionDays &&
			strings.TrimSpace(active.Host) == strings.TrimSpace(candidate.Host)
	}
	return active == candidate
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
		`CREATE TABLE IF NOT EXISTS endpoints (
			id String,
			method LowCardinality(String),
			path String,
			hits UInt64,
			last_seen DateTime64(3, 'UTC'),
			status LowCardinality(String),
			is_active UInt8
		) ENGINE = ReplacingMergeTree(last_seen)
		ORDER BY (method, path)`,
		`CREATE TABLE IF NOT EXISTS schemas (
			id String,
			endpoint_id String,
			name String,
			format LowCardinality(String),
			type LowCardinality(String),
			endpoints UInt32,
			strict UInt8,
			is_active UInt8,
			content String,
			updated_at DateTime64(3, 'UTC')
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY id`,
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

func runRetentionWorker(retentionDays int) {
	if retentionDays <= 0 || retentionDays > MaxAnalyticsRetentionDays {
		retentionDays = DefaultAnalyticsRetentionDays
	}
	pruneOldDataWithRetention(retentionDays)
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		pruneOldDataWithRetention(retentionDays)
	}
}

func pruneOldData() {
	analyticsConfigMu.RLock()
	retentionDays := activeAnalyticsConfig.EffectiveRetentionDays()
	analyticsConfigMu.RUnlock()
	pruneOldDataWithRetention(retentionDays)
}

func pruneOldDataWithRetention(retentionDays int) {
	if DB == nil {
		return
	}
	if retentionDays <= 0 || retentionDays > MaxAnalyticsRetentionDays {
		retentionDays = DefaultAnalyticsRetentionDays
	}
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	if ActiveAnalyticsDriver() == DriverPostgreSQL {
		_, _ = DB.Exec("DELETE FROM access_events WHERE timestamp < ?", cutoff)
		_, _ = DB.Exec("DELETE FROM waf_events WHERE timestamp < ?", cutoff)
		_, _ = DB.Exec("DELETE FROM section_events WHERE timestamp < ?", cutoff)
		_, _ = DB.Exec("DELETE FROM security_events WHERE timestamp < ?", cutoff)
		return
	}
	_, _ = DB.Exec("ALTER TABLE access_events DELETE WHERE timestamp < ?", cutoff)
	_, _ = DB.Exec("ALTER TABLE waf_events DELETE WHERE timestamp < ?", cutoff)
	_, _ = DB.Exec("ALTER TABLE section_events DELETE WHERE timestamp < ?", cutoff)
	_, _ = DB.Exec("ALTER TABLE security_events DELETE WHERE timestamp < ?", cutoff)
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
	Action              string
	RuleID              string
	RuleName            string
	RuleType            string
	Score               int
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
	ExtraMetadata       map[string]string
}

func LogRequest(l RequestLog) {
	section := strings.TrimSpace(l.Section)
	if section == "" {
		section = "traffic"
	}
	metadata := map[string]string{}
	for k, v := range l.ExtraMetadata {
		if strings.TrimSpace(v) != "" {
			metadata[k] = v
		}
	}
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
	if l.RuleID != "" {
		metadata["rule_id"] = l.RuleID
	}
	if l.RuleName != "" {
		metadata["rule_name"] = l.RuleName
	}
	if l.RuleType != "" {
		metadata["rule_type"] = l.RuleType
	}
	if l.Score > 0 {
		metadata["score"] = strconv.Itoa(l.Score)
		metadata["anomaly_score"] = strconv.Itoa(l.Score)
	}
	if section != "" {
		metadata["section"] = section
	}
	rawMetadata, _ := json.Marshal(metadata)
	LogSectionEvent(SectionEventLog{
		Timestamp:       l.Timestamp,
		Section:         section,
		EventType:       "http_request",
		Action:          requestAction(l.Status, l.Blocked, l.Action),
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
		Score:           l.Score,
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
		log.Printf("Failed to begin analytics request batch: %v", err)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO access_events (timestamp, ip, path, method, status, latency_ms, user_agent, referer, country, blocked, rule_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		_ = tx.Rollback()
		log.Printf("Failed to prepare analytics request batch: %v", err)
		return
	}
	for _, l := range batch {
		_, err = stmt.Exec(time.Unix(l.Timestamp, 0).UTC(), l.IP, l.Path, l.Method, uint16(l.Status), l.LatencyMs, l.UserAgent, l.Referer, l.Country, boolToUInt8(l.Blocked), l.RuleID)
		if err != nil {
			log.Printf("Failed to append analytics request event: %v", err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit analytics request batch: %v", err)
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
	ASN                        string
	ASNOrg                     string
	JA3                        string
	JA4                        string
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
	add("asn", l.ASN)
	add("asn_org", l.ASNOrg)
	add("ja3", l.JA3)
	add("ja4", l.JA4)
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
		log.Printf("Failed to begin analytics WAF batch: %v", err)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO waf_events (timestamp, ip, method, path, query_string, user_agent, host, action, anomaly_score, rule_ids, rule_messages, categories, status_code, latency_ms, request_size, response_size, country, city) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		_ = tx.Rollback()
		log.Printf("Failed to prepare analytics WAF batch: %v", err)
		return
	}
	for _, l := range batch {
		_, err = stmt.Exec(time.Unix(l.Timestamp, 0).UTC(), l.IP, l.Method, l.Path, l.QueryString, l.UserAgent, l.Host, l.Action, int32(l.AnomalyScore), l.RuleIDs, l.RuleMessages, l.Categories, uint16(l.StatusCode), l.LatencyMs, l.RequestSize, l.ResponseSize, l.Country, l.City)
		if err != nil {
			log.Printf("Failed to append analytics WAF event: %v", err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit analytics WAF batch: %v", err)
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

var (
	sectionEventHookMu sync.RWMutex
	sectionEventHook   func(SectionEventLog)
)

// SetSectionEventHookForTest registers a hook called whenever LogSectionEvent is invoked.
func SetSectionEventHookForTest(hook func(SectionEventLog)) func() {
	sectionEventHookMu.Lock()
	prev := sectionEventHook
	sectionEventHook = hook
	sectionEventHookMu.Unlock()
	return func() {
		sectionEventHookMu.Lock()
		sectionEventHook = prev
		sectionEventHookMu.Unlock()
	}
}

func LogSectionEvent(l SectionEventLog) bool {
	sectionEventHookMu.RLock()
	hook := sectionEventHook
	sectionEventHookMu.RUnlock()
	if hook != nil {
		hook(l)
	}
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
		log.Printf("Failed to begin analytics section event batch: %v", err)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO section_events (id, timestamp, section, event_type, action, client_ip, method, path, status_code, latency_ms, country, user_agent, user_agent_family, rule_id, rule_name, rule_type, score, request_id, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		_ = tx.Rollback()
		log.Printf("Failed to prepare analytics section event batch: %v", err)
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
			log.Printf("Failed to append analytics section event: %v", err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit analytics section event batch: %v", err)
	}
}

func requestAction(status int, blocked bool, explicitAction ...string) string {
	if len(explicitAction) > 0 {
		switch strings.ToLower(strings.TrimSpace(explicitAction[0])) {
		case "block", "blocked", "deny", "denied":
			return "block"
		case "ratelimit", "rate_limit", "throttle":
			return "ratelimit"
		case "challenge", "challenged":
			return "challenge"
		case "detect", "detected", "flag", "flagged", "log":
			return "detect"
		case "redirect", "redirected":
			return "redirect"
		}
	}
	if status == 429 {
		return "ratelimit"
	}
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
