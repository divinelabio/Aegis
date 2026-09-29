package analytics

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/rules"
	"github.com/google/uuid"
)

type SecurityEvent struct {
	ID            string            `json:"id"`
	Timestamp     time.Time         `json:"timestamp"`
	RuleID        string            `json:"rule_id,omitempty"`
	RuleName      string            `json:"rule_name,omitempty"`
	RuleType      string            `json:"rule_type,omitempty"`
	Action        string            `json:"action"`
	ClientIP      string            `json:"client_ip"`
	Country       string            `json:"country,omitempty"`
	Path          string            `json:"path"`
	Method        string            `json:"method"`
	UserAgent     string            `json:"user_agent,omitempty"`
	Score         int               `json:"score,omitempty"`
	Section       string            `json:"section,omitempty"`
	MatchedFields map[string]string `json:"matched_fields,omitempty"`
	ResponseCode  int               `json:"response_code"`
	LatencyMs     int64             `json:"latency_ms,omitempty"`
}

type Query struct {
	Limit            int
	Action           string
	RuleID           string
	RuleName         string
	RuleType         string
	Section          string
	Country          string
	IP               string
	Path             string
	Method           string
	UserAgent        string
	JA3              string
	JA4              string
	ASN              string
	ASNOrg           string
	TLSVersion       string
	Host             string
	QueryString      string
	DecisionSource   string
	ChallengeType    string
	ChallengeOutcome string
	RuleOverride     string
	ScoreMin         *int
	ScoreMax         *int
	StatusCode       *int
	Since            time.Time
	Until            time.Time
}

type Summary struct {
	Total         int            `json:"total"`
	ByAction      map[string]int `json:"by_action"`
	BlockRate     float64        `json:"block_rate"`
	ChallengeRate float64        `json:"challenge_rate"`
	AvgScore      float64        `json:"avg_score"`
	AvgLatencyMs  float64        `json:"avg_latency_ms"`
}

type Store struct {
	db *sql.DB
}

const insertSecurityEventQuery = `INSERT INTO section_events (id, timestamp, section, event_type, action, client_ip, method, path, status_code, latency_ms, country, user_agent, user_agent_family, rule_id, rule_name, rule_type, score, request_id, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("ClickHouse analytics database is not initialized")
	}
	store := &Store{db: db}
	return store, store.EnsureSchema()
}

func (s *Store) EnsureSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS section_events (
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
	TTL timestamp + INTERVAL 30 DAY`)
	return err
}

func (s *Store) Record(ctx context.Context, event SecurityEvent) error {
	_, err := s.db.ExecContext(ctx, insertSecurityEventQuery, securityEventValues(event)...)
	return err
}

// RecordBatch persists a bounded group of security events in one transaction.
// Bot Protection uses this path to keep audit delivery ahead of burst traffic
// without moving database work back onto the request path.
func (s *Store) RecordBatch(ctx context.Context, events []SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, insertSecurityEventQuery)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, event := range events {
		if _, err := stmt.ExecContext(ctx, securityEventValues(event)...); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func securityEventValues(event SecurityEvent) []any {
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	fields, _ := json.Marshal(event.MatchedFields)
	return []any{
		event.ID,
		event.Timestamp,
		normalizeSection(event.Section, event.RuleType),
		"security",
		event.Action,
		event.ClientIP,
		event.Method,
		event.Path,
		uint16(event.ResponseCode),
		event.LatencyMs,
		event.Country,
		event.UserAgent,
		normalizeUserAgentFamily(event.UserAgent),
		event.RuleID,
		event.RuleName,
		event.RuleType,
		int32(event.Score),
		"",
		string(fields),
	}
}

func (s *Store) RecordRuleEvent(ctx context.Context, event rules.RuleEvent) {
	_ = s.Record(ctx, securityEventFromRuleEvent(event))
}

func securityEventFromRuleEvent(event rules.RuleEvent) SecurityEvent {
	return SecurityEvent{
		Timestamp: event.Timestamp,
		RuleID:    event.Verdict.RuleID,
		RuleName:  event.Verdict.RuleName,
		RuleType:  string(event.Verdict.RuleType),
		Action:    string(event.Verdict.Action),
		ClientIP:  event.Request.ClientIP,
		Country:   event.Request.Country,
		Path:      event.Request.Path,
		Method:    event.Request.Method,
		UserAgent: event.Request.UserAgent,
		Score:     event.Request.BotScore,
		Section:   "security_rules",
		MatchedFields: map[string]string{
			"asn":           event.Request.ASN,
			"asn_org":       event.Request.ASNOrg,
			"bot_category":  event.Request.BotCategory,
			"bot_verified":  fmt.Sprintf("%t", event.Request.BotVerified),
			"bot_headless":  fmt.Sprintf("%t", event.Request.BotHeadless),
			"host":          event.Request.Host,
			"ip_reputation": fmt.Sprintf("%d", event.Request.IPReputation),
			"query_string":  queryStringFromMap(event.Request.Query),
			"tls_ja3":       event.Request.TLSJA3,
			"tls_ja4":       event.Request.TLSJA4,
			"tls_version":   event.Request.TLSVersion,
		},
		ResponseCode: event.Status,
	}
}

func queryStringFromMap(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for key, value := range values {
		if key == "" {
			continue
		}
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, "&")
}

func (s *Store) List(ctx context.Context, q Query) ([]SecurityEvent, error) {
	where, args := buildWhere(q)
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT id, timestamp, rule_id, rule_name, rule_type, action, client_ip, country, path, method, user_agent, score, section, metadata, status_code, latency_ms FROM section_events `+where+` ORDER BY timestamp DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) Timeline(ctx context.Context, q Query) ([]map[string]any, error) {
	where, args := buildWhere(q)
	rows, err := s.db.QueryContext(ctx, `SELECT formatDateTime(toStartOfHour(timestamp), '%FT%TZ') AS bucket, action, count() FROM section_events `+where+` GROUP BY bucket, action ORDER BY bucket ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAggregate(rows, "bucket", "action")
}

func (s *Store) Top(ctx context.Context, field string, q Query, limit int) ([]map[string]any, error) {
	allowed := map[string]string{
		"ips":               "client_ip",
		"paths":             "path",
		"geo":               "country",
		"rules":             "rule_name",
		"actions":           "action",
		"statuses":          "toString(status_code)",
		"user-agents":       "user_agent_family",
		"user_agents":       "user_agent_family",
		"bot-categories":    "JSONExtractString(metadata, 'bot_category')",
		"decision-source":   "JSONExtractString(metadata, 'decision_source')",
		"decision-state":    "JSONExtractString(metadata, 'decision_state')",
		"challenge-type":    "JSONExtractString(metadata, 'challenge_type')",
		"challenge-outcome": "JSONExtractString(metadata, 'challenge_outcome')",
		"rule-override":     "JSONExtractString(metadata, 'rule_override')",
	}
	column, ok := allowed[field]
	if !ok {
		return nil, fmt.Errorf("unsupported aggregate %s", field)
	}
	outputKey := column
	if field == "bot-categories" {
		outputKey = "bot_category"
	} else if field == "decision-source" {
		outputKey = "decision_source"
	} else if field == "decision-state" {
		outputKey = "decision_state"
	} else if field == "challenge-type" {
		outputKey = "challenge_type"
	} else if field == "challenge-outcome" {
		outputKey = "challenge_outcome"
	} else if field == "rule-override" {
		outputKey = "rule_override"
	} else if field == "user-agents" || field == "user_agents" {
		outputKey = "user_agent"
	} else if field == "statuses" {
		outputKey = "status_code"
	}
	where, args := buildWhere(q)
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`SELECT %s, count() FROM section_events %s AND %s != '' GROUP BY %s ORDER BY count() DESC LIMIT ?`, column, where, column, column), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSimpleAggregate(rows, outputKey)
}

func (s *Store) Summary(ctx context.Context, q Query) (Summary, error) {
	where, args := buildWhere(q)
	rows, err := s.db.QueryContext(ctx, `SELECT action, count(), COALESCE(AVG(score), 0), COALESCE(AVG(latency_ms), 0) FROM section_events `+where+` GROUP BY action`, args...)
	if err != nil {
		return Summary{}, err
	}
	defer rows.Close()

	summary := Summary{ByAction: map[string]int{}}
	var weightedScore float64
	var weightedLatency float64
	for rows.Next() {
		var action string
		var count uint64
		var avgScore float64
		var avgLatency float64
		if err := rows.Scan(&action, &count, &avgScore, &avgLatency); err != nil {
			return Summary{}, err
		}
		summary.ByAction[action] = int(count)
		summary.Total += int(count)
		weightedScore += avgScore * float64(count)
		weightedLatency += avgLatency * float64(count)
	}
	if err := rows.Err(); err != nil {
		return Summary{}, err
	}
	if summary.Total > 0 {
		summary.BlockRate = float64(summary.ByAction["block"]) / float64(summary.Total) * 100
		summary.ChallengeRate = float64(summary.ByAction["challenge"]) / float64(summary.Total) * 100
		summary.AvgScore = weightedScore / float64(summary.Total)
		summary.AvgLatencyMs = weightedLatency / float64(summary.Total)
	}
	return summary, nil
}

func buildWhere(q Query) (string, []any) {
	var clauses []string
	var args []any
	add := func(condition string, value any) {
		clauses = append(clauses, condition)
		args = append(args, value)
	}
	if q.Action != "" {
		add("action = ?", q.Action)
	}
	if q.RuleID != "" {
		add("rule_id = ?", q.RuleID)
	}
	if q.RuleName != "" {
		add("rule_name LIKE ?", "%"+q.RuleName+"%")
	}
	if q.RuleType != "" {
		add("rule_type = ?", q.RuleType)
	}
	if q.Section != "" {
		if q.Section == "bot_protection" || q.Section == "bot" {
			clauses = append(clauses, "(section IN ('bot_protection', 'bot') OR rule_type = 'bot')")
		} else {
			add("section = ?", q.Section)
		}
	}
	if q.Country != "" {
		add("country = ?", q.Country)
	}
	if q.IP != "" {
		add("client_ip = ?", q.IP)
	}
	if q.Path != "" {
		add("path LIKE ?", "%"+q.Path+"%")
	}
	if q.Method != "" {
		add("method = ?", strings.ToUpper(q.Method))
	}
	if q.UserAgent != "" {
		add("user_agent LIKE ?", "%"+q.UserAgent+"%")
	}
	if q.JA3 != "" {
		clauses = append(clauses, "(metadata LIKE ? OR metadata LIKE ?)")
		args = append(args, "%\"tls_ja3\":\""+q.JA3+"\"%", "%\"ja3\":\""+q.JA3+"\"%")
	}
	if q.JA4 != "" {
		clauses = append(clauses, "(metadata LIKE ? OR metadata LIKE ?)")
		args = append(args, "%\"tls_ja4\":\""+q.JA4+"\"%", "%\"ja4\":\""+q.JA4+"\"%")
	}
	if q.ASN != "" {
		add("JSONExtractString(metadata, 'asn') = ?", q.ASN)
	}
	if q.ASNOrg != "" {
		add("JSONExtractString(metadata, 'asn_org') LIKE ?", "%"+q.ASNOrg+"%")
	}
	if q.TLSVersion != "" {
		add("JSONExtractString(metadata, 'tls_version') = ?", q.TLSVersion)
	}
	if q.Host != "" {
		add("JSONExtractString(metadata, 'host') LIKE ?", "%"+q.Host+"%")
	}
	if q.QueryString != "" {
		add("JSONExtractString(metadata, 'query_string') LIKE ?", "%"+q.QueryString+"%")
	}
	if q.DecisionSource != "" {
		add("JSONExtractString(metadata, 'decision_source') = ?", q.DecisionSource)
	}
	if q.ChallengeType != "" {
		add("JSONExtractString(metadata, 'challenge_type') = ?", q.ChallengeType)
	}
	if q.ChallengeOutcome != "" {
		add("JSONExtractString(metadata, 'challenge_outcome') = ?", q.ChallengeOutcome)
	}
	if q.RuleOverride != "" {
		add("JSONExtractString(metadata, 'rule_override') = ?", strings.ToLower(q.RuleOverride))
	}
	if q.ScoreMin != nil {
		add("score >= ?", *q.ScoreMin)
	}
	if q.ScoreMax != nil {
		add("score <= ?", *q.ScoreMax)
	}
	if q.StatusCode != nil {
		add("status_code = ?", *q.StatusCode)
	}
	if !q.Since.IsZero() {
		add("timestamp >= ?", q.Since)
	}
	if !q.Until.IsZero() {
		add("timestamp <= ?", q.Until)
	}
	if len(clauses) == 0 {
		return "WHERE 1 = 1", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

type scanner interface {
	Scan(dest ...any) error
}

func scanEvent(row scanner) (SecurityEvent, error) {
	var event SecurityEvent
	var fields sql.NullString
	err := row.Scan(&event.ID, &event.Timestamp, &event.RuleID, &event.RuleName, &event.RuleType, &event.Action, &event.ClientIP, &event.Country, &event.Path, &event.Method, &event.UserAgent, &event.Score, &event.Section, &fields, &event.ResponseCode, &event.LatencyMs)
	if err != nil {
		return event, err
	}
	if fields.Valid && fields.String != "" {
		_ = json.Unmarshal([]byte(fields.String), &event.MatchedFields)
	}
	return event, nil
}

func scanAggregate(rows *sql.Rows, firstKey, secondKey string) ([]map[string]any, error) {
	var out []map[string]any
	for rows.Next() {
		var first, second string
		var count uint64
		if err := rows.Scan(&first, &second, &count); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{firstKey: first, secondKey: second, "count": count})
	}
	return out, rows.Err()
}

func scanSimpleAggregate(rows *sql.Rows, key string) ([]map[string]any, error) {
	var out []map[string]any
	for rows.Next() {
		var value string
		var count uint64
		if err := rows.Scan(&value, &count); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{key: value, "count": count})
	}
	return out, rows.Err()
}

func normalizeSection(section, ruleType string) string {
	switch section {
	case "traffic":
		return "traffic_control"
	case "bot":
		return "bot_protection"
	case "api":
		return "api_security"
	case "http":
		return "http_security"
	case "":
		switch ruleType {
		case "bot":
			return "bot_protection"
		case "api":
			return "api_security"
		case "http_security":
			return "http_security"
		default:
			return "security_rules"
		}
	default:
		return section
	}
}

func normalizeUserAgentFamily(ua string) string {
	value := strings.ToLower(ua)
	switch {
	case value == "":
		return "unknown"
	case strings.Contains(value, "bot"), strings.Contains(value, "crawler"), strings.Contains(value, "spider"):
		return "bot"
	case strings.Contains(value, "firefox"):
		return "firefox"
	case strings.Contains(value, "edg/"), strings.Contains(value, "edge"):
		return "edge"
	case strings.Contains(value, "chrome"):
		return "chrome"
	case strings.Contains(value, "safari"):
		return "safari"
	default:
		return "other"
	}
}
