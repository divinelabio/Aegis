package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

var (
	quantilePattern            = regexp.MustCompile(`(?i)\bquantile\s*\(\s*([0-9]+(?:\.[0-9]+)?)\s*\)\s*\(`)
	alterTableDeletePattern    = regexp.MustCompile(`(?is)^\s*ALTER\s+TABLE\s+([a-zA-Z0-9_]+)\s+DELETE\s+WHERE\s+(.+)$`)
	startOfInterval5MinPattern = regexp.MustCompile(`(?i)\btoStartOfInterval\s*\(\s*([a-zA-Z0-9_.]+)\s*,\s*INTERVAL\s+5\s+minute\s*\)`)
)

func initPostgresAnalyticsDB(config AnalyticsConfig) error {
	pool, err := resolvePostgresAnalyticsPool(config)
	if err != nil {
		return err
	}

	baseConnector := stdlib.GetPoolConnector(pool)
	candidate := sql.OpenDB(&postgresAnalyticsConnector{base: baseConnector})
	if config.MaxOpenConns > 0 {
		candidate.SetMaxOpenConns(config.MaxOpenConns)
	}
	if config.MaxIdleConns > 0 {
		candidate.SetMaxIdleConns(config.MaxIdleConns)
	}
	if config.ConnMaxLifetime > 0 {
		candidate.SetConnMaxLifetime(config.ConnMaxLifetime)
	}

	pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := candidate.PingContext(pingCtx); err != nil {
		_ = candidate.Close()
		return fmt.Errorf("failed to connect to PostgreSQL analytics store: %w", err)
	}
	if err := applyPostgresAnalyticsMigrations(candidate); err != nil {
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

func isLoopbackAnalyticsHost(h string) bool {
	normalized := strings.ToLower(strings.TrimSpace(h))
	return normalized == "" || normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
}

func resolvePostgresAnalyticsPool(config AnalyticsConfig) (*pgxpool.Pool, error) {
	controlMu.Lock()
	controlPool := ControlDB
	controlCfg := activeControlConfig
	controlMu.Unlock()

	host := strings.TrimSpace(config.Host)
	sameOrLoopbackHost := host == "" || strings.EqualFold(host, strings.TrimSpace(controlCfg.Host)) || (isLoopbackAnalyticsHost(host) && isLoopbackAnalyticsHost(controlCfg.Host))
	isClickHouseLegacyPortOrUser := config.Port == 9000 || strings.EqualFold(strings.TrimSpace(config.Username), "default") || strings.EqualFold(strings.TrimSpace(config.PasswordSecretRef), "env:AEGIS_ANALYTICS_DB_PASSWORD")
	hasCustomHost := !sameOrLoopbackHost
	hasCustomDB := strings.TrimSpace(config.Database) != "" && !strings.EqualFold(strings.TrimSpace(config.Database), strings.TrimSpace(controlCfg.Database))
	hasCustomSecret := strings.TrimSpace(config.PasswordSecretRef) != "" && !isClickHouseLegacyPortOrUser

	if controlPool != nil && (isClickHouseLegacyPortOrUser || (!hasCustomHost && !hasCustomDB) || !hasCustomSecret) {
		return controlPool, nil
	}

	if hasCustomSecret && host != "" {
		password, err := resolveEnvironmentSecret(config.PasswordSecretRef, "storage.analytics.password_secret_ref", "PostgreSQL analytics database")
		if err != nil {
			if controlPool != nil {
				return controlPool, nil
			}
			return nil, err
		}
		port := config.Port
		if port <= 0 || port == 9000 {
			port = 5432
		}
		database := strings.TrimSpace(config.Database)
		if database == "" {
			database = "aegis"
		}
		username := strings.TrimSpace(config.Username)
		if username == "" || username == "default" {
			username = "aegis"
		}
		sslMode := "disable"
		if config.Secure {
			sslMode = "require"
		}
		dsn := &url.URL{
			Scheme: "postgres",
			User:   url.UserPassword(username, password),
			Host:   fmt.Sprintf("%s:%d", host, port),
			Path:   database,
		}
		q := dsn.Query()
		q.Set("sslmode", sslMode)
		q.Set("application_name", "aegis-analytics")
		dsn.RawQuery = q.Encode()

		poolConfig, err := pgxpool.ParseConfig(dsn.String())
		if err != nil {
			return nil, fmt.Errorf("parse PostgreSQL analytics database configuration: %w", err)
		}
		poolConfig.MinConns = 1
		if config.MaxOpenConns > 0 {
			poolConfig.MaxConns = int32(config.MaxOpenConns)
		} else {
			poolConfig.MaxConns = 25
		}
		poolConfig.ConnConfig.ConnectTimeout = controlDatabaseConnectTimeout

		connectCtx, cancel := context.WithTimeout(context.Background(), controlDatabaseConnectTimeout)
		defer cancel()
		pool, err := pgxpool.NewWithConfig(connectCtx, poolConfig)
		if err != nil {
			if controlPool != nil {
				return controlPool, nil
			}
			return nil, fmt.Errorf("open PostgreSQL analytics database: %w", err)
		}
		if err := pool.Ping(connectCtx); err != nil {
			pool.Close()
			if controlPool != nil {
				return controlPool, nil
			}
			return nil, fmt.Errorf("ping PostgreSQL analytics database: %w", err)
		}
		return pool, nil
	}

	if controlPool != nil {
		return controlPool, nil
	}
	return nil, errors.New("PostgreSQL analytics requires an active PostgreSQL control-plane connection or configured credentials")
}

func applyPostgresAnalyticsMigrations(db *sql.DB) error {
	stmts := []string{
		`CREATE OR REPLACE FUNCTION jsonextractstring(doc text, key text)
		RETURNS text
		LANGUAGE plpgsql
		IMMUTABLE PARALLEL SAFE
		AS $$
		DECLARE
			trimmed text;
		BEGIN
			IF doc IS NULL THEN
				RETURN '';
			END IF;
			trimmed := btrim(doc, E' \t\r\n');
			IF trimmed = '' OR left(trimmed, 1) != '{' THEN
				RETURN '';
			END IF;
			RETURN COALESCE((trimmed::jsonb)->>key, '');
		EXCEPTION WHEN OTHERS THEN
			RETURN '';
		END;
		$$`,
		`CREATE OR REPLACE FUNCTION tounixtimestamp(ts timestamptz)
		RETURNS bigint
		LANGUAGE sql
		IMMUTABLE PARALLEL SAFE
		AS $$
			SELECT COALESCE(EXTRACT(EPOCH FROM ts)::bigint, 0::bigint);
		$$`,
		`CREATE OR REPLACE FUNCTION tostartofminute(ts timestamptz)
		RETURNS timestamptz
		LANGUAGE sql
		IMMUTABLE PARALLEL SAFE
		AS $$
			SELECT date_trunc('minute', ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
		$$`,
		`CREATE OR REPLACE FUNCTION tostartofhour(ts timestamptz)
		RETURNS timestamptz
		LANGUAGE sql
		IMMUTABLE PARALLEL SAFE
		AS $$
			SELECT date_trunc('hour', ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
		$$`,
		`CREATE OR REPLACE FUNCTION tostartofday(ts timestamptz)
		RETURNS timestamptz
		LANGUAGE sql
		IMMUTABLE PARALLEL SAFE
		AS $$
			SELECT date_trunc('day', ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
		$$`,
		`CREATE OR REPLACE FUNCTION tostring(val anyelement)
		RETURNS text
		LANGUAGE sql
		IMMUTABLE PARALLEL SAFE
		AS $$
			SELECT COALESCE(val::text, '');
		$$`,
		`CREATE OR REPLACE FUNCTION toint64orzero(val text)
		RETURNS bigint
		LANGUAGE plpgsql
		IMMUTABLE PARALLEL SAFE
		AS $$
		DECLARE
			trimmed text;
		BEGIN
			IF val IS NULL THEN
				RETURN 0;
			END IF;
			trimmed := btrim(val, E' \t\r\n');
			IF trimmed ~ '^-?[0-9]+$' THEN
				RETURN trimmed::bigint;
			END IF;
			RETURN 0;
		EXCEPTION WHEN OTHERS THEN
			RETURN 0;
		END;
		$$`,
		`CREATE OR REPLACE FUNCTION toint32orzero(val text)
		RETURNS integer
		LANGUAGE plpgsql
		IMMUTABLE PARALLEL SAFE
		AS $$
		DECLARE
			trimmed text;
		BEGIN
			IF val IS NULL THEN
				RETURN 0;
			END IF;
			trimmed := btrim(val, E' \t\r\n');
			IF trimmed ~ '^-?[0-9]+$' THEN
				RETURN trimmed::integer;
			END IF;
			RETURN 0;
		EXCEPTION WHEN OTHERS THEN
			RETURN 0;
		END;
		$$`,
		`CREATE OR REPLACE FUNCTION formatdatetime(ts timestamptz, fmt text)
		RETURNS text
		LANGUAGE sql
		IMMUTABLE PARALLEL SAFE
		AS $$
			SELECT CASE
				WHEN ts IS NULL THEN ''
				ELSE to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
			END;
		$$`,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS access_events (
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			ip TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			status INTEGER NOT NULL DEFAULT 0,
			latency_ms BIGINT NOT NULL DEFAULT 0,
			user_agent TEXT NOT NULL DEFAULT '',
			referer TEXT NOT NULL DEFAULT '',
			country TEXT NOT NULL DEFAULT '',
			blocked SMALLINT NOT NULL DEFAULT 0,
			rule_id TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_access_events_timestamp ON access_events (timestamp DESC)`,
		`CREATE TABLE IF NOT EXISTS section_events (
			id TEXT PRIMARY KEY,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			section TEXT NOT NULL DEFAULT '',
			event_type TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL DEFAULT '',
			client_ip TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL DEFAULT '',
			status_code INTEGER NOT NULL DEFAULT 0,
			latency_ms BIGINT NOT NULL DEFAULT 0,
			country TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			user_agent_family TEXT NOT NULL DEFAULT '',
			rule_id TEXT NOT NULL DEFAULT '',
			rule_name TEXT NOT NULL DEFAULT '',
			rule_type TEXT NOT NULL DEFAULT '',
			score INTEGER NOT NULL DEFAULT 0,
			request_id TEXT NOT NULL DEFAULT '',
			metadata TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_section_events_section_ts ON section_events (section, timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_section_events_ts ON section_events (timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_section_events_action ON section_events (action)`,
		`CREATE INDEX IF NOT EXISTS idx_section_events_client_ip ON section_events (client_ip)`,
		`DO $$
		BEGIN
			UPDATE section_events SET id = gen_random_uuid()::text WHERE id IS NULL OR id = '';
			DELETE FROM section_events a USING section_events b WHERE a.ctid < b.ctid AND a.id = b.id;
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint 
				WHERE conrelid = 'section_events'::regclass AND contype = 'p'
			) THEN
				ALTER TABLE section_events ADD PRIMARY KEY (id);
			END IF;
		END $$`,
		`CREATE INDEX IF NOT EXISTS idx_section_events_id ON section_events (id)`,
		`CREATE INDEX IF NOT EXISTS idx_section_events_security_feed ON section_events (timestamp DESC, action) WHERE section != 'traffic'`,
		`CREATE INDEX IF NOT EXISTS idx_section_events_sec_action_ts ON section_events (section, action, timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_section_events_metadata_gin ON section_events USING gin ((metadata::jsonb)) WHERE metadata != '' AND metadata != '{}'`,
		`CREATE TABLE IF NOT EXISTS waf_events (
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			ip TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL DEFAULT '',
			query_string TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			host TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL DEFAULT '',
			anomaly_score INTEGER NOT NULL DEFAULT 0,
			rule_ids TEXT NOT NULL DEFAULT '',
			rule_messages TEXT NOT NULL DEFAULT '',
			categories TEXT NOT NULL DEFAULT '',
			status_code INTEGER NOT NULL DEFAULT 0,
			latency_ms BIGINT NOT NULL DEFAULT 0,
			request_size BIGINT NOT NULL DEFAULT 0,
			response_size BIGINT NOT NULL DEFAULT 0,
			country TEXT NOT NULL DEFAULT '',
			city TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_waf_events_timestamp ON waf_events (timestamp DESC)`,
		`CREATE TABLE IF NOT EXISTS security_events (
			id TEXT NOT NULL DEFAULT '',
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			rule_id TEXT NOT NULL DEFAULT '',
			rule_name TEXT NOT NULL DEFAULT '',
			rule_type TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL DEFAULT '',
			client_ip TEXT NOT NULL DEFAULT '',
			country TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			score INTEGER NOT NULL DEFAULT 0,
			section TEXT NOT NULL DEFAULT '',
			matched_fields TEXT NOT NULL DEFAULT '',
			response_code INTEGER NOT NULL DEFAULT 0,
			latency_ms BIGINT NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events (timestamp DESC)`,
		`CREATE TABLE IF NOT EXISTS endpoints (
			id TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL DEFAULT '',
			hits BIGINT NOT NULL DEFAULT 0,
			last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			status TEXT NOT NULL DEFAULT 'shadow',
			is_active INTEGER NOT NULL DEFAULT 1,
			PRIMARY KEY (method, path)
		)`,
		`ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS is_active INTEGER NOT NULL DEFAULT 1`,
		`CREATE TABLE IF NOT EXISTS schemas (
			id TEXT PRIMARY KEY,
			endpoint_id TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL DEFAULT '',
			format TEXT NOT NULL DEFAULT 'OpenAPI 3.0',
			type TEXT NOT NULL DEFAULT 'openapi',
			endpoints INTEGER NOT NULL DEFAULT 0,
			strict BOOLEAN NOT NULL DEFAULT FALSE,
			is_active INTEGER NOT NULL DEFAULT 1,
			content TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`ALTER TABLE schemas ADD COLUMN IF NOT EXISTS endpoint_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE schemas ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'openapi'`,
		`ALTER TABLE schemas ADD COLUMN IF NOT EXISTS is_active INTEGER NOT NULL DEFAULT 1`,
		`INSERT INTO schema_migrations (version, name, applied_at)
		SELECT 1, 'initial_postgres_analytics_schema', NOW()
		WHERE NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 1)`,
		`INSERT INTO schema_migrations (version, name, applied_at)
		SELECT 2, 'optimized_section_events_indexes', NOW()
		WHERE NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 2)`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to apply PostgreSQL analytics migration: %w", err)
		}
	}
	return nil
}

type postgresAnalyticsConnector struct {
	base driver.Connector
}

func (c *postgresAnalyticsConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &postgresAnalyticsConn{Conn: conn}, nil
}

func (c *postgresAnalyticsConnector) Driver() driver.Driver {
	return c.base.Driver()
}

type postgresAnalyticsConn struct {
	driver.Conn
}

func (c *postgresAnalyticsConn) Prepare(query string) (driver.Stmt, error) {
	return c.Conn.Prepare(translateClickHouseToPostgresSQL(query))
}

func (c *postgresAnalyticsConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	translated := translateClickHouseToPostgresSQL(query)
	if prepCtx, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return prepCtx.PrepareContext(ctx, translated)
	}
	return c.Conn.Prepare(translated)
}

func (c *postgresAnalyticsConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	translated := translateClickHouseToPostgresSQL(query)
	if execer, ok := c.Conn.(driver.ExecerContext); ok {
		return execer.ExecContext(ctx, translated, args)
	}
	return nil, driver.ErrSkip
}

func (c *postgresAnalyticsConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	translated := translateClickHouseToPostgresSQL(query)
	if queryer, ok := c.Conn.(driver.QueryerContext); ok {
		return queryer.QueryContext(ctx, translated, args)
	}
	return nil, driver.ErrSkip
}

func (c *postgresAnalyticsConn) Ping(ctx context.Context) error {
	if pinger, ok := c.Conn.(driver.Pinger); ok {
		return pinger.Ping(ctx)
	}
	return nil
}

func (c *postgresAnalyticsConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if beginner, ok := c.Conn.(driver.ConnBeginTx); ok {
		return beginner.BeginTx(ctx, opts)
	}
	return c.Conn.Begin()
}

func (c *postgresAnalyticsConn) ResetSession(ctx context.Context) error {
	if resetter, ok := c.Conn.(driver.SessionResetter); ok {
		return resetter.ResetSession(ctx)
	}
	return nil
}

func (c *postgresAnalyticsConn) IsValid() bool {
	if validator, ok := c.Conn.(driver.Validator); ok {
		return validator.IsValid()
	}
	return true
}

// translateClickHouseToPostgresSQL rewrites ClickHouse-specific SQL constructs
// used by Aegis analytics queries into standard PostgreSQL SQL so both drivers
// can execute the same analytics code paths seamlessly.
func translateClickHouseToPostgresSQL(query string) string {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return query
	}

	// Normalize ClickHouse shorthand INSERT statements if any caller uses them.
	switch strings.ToUpper(trimmed) {
	case "INSERT INTO ACCESS_EVENTS":
		trimmed = "INSERT INTO access_events (timestamp, ip, path, method, status, latency_ms, user_agent, referer, country, blocked, rule_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	case "INSERT INTO WAF_EVENTS":
		trimmed = "INSERT INTO waf_events (timestamp, ip, method, path, query_string, user_agent, host, action, anomaly_score, rule_ids, rule_messages, categories, status_code, latency_ms, request_size, response_size, country, city) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	case "INSERT INTO SECTION_EVENTS":
		trimmed = "INSERT INTO section_events (id, timestamp, section, event_type, action, client_ip, method, path, status_code, latency_ms, country, user_agent, user_agent_family, rule_id, rule_name, rule_type, score, request_id, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	}

	// Rewrite ClickHouse ALTER TABLE <t> DELETE WHERE <cond> into PostgreSQL DELETE FROM <t> WHERE <cond>.
	if matches := alterTableDeletePattern.FindStringSubmatch(trimmed); len(matches) == 3 {
		trimmed = fmt.Sprintf("DELETE FROM %s WHERE %s", matches[1], matches[2])
	}

	// Rewrite toStartOfInterval(ts, INTERVAL 5 minute).
	trimmed = startOfInterval5MinPattern.ReplaceAllString(
		trimmed,
		`(date_trunc('hour', $1 AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' + (((EXTRACT(MINUTE FROM $1 AT TIME ZONE 'UTC')::int / 5) * 5) * INTERVAL '1 minute'))`,
	)

	// Rewrite ClickHouse functions with balanced parenthesis parsing.
	trimmed = rewriteClickHouseFunctions(trimmed)

	// Ensure every subquery in FROM (...) has an alias in PostgreSQL.
	trimmed = ensureDerivedTableAliases(trimmed)

	// Convert ? positional placeholders into PostgreSQL $1, $2, ... placeholders.
	trimmed = replaceQuestionMarkPlaceholders(trimmed)

	return trimmed
}

func rewriteClickHouseFunctions(sqlText string) string {
	out := sqlText
	for pass := 0; pass < 128; pass++ {
		changed := false

		// 1. quantile(p)(expr) -> (PERCENTILE_CONT(p) WITHIN GROUP (ORDER BY expr))
		if loc := quantilePattern.FindStringSubmatchIndex(out); loc != nil {
			pVal := out[loc[2]:loc[3]]
			argStart := loc[1]
			argEnd, ok := findMatchingParen(out, argStart-1)
			if ok {
				inner := rewriteClickHouseFunctions(strings.TrimSpace(out[argStart:argEnd]))
				replacement := fmt.Sprintf("(PERCENTILE_CONT(%s) WITHIN GROUP (ORDER BY (%s)::double precision))", pVal, inner)
				out = out[:loc[0]] + replacement + out[argEnd+1:]
				changed = true
				continue
			}
		}

		// 2. Named function calls: count(), countIf, uniqExact, uniqExactIf, countDistinct, countDistinctIf, if, multiIf
		rewritten, didChange := rewriteNextNamedFunction(out)
		if didChange {
			out = rewritten
			changed = true
		}

		if !changed {
			break
		}
	}
	return out
}

func rewriteNextNamedFunction(s string) (string, bool) {
	inSingleQuote := false
	inDoubleQuote := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' && !inDoubleQuote {
			if inSingleQuote && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			inSingleQuote = !inSingleQuote
			continue
		}
		if ch == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}
		if inSingleQuote || inDoubleQuote {
			continue
		}

		if !isIdentStart(ch) || (i > 0 && isIdentChar(s[i-1])) {
			continue
		}

		identEnd := i + 1
		for identEnd < len(s) && isIdentChar(s[identEnd]) {
			identEnd++
		}
		name := s[i:identEnd]
		lowerName := strings.ToLower(name)

		// Skip whitespace before '('
		openParen := identEnd
		for openParen < len(s) && (s[openParen] == ' ' || s[openParen] == '\t' || s[openParen] == '\r' || s[openParen] == '\n') {
			openParen++
		}
		if openParen >= len(s) || s[openParen] != '(' {
			i = identEnd - 1
			continue
		}

		switch lowerName {
		case "count", "countif", "uniqexact", "uniqexactif", "countdistinct", "countdistinctif", "if", "multiif":
		default:
			i = identEnd - 1
			continue
		}

		closeParen, ok := findMatchingParen(s, openParen)
		if !ok {
			i = identEnd - 1
			continue
		}

		rawArgs := s[openParen+1 : closeParen]
		args := splitTopLevelSQLArgs(rawArgs)
		for idx := range args {
			args[idx] = rewriteClickHouseFunctions(strings.TrimSpace(args[idx]))
		}

		var replacement string
		matched := true
		switch lowerName {
		case "count":
			if len(args) == 0 || (len(args) == 1 && args[0] == "") {
				replacement = "COUNT(*)"
			} else {
				matched = false
			}
		case "countif":
			if len(args) == 1 {
				replacement = fmt.Sprintf("COALESCE(SUM(CASE WHEN %s THEN 1 ELSE 0 END), 0)", args[0])
			} else {
				matched = false
			}
		case "uniqexact", "countdistinct":
			if len(args) == 1 {
				replacement = fmt.Sprintf("COUNT(DISTINCT %s)", args[0])
			} else {
				matched = false
			}
		case "uniqexactif", "countdistinctif":
			if len(args) == 2 {
				replacement = fmt.Sprintf("COUNT(DISTINCT CASE WHEN %s THEN %s END)", args[1], args[0])
			} else {
				matched = false
			}
		case "if":
			if len(args) == 3 {
				replacement = fmt.Sprintf("CASE WHEN %s THEN %s ELSE %s END", args[0], args[1], args[2])
			} else {
				matched = false
			}
		case "multiif":
			if len(args) >= 3 && len(args)%2 == 1 {
				var b strings.Builder
				b.WriteString("CASE")
				for j := 0; j+1 < len(args); j += 2 {
					b.WriteString(" WHEN ")
					b.WriteString(args[j])
					b.WriteString(" THEN ")
					b.WriteString(args[j+1])
				}
				b.WriteString(" ELSE ")
				b.WriteString(args[len(args)-1])
				b.WriteString(" END")
				replacement = b.String()
			} else {
				matched = false
			}
		}

		if matched {
			return s[:i] + replacement + s[closeParen+1:], true
		}
		i = identEnd - 1
	}
	return s, false
}

func ensureDerivedTableAliases(s string) string {
	var out strings.Builder
	out.Grow(len(s) + 32)

	inSingleQuote := false
	inDoubleQuote := false
	aliasCounter := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' && !inDoubleQuote {
			out.WriteByte(ch)
			if inSingleQuote && i+1 < len(s) && s[i+1] == '\'' {
				out.WriteByte(s[i+1])
				i++
				continue
			}
			inSingleQuote = !inSingleQuote
			continue
		}
		if ch == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			out.WriteByte(ch)
			continue
		}
		if inSingleQuote || inDoubleQuote {
			out.WriteByte(ch)
			continue
		}

		if isWordAt(s, i, "from") {
			out.WriteString(s[i : i+4])
			j := i + 4
			for j < len(s) && unicode.IsSpace(rune(s[j])) {
				out.WriteByte(s[j])
				j++
			}
			if j < len(s) && s[j] == '(' {
				closeParen, ok := findMatchingParen(s, j)
				if ok {
					inner := ensureDerivedTableAliases(s[j+1 : closeParen])
					out.WriteByte('(')
					out.WriteString(inner)
					out.WriteByte(')')
					if !hasSubqueryAliasAfter(s, closeParen+1) {
						aliasCounter++
						out.WriteString(" AS _subq_")
						out.WriteString(strconv.Itoa(aliasCounter))
					}
					i = closeParen
					continue
				}
			}
			i = j - 1
			continue
		}

		out.WriteByte(ch)
	}
	return out.String()
}

func hasSubqueryAliasAfter(s string, pos int) bool {
	j := pos
	for j < len(s) && unicode.IsSpace(rune(s[j])) {
		j++
	}
	if j >= len(s) {
		return false
	}
	if !isIdentStart(s[j]) {
		return false
	}
	end := j + 1
	for end < len(s) && isIdentChar(s[end]) {
		end++
	}
	word := strings.ToLower(s[j:end])
	switch word {
	case "where", "group", "order", "limit", "offset", "union", "intersect", "except", "having", "window", "inner", "left", "right", "full", "cross", "join", "on":
		return false
	default:
		return true
	}
}

func isWordAt(s string, pos int, word string) bool {
	if pos < 0 || pos+len(word) > len(s) {
		return false
	}
	if pos > 0 && isIdentChar(s[pos-1]) {
		return false
	}
	if pos+len(word) < len(s) && isIdentChar(s[pos+len(word)]) {
		return false
	}
	return strings.EqualFold(s[pos:pos+len(word)], word)
}

func findMatchingParen(s string, openIdx int) (int, bool) {
	if openIdx < 0 || openIdx >= len(s) || s[openIdx] != '(' {
		return -1, false
	}
	depth := 0
	inSingleQuote := false
	inDoubleQuote := false

	for i := openIdx; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' && !inDoubleQuote {
			if inSingleQuote && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			inSingleQuote = !inSingleQuote
			continue
		}
		if ch == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}
		if inSingleQuote || inDoubleQuote {
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return -1, false
}

func splitTopLevelSQLArgs(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var args []string
	depth := 0
	inSingleQuote := false
	inDoubleQuote := false
	start := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' && !inDoubleQuote {
			if inSingleQuote && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			inSingleQuote = !inSingleQuote
			continue
		}
		if ch == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}
		if inSingleQuote || inDoubleQuote {
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	args = append(args, strings.TrimSpace(s[start:]))
	return args
}

func replaceQuestionMarkPlaceholders(s string) string {
	if !strings.ContainsRune(s, '?') {
		return s
	}
	var out strings.Builder
	out.Grow(len(s) + 16)

	inSingleQuote := false
	inDoubleQuote := false
	index := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' && !inDoubleQuote {
			out.WriteByte(ch)
			if inSingleQuote && i+1 < len(s) && s[i+1] == '\'' {
				out.WriteByte(s[i+1])
				i++
				continue
			}
			inSingleQuote = !inSingleQuote
			continue
		}
		if ch == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			out.WriteByte(ch)
			continue
		}
		if !inSingleQuote && !inDoubleQuote && ch == '?' {
			index++
			out.WriteByte('$')
			out.WriteString(strconv.Itoa(index))
			continue
		}
		out.WriteByte(ch)
	}
	return out.String()
}

func isIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func isIdentChar(ch byte) bool {
	return isIdentStart(ch) || (ch >= '0' && ch <= '9')
}
