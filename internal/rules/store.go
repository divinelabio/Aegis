package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const rulesSchemaLockID int64 = 4_129_741_034

const securityRuleSelectColumns = `id, name, description, enabled, priority, type, section, source, phase, mode, expression, action, action_params, tags, managed_by, sync_status, version, last_matched_at, match_count, created_at, updated_at`

const ruleChangeChannel = "aegis_rule_changes"

const ruleChangeReconnectDelay = time.Second

// Store is the PostgreSQL control-plane repository for unified security-rule
// definitions. Match events are recorded separately in ClickHouse analytics.
type Store struct {
	db                  *pgxpool.Pool
	ruleChangesMu       sync.RWMutex
	ruleChangeListeners []func(context.Context)
}

// NewStore opens the PostgreSQL rule repository and applies its idempotent
// schema setup before callers can evaluate or mutate rules.
func NewStore(ctx context.Context, db *pgxpool.Pool) (*Store, error) {
	if db == nil {
		return nil, errors.New("PostgreSQL control database pool is required")
	}
	store := &Store{db: db}
	return store, store.EnsureSchema(ctx)
}

// EnsureSchema serializes rule-schema setup independently from application
// startup so multiple Aegis processes cannot race the schema or ledger.
func (s *Store) EnsureSchema(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin security-rule schema transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, rulesSchemaLockID); err != nil {
		return fmt.Errorf("lock security-rule schema migration: %w", err)
	}
	for _, statement := range postgreSQLRuleSchema {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return fmt.Errorf("apply PostgreSQL security-rule schema: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO rule_schema_migrations (version, name)
		VALUES (1, 'initial_postgresql_security_rules')
		ON CONFLICT (version) DO NOTHING`); err != nil {
		return fmt.Errorf("record PostgreSQL security-rule schema migration: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit security-rule schema transaction: %w", err)
	}
	return nil
}

var postgreSQLRuleSchema = []string{
	`CREATE TABLE IF NOT EXISTS rule_schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS security_rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		priority INTEGER NOT NULL,
		type TEXT NOT NULL,
		section TEXT NOT NULL DEFAULT '',
		source TEXT NOT NULL DEFAULT '',
		phase TEXT NOT NULL DEFAULT '',
		mode TEXT NOT NULL DEFAULT '',
		expression TEXT NOT NULL,
		action TEXT NOT NULL,
		action_params JSONB NOT NULL DEFAULT '{}'::jsonb,
		tags JSONB NOT NULL DEFAULT '[]'::jsonb,
		managed_by TEXT NOT NULL DEFAULT '',
		sync_status TEXT NOT NULL DEFAULT '',
		version INTEGER NOT NULL DEFAULT 1,
		last_matched_at TIMESTAMPTZ NULL,
		match_count BIGINT NOT NULL DEFAULT 0,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL,
		deleted BOOLEAN NOT NULL DEFAULT FALSE
	)`,
	`CREATE INDEX IF NOT EXISTS security_rules_active_order_idx
		ON security_rules (phase, priority, created_at, id) WHERE deleted = FALSE`,
	`CREATE TABLE IF NOT EXISTS security_rule_versions (
		id UUID PRIMARY KEY,
		rule_id TEXT NOT NULL REFERENCES security_rules(id) ON DELETE CASCADE,
		version INTEGER NOT NULL,
		snapshot JSONB NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		UNIQUE (rule_id, version)
	)`,
}

func (s *Store) List(ctx context.Context) ([]SecurityRule, error) {
	rows, err := s.db.Query(ctx, `
		SELECT `+securityRuleSelectColumns+`
		FROM security_rules
		WHERE deleted = FALSE
		ORDER BY phase ASC, priority ASC, created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]SecurityRule, 0)
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		applyRuleDefaults(&rule)
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// SubscribeRuleChanges registers a process-local callback invoked after a
// rule transaction commits. Listeners are called outside the store lock.
func (s *Store) SubscribeRuleChanges(listener func(context.Context)) {
	if listener == nil {
		return
	}
	s.ruleChangesMu.Lock()
	s.ruleChangeListeners = append(s.ruleChangeListeners, listener)
	s.ruleChangesMu.Unlock()
}

func (s *Store) notifyRuleChanges(ctx context.Context) {
	s.ruleChangesMu.RLock()
	listeners := append([]func(context.Context){}, s.ruleChangeListeners...)
	s.ruleChangesMu.RUnlock()
	for _, listener := range listeners {
		listener(ctx)
	}
}

// StartRuleChangeListener delivers committed rule changes from every Aegis
// process sharing this PostgreSQL control database. It reserves one pool
// connection for LISTEN until ctx is cancelled and reconnects after failures.
func (s *Store) StartRuleChangeListener(ctx context.Context, reportError func(error)) error {
	listener, err := s.openRuleChangeListener(ctx)
	if err != nil {
		return err
	}
	go s.listenForRuleChanges(ctx, listener, reportError)
	return nil
}

func (s *Store) openRuleChangeListener(ctx context.Context) (*pgxpool.Conn, error) {
	listener, err := s.db.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire security-rule change listener: %w", err)
	}
	if _, err := listener.Exec(ctx, "LISTEN "+ruleChangeChannel); err != nil {
		listener.Release()
		return nil, fmt.Errorf("listen for security-rule changes: %w", err)
	}
	return listener, nil
}

func (s *Store) listenForRuleChanges(ctx context.Context, listener *pgxpool.Conn, reportError func(error)) {
	for {
		_, err := listener.Conn().WaitForNotification(ctx)
		if err == nil {
			s.notifyRuleChanges(ctx)
			continue
		}
		listener.Release()
		if ctx.Err() != nil {
			return
		}
		if reportError != nil {
			reportError(fmt.Errorf("security-rule change listener interrupted: %w", err))
		}

		for {
			if !waitForRuleChangeReconnect(ctx) {
				return
			}
			listener, err = s.openRuleChangeListener(ctx)
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return
			}
			if reportError != nil {
				reportError(err)
			}
		}
	}
}

func waitForRuleChangeReconnect(ctx context.Context) bool {
	timer := time.NewTimer(ruleChangeReconnectDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (s *Store) Get(ctx context.Context, id string) (*SecurityRule, error) {
	rule, err := scanRule(s.db.QueryRow(ctx, `
		SELECT `+securityRuleSelectColumns+`
		FROM security_rules WHERE id = $1 AND deleted = FALSE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	applyRuleDefaults(&rule)
	return &rule, nil
}

func (s *Store) Create(ctx context.Context, rule SecurityRule) (*SecurityRule, error) {
	if rule.ID == "" {
		rule.ID = uuid.NewString()
	}
	if rule.Priority == 0 {
		rule.Priority = int(time.Now().Unix())
	}
	applyRuleDefaults(&rule)
	now := time.Now().UTC()
	rule.CreatedAt = now
	rule.UpdatedAt = now
	if err := validateRule(rule); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertRule(ctx, tx, rule, false); err != nil {
		return nil, err
	}
	if err := snapshotRule(ctx, tx, rule); err != nil {
		return nil, err
	}
	if err := notifyRuleChange(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.notifyRuleChanges(ctx)
	return &rule, nil
}

func (s *Store) Update(ctx context.Context, id string, rule SecurityRule) (*SecurityRule, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, err := currentRuleForUpdate(ctx, tx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rule.ID = id
	rule.CreatedAt = existing.CreatedAt
	rule.Version = existing.Version + 1
	rule.LastMatchedAt = existing.LastMatchedAt
	rule.MatchCount = existing.MatchCount
	applyRuleDefaults(&rule)
	rule.UpdatedAt = time.Now().UTC()
	if err := validateRule(rule); err != nil {
		return nil, err
	}
	if err := updateRule(ctx, tx, rule, false); err != nil {
		return nil, err
	}
	if err := snapshotRule(ctx, tx, rule); err != nil {
		return nil, err
	}
	if err := notifyRuleChange(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.notifyRuleChanges(ctx)
	return &rule, nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rule, err := currentRuleForUpdate(ctx, tx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rule.Version++
	rule.UpdatedAt = time.Now().UTC()
	if err := updateRule(ctx, tx, rule, true); err != nil {
		return err
	}
	if err := snapshotRule(ctx, tx, rule); err != nil {
		return err
	}
	if err := notifyRuleChange(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.notifyRuleChanges(ctx)
	return nil
}

func (s *Store) Reorder(ctx context.Context, ids []string) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	seen := make(map[string]struct{}, len(ids))
	for index, id := range ids {
		if id == "" {
			return errors.New("rule id is required for reordering")
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("rule %q appears more than once in reorder request", id)
		}
		seen[id] = struct{}{}
		rule, err := currentRuleForUpdate(ctx, tx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("rule %q does not exist", id)
		}
		if err != nil {
			return err
		}
		rule.Priority = (index + 1) * 100
		rule.Version++
		rule.UpdatedAt = time.Now().UTC()
		if err := updateRule(ctx, tx, rule, false); err != nil {
			return err
		}
		if err := snapshotRule(ctx, tx, rule); err != nil {
			return err
		}
	}
	if err := notifyRuleChange(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.notifyRuleChanges(ctx)
	return nil
}

// MarkMatched is retained for explicit administrative callers. The request
// engine records rule-match events only in ClickHouse and does not call this
// method, keeping hot-path telemetry out of PostgreSQL.
func (s *Store) MarkMatched(ctx context.Context, id string, matchedAt time.Time) error {
	if id == "" {
		return nil
	}
	if matchedAt.IsZero() {
		matchedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(ctx, `
		UPDATE security_rules
		SET last_matched_at = $2, match_count = match_count + 1
		WHERE id = $1 AND deleted = FALSE`, id, matchedAt.UTC())
	return err
}

func currentRuleForUpdate(ctx context.Context, tx pgx.Tx, id string) (SecurityRule, error) {
	return scanRule(tx.QueryRow(ctx, `
		SELECT `+securityRuleSelectColumns+`
		FROM security_rules WHERE id = $1 AND deleted = FALSE FOR UPDATE`, id))
}

func notifyRuleChange(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_notify($1, '')`, ruleChangeChannel)
	return err
}

func insertRule(ctx context.Context, tx pgx.Tx, rule SecurityRule, deleted bool) error {
	params, tags := encodeRuleJSON(rule)
	_, err := tx.Exec(ctx, `
		INSERT INTO security_rules (
			id, name, description, enabled, priority, type, section, source, phase, mode,
			expression, action, action_params, tags, managed_by, sync_status, version,
			last_matched_at, match_count, created_at, updated_at, deleted
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13::jsonb, $14::jsonb, $15, $16, $17,
			$18, $19, $20, $21, $22
		)`,
		rule.ID, rule.Name, rule.Description, rule.Enabled, rule.Priority, rule.Type, rule.Section, rule.Source,
		rule.Phase, rule.Mode, rule.Expression, rule.Action, params, tags, rule.ManagedBy, rule.SyncStatus,
		rule.Version, rule.LastMatchedAt, rule.MatchCount, rule.CreatedAt, rule.UpdatedAt, deleted)
	return err
}

func updateRule(ctx context.Context, tx pgx.Tx, rule SecurityRule, deleted bool) error {
	params, tags := encodeRuleJSON(rule)
	_, err := tx.Exec(ctx, `
		UPDATE security_rules SET
			name = $2, description = $3, enabled = $4, priority = $5, type = $6,
			section = $7, source = $8, phase = $9, mode = $10, expression = $11,
			action = $12, action_params = $13::jsonb, tags = $14::jsonb, managed_by = $15,
			sync_status = $16, version = $17, last_matched_at = $18, match_count = $19,
			updated_at = $20, deleted = $21
		WHERE id = $1`,
		rule.ID, rule.Name, rule.Description, rule.Enabled, rule.Priority, rule.Type, rule.Section, rule.Source,
		rule.Phase, rule.Mode, rule.Expression, rule.Action, params, tags, rule.ManagedBy, rule.SyncStatus,
		rule.Version, rule.LastMatchedAt, rule.MatchCount, rule.UpdatedAt, deleted)
	return err
}

func snapshotRule(ctx context.Context, tx pgx.Tx, rule SecurityRule) error {
	body, err := json.Marshal(rule)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO security_rule_versions (id, rule_id, version, snapshot, created_at)
		VALUES ($1, $2, $3, $4::jsonb, $5)`, uuid.New(), rule.ID, rule.Version, string(body), time.Now().UTC())
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRule(row scanner) (SecurityRule, error) {
	var rule SecurityRule
	var params, tags []byte
	var lastMatchedAt *time.Time
	err := row.Scan(
		&rule.ID, &rule.Name, &rule.Description, &rule.Enabled, &rule.Priority, &rule.Type,
		&rule.Section, &rule.Source, &rule.Phase, &rule.Mode, &rule.Expression, &rule.Action,
		&params, &tags, &rule.ManagedBy, &rule.SyncStatus, &rule.Version, &lastMatchedAt,
		&rule.MatchCount, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		return rule, err
	}
	rule.LastMatchedAt = lastMatchedAt
	if len(params) > 0 {
		_ = json.Unmarshal(params, &rule.ActionParams)
	}
	if len(tags) > 0 {
		_ = json.Unmarshal(tags, &rule.Tags)
	}
	return rule, nil
}

func encodeRuleJSON(rule SecurityRule) (string, string) {
	params, _ := json.Marshal(rule.ActionParams)
	tags, _ := json.Marshal(rule.Tags)
	return string(params), string(tags)
}

func validateRule(rule SecurityRule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if rule.Type == "" {
		return fmt.Errorf("rule type is required")
	}
	if rule.Expression == "" {
		return fmt.Errorf("rule expression is required")
	}
	if rule.Action == "" {
		return fmt.Errorf("rule action is required")
	}
	validation := ValidateExpression(rule.Expression)
	if !validation.Valid && rule.Enabled {
		if len(validation.Errors) > 0 {
			return validation.Errors[0]
		}
		if len(validation.Warnings) > 0 {
			return errors.New(validation.Warnings[0])
		}
		return fmt.Errorf("rule expression is invalid")
	}
	return nil
}

func applyRuleDefaults(rule *SecurityRule) {
	if rule.Section == "" {
		rule.Section = string(rule.Type)
	}
	if rule.Source == "" {
		rule.Source = "unified"
	}
	if rule.Phase == "" {
		rule.Phase = defaultPhase(rule.Type)
	}
	if rule.Mode == "" {
		rule.Mode = "code"
	}
	if rule.ManagedBy == "" {
		rule.ManagedBy = "security_rules"
	}
	if rule.SyncStatus == "" {
		rule.SyncStatus = "unified"
	}
	if rule.Version == 0 {
		rule.Version = 1
	}
}

func defaultPhase(ruleType RuleType) string {
	switch ruleType {
	case RuleTypeRateLimit:
		return "rate_limit"
	case RuleTypeBot:
		return "bot"
	case RuleTypeGeo, RuleTypeIPAccess, RuleTypeAccess:
		return "access"
	case RuleTypeAPI:
		return "api"
	case RuleTypeHTTPSec:
		return "http_security"
	default:
		return "http_request_firewall_custom"
	}
}
