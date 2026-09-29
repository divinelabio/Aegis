// Package configstore provides the PostgreSQL persistence boundary for
// operator-managed configuration documents. It deliberately stores complete,
// versioned documents; section-specific validation remains with the owning
// domain before a document reaches this package.
package configstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	configurationSchemaAdvisoryLock int64 = 4_129_741_043
	configurationChangeChannel            = "aegis_configuration_changes"
	maxDocumentBytes                      = 2 << 20
	maxScopeBytes                         = 160
	maxActorBytes                         = 256
	maxReasonBytes                        = 256
)

var ErrRevisionConflict = errors.New("configuration revision conflict")

// RevisionConflictError reports the persisted revision that rejected a stale
// write. Callers use errors.Is(err, ErrRevisionConflict) to return HTTP 409.
type RevisionConflictError struct {
	Scope    string
	Expected int64
	Actual   int64
}

func (e *RevisionConflictError) Error() string {
	if e == nil {
		return ErrRevisionConflict.Error()
	}
	return fmt.Sprintf("%s for scope %q: expected revision %d, current revision %d", ErrRevisionConflict, e.Scope, e.Expected, e.Actual)
}

func (e *RevisionConflictError) Unwrap() error { return ErrRevisionConflict }

// SaveInput is one validated candidate document. ExpectedRevision is zero for
// creation and the current revision for an update.
type SaveInput struct {
	Scope            string
	ExpectedRevision int64
	SchemaVersion    int
	Payload          json.RawMessage
	Actor            string
	Reason           string
}

// Document is an immutable configuration revision. Load returns the active
// document; ListRevisions returns historical snapshots.
type Document struct {
	Scope         string
	Revision      int64
	SchemaVersion int
	Checksum      string
	Payload       json.RawMessage
	Actor         string
	Reason        string
	CreatedAt     time.Time
}

// Store owns the configuration-document tables on PostgreSQL. It does not
// decide whether a configuration root belongs to the control plane; that
// decision stays in the config ownership registry.
type Store struct {
	pool *pgxpool.Pool
}

// New applies the configuration-store schema before accepting reads or
// writes. Other control-plane schemas remain separate until their own
// migration is consolidated deliberately.
func New(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL configuration store requires a pool")
	}
	store := &Store{pool: pool}
	if err := store.EnsureSchema(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

// EnsureSchema creates the document, revision, and durable event-outbox
// tables under one advisory lock, making first startup safe across processes.
func (s *Store) EnsureSchema(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL configuration store is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin configuration store schema transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", configurationSchemaAdvisoryLock); err != nil {
		return fmt.Errorf("lock configuration store schema migration: %w", err)
	}
	for _, statement := range configurationSchema {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return fmt.Errorf("apply configuration store schema: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO configuration_schema_migrations (version, name)
		VALUES (1, 'configuration_documents')
		ON CONFLICT (version) DO NOTHING`); err != nil {
		return fmt.Errorf("record configuration store schema migration: %w", err)
	}
	var payloadShapeMigrationApplied bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM configuration_schema_migrations WHERE version = 2)`).Scan(&payloadShapeMigrationApplied); err != nil {
		return fmt.Errorf("inspect configuration store payload-shape migration: %w", err)
	}
	if !payloadShapeMigrationApplied {
		for _, statement := range configurationPayloadShapeMigration {
			if _, err := tx.Exec(ctx, statement); err != nil {
				return fmt.Errorf("apply configuration store payload-shape migration: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO configuration_schema_migrations (version, name)
			VALUES (2, 'allow_array_configuration_documents')`); err != nil {
			return fmt.Errorf("record configuration store payload-shape migration: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit configuration store schema migration: %w", err)
	}
	return nil
}

var configurationSchema = []string{
	`CREATE TABLE IF NOT EXISTS configuration_schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS configuration_documents (
		scope TEXT PRIMARY KEY,
		revision BIGINT NOT NULL CHECK (revision > 0),
		schema_version INTEGER NOT NULL CHECK (schema_version > 0),
		checksum TEXT NOT NULL CHECK (char_length(checksum) = 64),
		payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
		updated_by TEXT NOT NULL,
		update_reason TEXT NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS configuration_revisions (
		scope TEXT NOT NULL REFERENCES configuration_documents(scope) ON DELETE RESTRICT,
		revision BIGINT NOT NULL CHECK (revision > 0),
		schema_version INTEGER NOT NULL CHECK (schema_version > 0),
		checksum TEXT NOT NULL CHECK (char_length(checksum) = 64),
		payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
		actor TEXT NOT NULL,
		reason TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		PRIMARY KEY (scope, revision)
	)`,
	`CREATE INDEX IF NOT EXISTS configuration_revisions_scope_revision_idx
		ON configuration_revisions (scope, revision DESC)`,
	`CREATE TABLE IF NOT EXISTS configuration_events (
		id BIGSERIAL PRIMARY KEY,
		scope TEXT NOT NULL,
		revision BIGINT NOT NULL CHECK (revision > 0),
		created_at TIMESTAMPTZ NOT NULL,
		UNIQUE (scope, revision)
	)`,
}

// Some complete configuration documents are collections (for example,
// upstream Origin pools and advanced route rules). The initial schema only
// admitted JSON objects, which made those validated documents impossible to
// save to PostgreSQL. Version 2 expands the durable shape contract while
// continuing to reject scalar JSON values.
var configurationPayloadShapeMigration = []string{
	`ALTER TABLE configuration_documents DROP CONSTRAINT IF EXISTS configuration_documents_payload_check`,
	`ALTER TABLE configuration_documents
		ADD CONSTRAINT configuration_documents_payload_shape_check
		CHECK (jsonb_typeof(payload) IN ('object', 'array'))`,
	`ALTER TABLE configuration_revisions DROP CONSTRAINT IF EXISTS configuration_revisions_payload_check`,
	`ALTER TABLE configuration_revisions
		ADD CONSTRAINT configuration_revisions_payload_shape_check
		CHECK (jsonb_typeof(payload) IN ('object', 'array'))`,
}

// Save commits a new immutable revision and its durable notification record in
// one transaction. Per-scope advisory locking makes creation and compare-and-
// swap updates safe across independent Aegis processes.
func (s *Store) Save(ctx context.Context, input SaveInput) (Document, error) {
	prepared, err := prepareSave(input)
	if err != nil {
		return Document{}, err
	}
	if s == nil || s.pool == nil {
		return Document{}, errors.New("PostgreSQL configuration store is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Document{}, fmt.Errorf("begin configuration save transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", prepared.scope); err != nil {
		return Document{}, fmt.Errorf("lock configuration scope %q: %w", prepared.scope, err)
	}

	var currentRevision int64
	err = tx.QueryRow(ctx, `SELECT revision FROM configuration_documents WHERE scope = $1 FOR UPDATE`, prepared.scope).Scan(&currentRevision)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Document{}, fmt.Errorf("read current configuration revision: %w", err)
	}
	if !found {
		if prepared.expectedRevision != 0 {
			return Document{}, &RevisionConflictError{Scope: prepared.scope, Expected: prepared.expectedRevision, Actual: 0}
		}
		currentRevision = 0
	} else if currentRevision != prepared.expectedRevision {
		return Document{}, &RevisionConflictError{Scope: prepared.scope, Expected: prepared.expectedRevision, Actual: currentRevision}
	}

	nextRevision := currentRevision + 1
	now := time.Now().UTC()
	if !found {
		_, err = tx.Exec(ctx, `
			INSERT INTO configuration_documents
				(scope, revision, schema_version, checksum, payload, updated_by, update_reason, updated_at)
			VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)`,
			prepared.scope, nextRevision, prepared.schemaVersion, prepared.checksum, string(prepared.payload), prepared.actor, prepared.reason, now)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE configuration_documents
			SET revision = $2, schema_version = $3, checksum = $4, payload = $5::jsonb,
				updated_by = $6, update_reason = $7, updated_at = $8
			WHERE scope = $1`,
			prepared.scope, nextRevision, prepared.schemaVersion, prepared.checksum, string(prepared.payload), prepared.actor, prepared.reason, now)
	}
	if err != nil {
		return Document{}, fmt.Errorf("save configuration document: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO configuration_revisions
			(scope, revision, schema_version, checksum, payload, actor, reason, created_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)`,
		prepared.scope, nextRevision, prepared.schemaVersion, prepared.checksum, string(prepared.payload), prepared.actor, prepared.reason, now); err != nil {
		return Document{}, fmt.Errorf("save configuration revision: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO configuration_events (scope, revision, created_at)
		VALUES ($1, $2, $3)`, prepared.scope, nextRevision, now); err != nil {
		return Document{}, fmt.Errorf("save configuration event: %w", err)
	}
	notification, err := json.Marshal(struct {
		Scope    string `json:"scope"`
		Revision int64  `json:"revision"`
	}{Scope: prepared.scope, Revision: nextRevision})
	if err != nil {
		return Document{}, fmt.Errorf("encode configuration event: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_notify('"+configurationChangeChannel+"', $1)", string(notification)); err != nil {
		return Document{}, fmt.Errorf("publish configuration event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Document{}, fmt.Errorf("commit configuration save: %w", err)
	}
	return Document{
		Scope:         prepared.scope,
		Revision:      nextRevision,
		SchemaVersion: prepared.schemaVersion,
		Checksum:      prepared.checksum,
		Payload:       append(json.RawMessage(nil), prepared.payload...),
		Actor:         prepared.actor,
		Reason:        prepared.reason,
		CreatedAt:     now,
	}, nil
}

// Load returns the active configuration document for one scope.
func (s *Store) Load(ctx context.Context, scope string) (Document, bool, error) {
	if s == nil || s.pool == nil {
		return Document{}, false, errors.New("PostgreSQL configuration store is unavailable")
	}
	return loadConfigurationDocument(ctx, s.pool, scope)
}

// HasActiveDocuments reports whether PostgreSQL currently owns any
// operator-managed configuration documents. It is intentionally a narrow
// recovery guardrail: callers only need to know whether a legacy YAML archive
// would omit live control-plane state.
func (s *Store) HasActiveDocuments(ctx context.Context) (bool, error) {
	if s == nil || s.pool == nil {
		return false, errors.New("PostgreSQL configuration store is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var active bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM configuration_documents)`).Scan(&active); err != nil {
		return false, fmt.Errorf("inspect active configuration documents: %w", err)
	}
	return active, nil
}

type configurationDocumentQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadConfigurationDocument(ctx context.Context, queryer configurationDocumentQueryer, scope string) (Document, bool, error) {
	scope, err := normalizeScope(scope)
	if err != nil {
		return Document{}, false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var document Document
	var payload []byte
	err = queryer.QueryRow(ctx, `
		SELECT scope, revision, schema_version, checksum, payload, updated_by, update_reason, updated_at
		FROM configuration_documents
		WHERE scope = $1`, scope).Scan(
		&document.Scope, &document.Revision, &document.SchemaVersion, &document.Checksum,
		&payload, &document.Actor, &document.Reason, &document.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, false, nil
	}
	if err != nil {
		return Document{}, false, fmt.Errorf("load configuration document: %w", err)
	}
	document.Payload = append(json.RawMessage(nil), payload...)
	return document, true, nil
}

// ListRevisions returns newest-first immutable revisions for one scope.
func (s *Store) ListRevisions(ctx context.Context, scope string, limit int) ([]Document, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("PostgreSQL configuration store is unavailable")
	}
	scope, err := normalizeScope(scope)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("configuration revision limit must be between 1 and 100")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := s.pool.Query(ctx, `
		SELECT scope, revision, schema_version, checksum, payload, actor, reason, created_at
		FROM configuration_revisions
		WHERE scope = $1
		ORDER BY revision DESC
		LIMIT $2`, scope, limit)
	if err != nil {
		return nil, fmt.Errorf("list configuration revisions: %w", err)
	}
	defer rows.Close()

	documents := make([]Document, 0)
	for rows.Next() {
		var document Document
		var payload []byte
		if err := rows.Scan(
			&document.Scope, &document.Revision, &document.SchemaVersion, &document.Checksum,
			&payload, &document.Actor, &document.Reason, &document.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan configuration revision: %w", err)
		}
		document.Payload = append(json.RawMessage(nil), payload...)
		documents = append(documents, document)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate configuration revisions: %w", err)
	}
	return documents, nil
}

type preparedSave struct {
	scope            string
	expectedRevision int64
	schemaVersion    int
	payload          json.RawMessage
	checksum         string
	actor            string
	reason           string
}

func prepareSave(input SaveInput) (preparedSave, error) {
	scope, err := normalizeScope(input.Scope)
	if err != nil {
		return preparedSave{}, err
	}
	if input.ExpectedRevision < 0 {
		return preparedSave{}, errors.New("expected configuration revision cannot be negative")
	}
	if input.SchemaVersion < 1 {
		return preparedSave{}, errors.New("configuration schema version must be positive")
	}
	actor, err := normalizeAuditText("configuration actor", input.Actor, maxActorBytes)
	if err != nil {
		return preparedSave{}, err
	}
	reason, err := normalizeAuditText("configuration reason", input.Reason, maxReasonBytes)
	if err != nil {
		return preparedSave{}, err
	}
	payload, err := canonicalDocumentPayload(input.Payload)
	if err != nil {
		return preparedSave{}, err
	}
	digest := sha256.Sum256(payload)
	return preparedSave{
		scope:            scope,
		expectedRevision: input.ExpectedRevision,
		schemaVersion:    input.SchemaVersion,
		payload:          payload,
		checksum:         hex.EncodeToString(digest[:]),
		actor:            actor,
		reason:           reason,
	}, nil
}

func canonicalDocumentPayload(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxDocumentBytes {
		return nil, fmt.Errorf("configuration document must be between 1 and %d bytes", maxDocumentBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode configuration document: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("configuration document must contain exactly one JSON value")
		}
		return nil, fmt.Errorf("decode trailing configuration document value: %w", err)
	}
	switch value.(type) {
	case map[string]interface{}, []interface{}:
	default:
		return nil, errors.New("configuration document payload must be a JSON object or array")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonicalize configuration document: %w", err)
	}
	return json.RawMessage(canonical), nil
}

func normalizeScope(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > maxScopeBytes {
		return "", errors.New("configuration scope is invalid")
	}
	for _, part := range strings.Split(raw, ".") {
		if part == "" {
			return "", errors.New("configuration scope is invalid")
		}
		for index, character := range part {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9' && index > 0) || character == '_' {
				continue
			}
			return "", errors.New("configuration scope is invalid")
		}
	}
	return raw, nil
}

func normalizeAuditText(label, raw string, maxLength int) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > maxLength || strings.ContainsRune(raw, '\x00') {
		return "", fmt.Errorf("%s is invalid", label)
	}
	return raw, nil
}
