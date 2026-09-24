package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const controlSchemaLockID int64 = 4_129_741_033

// PostgreSQLRepository is the transactional source of truth for Aegis
// identities, RBAC, administrative audit records, and reset tokens.
type PostgreSQLRepository struct {
	pool *pgxpool.Pool
}

func NewPostgreSQLRepository(ctx context.Context, pool *pgxpool.Pool) (*PostgreSQLRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL control database pool is required")
	}
	repo := &PostgreSQLRepository{pool: pool}
	if err := repo.EnsureSchema(ctx); err != nil {
		return nil, err
	}
	return repo, nil
}

// EnsureSchema applies idempotent control-plane schema setup under a database
// advisory lock so simultaneous Aegis processes never race migrations/seeding.
func (r *PostgreSQLRepository) EnsureSchema(ctx context.Context) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin control schema transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, controlSchemaLockID); err != nil {
		return fmt.Errorf("lock control schema migration: %w", err)
	}
	for _, statement := range postgreSQLControlSchema {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return fmt.Errorf("apply PostgreSQL control schema: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO control_schema_migrations (version, name)
		VALUES (1, 'initial_control_plane')
		ON CONFLICT (version) DO NOTHING`); err != nil {
		return fmt.Errorf("record PostgreSQL control schema migration: %w", err)
	}
	if err := seedDefaultControlData(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit PostgreSQL control schema: %w", err)
	}
	return nil
}

var postgreSQLControlSchema = []string{
	`CREATE TABLE IF NOT EXISTS control_schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS roles (
		id UUID PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		description TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS permissions (
		id UUID PRIMARY KEY,
		slug TEXT NOT NULL UNIQUE,
		description TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS role_permissions (
		role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
		permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (role_id, permission_id)
	)`,
	`CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role_id UUID NOT NULL REFERENCES roles(id),
		is_active BOOLEAN NOT NULL DEFAULT TRUE,
		mfa_secret TEXT NOT NULL DEFAULT '',
		mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
		last_login_at TIMESTAMPTZ NULL,
		failed_login_attempts INTEGER NOT NULL DEFAULT 0,
		locked_until TIMESTAMPTZ NULL,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS users_role_id_idx ON users (role_id)`,
	`CREATE TABLE IF NOT EXISTS audit_logs (
		id UUID PRIMARY KEY,
		user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
		actor_username TEXT NOT NULL DEFAULT '',
		actor_role_id TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL,
		resource TEXT NOT NULL,
		metadata TEXT NOT NULL DEFAULT '',
		ip_address TEXT NOT NULL DEFAULT '',
		peer_ip_address TEXT NOT NULL DEFAULT '',
		ip_address_source TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL
	)`,
	`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_username TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_role_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS peer_ip_address TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address_source TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS audit_logs_created_at_id_idx ON audit_logs (created_at DESC, id DESC)`,
	`CREATE INDEX IF NOT EXISTS audit_logs_action_created_at_id_idx ON audit_logs (action, created_at DESC, id DESC)`,
	`CREATE INDEX IF NOT EXISTS audit_logs_actor_created_at_id_idx ON audit_logs (actor_username, created_at DESC, id DESC)`,
	`CREATE OR REPLACE FUNCTION aegis_prevent_audit_log_mutation()
	RETURNS TRIGGER AS $$
	BEGIN
		IF TG_OP = 'DELETE' AND current_setting('aegis.audit_retention', true) = 'on' THEN
			RETURN OLD;
		END IF;
		RAISE EXCEPTION 'audit_logs is append-only';
	END;
	$$ LANGUAGE plpgsql`,
	`DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs`,
	`CREATE TRIGGER audit_logs_append_only
	BEFORE UPDATE OR DELETE ON audit_logs
	FOR EACH ROW EXECUTE FUNCTION aegis_prevent_audit_log_mutation()`,
	`CREATE TABLE IF NOT EXISTS password_resets (
		id UUID PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at TIMESTAMPTZ NOT NULL,
		used BOOLEAN NOT NULL DEFAULT FALSE,
		ip_address TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS password_resets_available_idx ON password_resets (token_hash, expires_at) WHERE used = FALSE`,
}

type defaultRoleSpec struct {
	name        string
	description string
	permissions []string
}

var defaultControlRoles = []defaultRoleSpec{
	{name: "super_admin", description: "Full administrative access across all system functions", permissions: []string{"users:read", "users:write", "audit:read", "logs:read", "waf:read", "waf:write", "app_security:read", "app_security:write", "api_security:read", "api_security:write", "traffic:read", "traffic:write", "traffic:admin", "rules:read", "rules:write", "analytics:read", "system:read", "system:config", "sessions:delete", "infra:read", "infra:write"}},
	{name: "admin", description: "Administrative access across security policies, traffic routing, and certificates", permissions: []string{"infra:read", "infra:write", "logs:read", "analytics:read", "waf:read", "waf:write", "app_security:read", "app_security:write", "api_security:read", "api_security:write", "traffic:read", "traffic:write", "traffic:admin", "rules:read", "rules:write", "system:read"}},
	{name: "auditor", description: "Compliance and security audit review with access to audit logs, events, and telemetry", permissions: []string{"audit:read", "logs:read", "analytics:read", "waf:read", "app_security:read", "api_security:read", "traffic:read", "rules:read", "users:read", "system:read"}},
	{name: "viewer", description: "Read-only observability access to dashboards and metrics", permissions: []string{"logs:read", "analytics:read", "waf:read", "app_security:read", "api_security:read", "traffic:read", "infra:read"}},
}

func seedDefaultControlData(ctx context.Context, tx pgx.Tx) error {
	for _, spec := range defaultControlRoles {
		if _, err := tx.Exec(ctx, `
			INSERT INTO roles (id, name, description, created_at, updated_at)
			VALUES ($1, $2, $3, NOW(), NOW())
			ON CONFLICT (name) DO NOTHING`, uuid.New(), spec.name, spec.description); err != nil {
			return fmt.Errorf("seed control role %q: %w", spec.name, err)
		}
		var roleID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM roles WHERE name = $1`, spec.name).Scan(&roleID); err != nil {
			return fmt.Errorf("read control role %q: %w", spec.name, err)
		}
		for _, slug := range spec.permissions {
			permissionID, err := ensureControlPermission(ctx, tx, slug)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO role_permissions (role_id, permission_id)
				VALUES ($1, $2) ON CONFLICT DO NOTHING`, roleID, permissionID); err != nil {
				return fmt.Errorf("seed permission %q: %w", slug, err)
			}
		}
	}
	for source, targets := range map[string][]string{"waf:read": {"app_security:read", "api_security:read", "traffic:read"}, "waf:write": {"app_security:write", "api_security:write", "traffic:write"}, "system:config": {"traffic:admin"}} {
		for _, target := range targets {
			if _, err := ensureControlPermission(ctx, tx, target); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO role_permissions (role_id, permission_id)
				SELECT rp.role_id, target.id
				FROM role_permissions rp
				JOIN permissions source_permission ON source_permission.id = rp.permission_id
				JOIN permissions target ON target.slug = $2
				WHERE source_permission.slug = $1
				ON CONFLICT DO NOTHING`, source, target); err != nil {
				return fmt.Errorf("backfill section permission %q: %w", target, err)
			}
		}
	}
	return nil
}

func ensureControlPermission(ctx context.Context, tx pgx.Tx, slug string) (uuid.UUID, error) {
	if _, err := tx.Exec(ctx, `
		INSERT INTO permissions (id, slug, description)
		VALUES ($1, $2, '') ON CONFLICT (slug) DO NOTHING`, uuid.New(), slug); err != nil {
		return uuid.Nil, fmt.Errorf("create control permission %q: %w", slug, err)
	}
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM permissions WHERE slug = $1`, slug).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("read control permission %q: %w", slug, err)
	}
	return id, nil
}

func (r *PostgreSQLRepository) CreateUser(ctx context.Context, u *User) error {
	if u == nil {
		return errors.New("user is required")
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now
	_, err := r.pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, role_id, is_active, mfa_secret, mfa_enabled, last_login_at, failed_login_attempts, locked_until, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO UPDATE SET
			username = EXCLUDED.username, email = EXCLUDED.email, password_hash = EXCLUDED.password_hash,
			role_id = EXCLUDED.role_id, is_active = EXCLUDED.is_active, mfa_secret = EXCLUDED.mfa_secret,
			mfa_enabled = EXCLUDED.mfa_enabled, last_login_at = EXCLUDED.last_login_at,
			failed_login_attempts = EXCLUDED.failed_login_attempts, locked_until = EXCLUDED.locked_until,
			updated_at = EXCLUDED.updated_at`,
		u.ID, u.Username, u.Email, u.PasswordHash, u.RoleID, u.IsActive, u.MFASecret, u.MFAEnabled,
		nullableTime(u.LastLoginAt), u.FailedLoginAttempts, nullableTime(u.LockedUntil), u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create PostgreSQL user: %w", err)
	}
	return nil
}

func (r *PostgreSQLRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	return r.queryUser(ctx, `id = $1`, id)
}

func (r *PostgreSQLRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return r.queryUser(ctx, `email = $1`, email)
}

func (r *PostgreSQLRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return r.queryUser(ctx, `username = $1`, username)
}

func (r *PostgreSQLRepository) queryUser(ctx context.Context, where string, value any) (*User, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, username, email, password_hash, role_id, is_active, mfa_secret, mfa_enabled,
			last_login_at, failed_login_attempts, locked_until, created_at, updated_at
		FROM users WHERE `+where, value)
	user, err := scanPostgreSQLUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func scanPostgreSQLUser(row pgx.Row) (*User, error) {
	var user User
	var lastLogin, lockedUntil pgtype.Timestamptz
	if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.RoleID,
		&user.IsActive, &user.MFASecret, &user.MFAEnabled, &lastLogin, &user.FailedLoginAttempts,
		&lockedUntil, &user.CreatedAt, &user.UpdatedAt); err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		user.LastLoginAt = lastLogin.Time
	}
	if lockedUntil.Valid {
		user.LockedUntil = lockedUntil.Time
	}
	return &user, nil
}

func (r *PostgreSQLRepository) UpdateUser(ctx context.Context, u *User) error {
	if u == nil || u.ID == uuid.Nil {
		return errors.New("user id is required")
	}
	existing, err := r.GetUserByID(ctx, u.ID)
	if err != nil || existing == nil {
		return err
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = existing.CreatedAt
	}
	return r.CreateUser(ctx, u)
}

func (r *PostgreSQLRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	command, err := r.pool.Exec(ctx, `
		UPDATE users SET is_active = FALSE, mfa_secret = '', mfa_enabled = FALSE, updated_at = NOW()
		WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return nil
	}
	return nil
}

func (r *PostgreSQLRepository) ListUsers(ctx context.Context, limit, offset int) ([]User, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, username, email, role_id, is_active, last_login_at, created_at
		FROM users ORDER BY updated_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		var user User
		var lastLogin pgtype.Timestamptz
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.RoleID, &user.IsActive, &lastLogin, &user.CreatedAt); err != nil {
			return nil, err
		}
		if lastLogin.Valid {
			user.LastLoginAt = lastLogin.Time
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (r *PostgreSQLRepository) IncrementFailedLogin(ctx context.Context, username string) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var attempts int
	if err := tx.QueryRow(ctx, `SELECT failed_login_attempts FROM users WHERE username = $1 FOR UPDATE`, username).Scan(&attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	attempts++
	var lockedUntil any
	if attempts >= 5 {
		lockedUntil = time.Now().UTC().Add(15 * time.Minute)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET failed_login_attempts = $1, locked_until = $2, updated_at = NOW()
		WHERE username = $3`, attempts, lockedUntil, username); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PostgreSQLRepository) ResetFailedLogin(ctx context.Context, username string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW(), updated_at = NOW()
		WHERE username = $1`, username)
	return err
}

func (r *PostgreSQLRepository) UpdateMFASecret(ctx context.Context, id uuid.UUID, secret string, enabled bool) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE users SET mfa_secret = $1, mfa_enabled = $2, updated_at = NOW() WHERE id = $3`, secret, enabled, id)
	return err
}

func (r *PostgreSQLRepository) GetRoleByID(ctx context.Context, id uuid.UUID) (*Role, error) {
	return r.queryRole(ctx, `id = $1`, id)
}

func (r *PostgreSQLRepository) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	return r.queryRole(ctx, `name = $1`, name)
}

func (r *PostgreSQLRepository) queryRole(ctx context.Context, where string, value any) (*Role, error) {
	var role Role
	err := r.pool.QueryRow(ctx, `SELECT id, name, description, created_at, updated_at FROM roles WHERE `+where, value).
		Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *PostgreSQLRepository) CreateRole(ctx context.Context, role *Role) error {
	if role == nil {
		return errors.New("role is required")
	}
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	now := time.Now().UTC()
	if role.CreatedAt.IsZero() {
		role.CreatedAt = now
	}
	role.UpdatedAt = now
	_, err := r.pool.Exec(ctx, `
		INSERT INTO roles (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)`, role.ID, role.Name, role.Description, role.CreatedAt, role.UpdatedAt)
	return err
}

func (r *PostgreSQLRepository) UpdateRole(ctx context.Context, role *Role) error {
	if role == nil || role.ID == uuid.Nil {
		return errors.New("role id is required")
	}
	role.UpdatedAt = time.Now().UTC()
	_, err := r.pool.Exec(ctx, `UPDATE roles SET name = $1, description = $2, updated_at = $3 WHERE id = $4`, role.Name, role.Description, role.UpdatedAt, role.ID)
	return err
}

func (r *PostgreSQLRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM roles WHERE id = $1`, id)
	return err
}

func (r *PostgreSQLRepository) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, name, description, created_at, updated_at FROM roles ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := make([]Role, 0)
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *PostgreSQLRepository) GetPermissionsForRole(ctx context.Context, roleID uuid.UUID) ([]Permission, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT p.id, p.slug, p.description FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = $1 ORDER BY p.slug`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPermissions(rows)
}

func (r *PostgreSQLRepository) ListPermissionsForRoles(ctx context.Context) (map[uuid.UUID][]Permission, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT rp.role_id, p.id, p.slug, p.description FROM role_permissions rp
		JOIN permissions p ON p.id = rp.permission_id ORDER BY rp.role_id, p.slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	permissions := make(map[uuid.UUID][]Permission)
	for rows.Next() {
		var roleID uuid.UUID
		var permission Permission
		if err := rows.Scan(&roleID, &permission.ID, &permission.Slug, &permission.Description); err != nil {
			return nil, err
		}
		permissions[roleID] = append(permissions[roleID], permission)
	}
	return permissions, rows.Err()
}

func (r *PostgreSQLRepository) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, slug, description FROM permissions ORDER BY slug ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPermissions(rows)
}

func scanPermissions(rows pgx.Rows) ([]Permission, error) {
	permissions := make([]Permission, 0)
	for rows.Next() {
		var permission Permission
		if err := rows.Scan(&permission.ID, &permission.Slug, &permission.Description); err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}
	return permissions, rows.Err()
}

func (r *PostgreSQLRepository) SetPermissionsForRole(ctx context.Context, roleID uuid.UUID, permissions []Permission) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID); err != nil {
		return err
	}
	for _, permission := range permissions {
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, roleID, permission.ID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *PostgreSQLRepository) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

func (r *PostgreSQLRepository) CountActiveUsersByRole(ctx context.Context, roleID uuid.UUID) (int64, error) {
	var count int64
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role_id = $1 AND is_active = TRUE`, roleID).Scan(&count)
	return count, err
}

func (r *PostgreSQLRepository) CountUsersByRole(ctx context.Context, roleID uuid.UUID) (int64, error) {
	var count int64
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role_id = $1`, roleID).Scan(&count)
	return count, err
}

func (r *PostgreSQLRepository) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	if log == nil {
		return errors.New("audit log is required")
	}
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO audit_logs (
			id, user_id, actor_username, actor_role_id, action, resource,
			metadata, ip_address, peer_ip_address, ip_address_source, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		log.ID, log.UserID, log.ActorUsername, log.ActorRoleID, log.Action, log.Resource,
		log.Metadata, log.IPAddress, log.PeerIPAddress, log.IPAddressSource, log.CreatedAt)
	return err
}

func (r *PostgreSQLRepository) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	return r.QueryAuditLogs(ctx, AuditLogQuery{Limit: limit})
}

// QueryAuditLogs returns one bounded page of audit records using only exact
// filters and a stable cursor. The caller requests one extra row when it needs
// to determine whether a following page exists.
func (r *PostgreSQLRepository) QueryAuditLogs(ctx context.Context, query AuditLogQuery) ([]AuditLog, error) {
	if query.Limit < 1 {
		return nil, errors.New("audit query limit must be positive")
	}

	clauses := make([]string, 0, 5)
	args := make([]any, 0, 7)
	argument := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if query.Action != "" {
		clauses = append(clauses, "action = "+argument(query.Action))
	}
	if query.ActorUsername != "" {
		clauses = append(clauses, "actor_username = "+argument(query.ActorUsername))
	}
	if query.From != nil {
		clauses = append(clauses, "created_at >= "+argument(query.From.UTC()))
	}
	if query.To != nil {
		clauses = append(clauses, "created_at <= "+argument(query.To.UTC()))
	}
	if query.Cursor != nil {
		createdAt := argument(query.Cursor.CreatedAt.UTC())
		id := argument(query.Cursor.ID)
		clauses = append(clauses, "(created_at, id) < ("+createdAt+", "+id+")")
	}

	statement := `
		SELECT id, user_id, actor_username, actor_role_id, action, resource,
			metadata, ip_address, peer_ip_address, ip_address_source, created_at
		FROM audit_logs`
	if len(clauses) > 0 {
		statement += " WHERE " + strings.Join(clauses, " AND ")
	}
	statement += " ORDER BY created_at DESC, id DESC LIMIT " + argument(query.Limit)

	rows, err := r.pool.Query(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	logs := make([]AuditLog, 0)
	for rows.Next() {
		var log AuditLog
		if err := rows.Scan(
			&log.ID, &log.UserID, &log.ActorUsername, &log.ActorRoleID, &log.Action, &log.Resource,
			&log.Metadata, &log.IPAddress, &log.PeerIPAddress, &log.IPAddressSource, &log.CreatedAt,
		); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

// PruneAuditLogs removes only records older than an explicit retention cutoff.
// It is the sole repository mutation path for audit logs: the database trigger
// rejects all other updates and deletes.
func (r *PostgreSQLRepository) PruneAuditLogs(ctx context.Context, before time.Time) (int64, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("begin audit retention transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT set_config('aegis.audit_retention', 'on', true)`); err != nil {
		return 0, fmt.Errorf("enable audit retention transaction scope: %w", err)
	}
	tag, err := tx.Exec(ctx, `DELETE FROM audit_logs WHERE created_at < $1`, before.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune audit logs: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit audit retention transaction: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *PostgreSQLRepository) CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time, ip string) error {
	now := time.Now().UTC()
	_, err := r.pool.Exec(ctx, `
		INSERT INTO password_resets (id, user_id, token_hash, expires_at, used, ip_address, created_at, updated_at)
		VALUES ($1, $2, $3, $4, FALSE, $5, $6, $6)`, uuid.New(), userID, tokenHash, expiresAt, ip, now)
	return err
}

func (r *PostgreSQLRepository) GetPasswordResetToken(ctx context.Context, tokenHash string) (*PasswordResetToken, error) {
	return r.queryPasswordResetToken(ctx, `token_hash = $1`, tokenHash)
}

func (r *PostgreSQLRepository) queryPasswordResetToken(ctx context.Context, where string, value any) (*PasswordResetToken, error) {
	var token PasswordResetToken
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, used, ip_address, created_at
		FROM password_resets WHERE `+where, value).
		Scan(&token.ID, &token.UserID, &token.TokenHash, &token.ExpiresAt, &token.Used, &token.IPAddress, &token.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *PostgreSQLRepository) ConsumePasswordResetToken(ctx context.Context, tokenHash string, now time.Time) (*PasswordResetToken, error) {
	var token PasswordResetToken
	err := r.pool.QueryRow(ctx, `
		UPDATE password_resets SET used = TRUE, updated_at = $2
		WHERE token_hash = $1 AND used = FALSE AND expires_at > $2
		RETURNING id, user_id, token_hash, expires_at, used, ip_address, created_at`, tokenHash, now.UTC()).
		Scan(&token.ID, &token.UserID, &token.TokenHash, &token.ExpiresAt, &token.Used, &token.IPAddress, &token.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *PostgreSQLRepository) MarkPasswordResetTokenUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE password_resets SET used = TRUE, updated_at = NOW() WHERE id = $1`, id)
	return err
}

func (r *PostgreSQLRepository) DeletePasswordResetToken(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM password_resets WHERE id = $1`, id)
	return err
}

var _ Repository = (*PostgreSQLRepository)(nil)
