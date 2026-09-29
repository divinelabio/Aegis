package storage

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const controlDatabaseConnectTimeout = 10 * time.Second

var (
	// ControlDB is the mandatory PostgreSQL pool for transactional Aegis state.
	// Analytics continue to use DB, the ClickHouse pool.
	ControlDB           *pgxpool.Pool
	controlMu           sync.Mutex
	activeControlConfig ControlConfig
)

// InitControlDB resolves the configured secret reference, opens the PostgreSQL
// control-plane pool, and verifies that it is usable. It never accepts a
// password in Config: the only supported production reference is env:NAME.
func InitControlDB(ctx context.Context, control ControlConfig) (*pgxpool.Pool, error) {
	controlMu.Lock()
	defer controlMu.Unlock()

	if ControlDB != nil {
		return ControlDB, nil
	}
	if !control.Enabled {
		return nil, errors.New("storage.control.enabled must be true; configure PostgreSQL before starting Aegis")
	}
	if control.Driver != ControlDriverPostgreSQL {
		return nil, fmt.Errorf("unsupported control database driver %q", control.Driver)
	}

	password, err := resolveControlDatabasePassword(control.PasswordSecretRef)
	if err != nil {
		return nil, err
	}
	poolConfig, err := pgxpool.ParseConfig(controlPostgreSQLDSN(control, password))
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL control database configuration: %w", err)
	}
	poolConfig.MinConns = 2
	poolConfig.MaxConns = 50
	poolConfig.ConnConfig.ConnectTimeout = controlDatabaseConnectTimeout
	poolConfig.MaxConnLifetime = time.Hour
	poolConfig.MaxConnIdleTime = 30 * time.Minute
	poolConfig.HealthCheckPeriod = time.Minute

	connectCtx, cancel := context.WithTimeout(ctx, controlDatabaseConnectTimeout)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(connectCtx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL control database: %w", err)
	}
	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping PostgreSQL control database: %w", err)
	}
	ControlDB = pool
	activeControlConfig = control
	return pool, nil
}

// CloseControlDB closes the PostgreSQL pool during process shutdown and test
// cleanup. It is safe to call more than once.
func CloseControlDB() {
	controlMu.Lock()
	defer controlMu.Unlock()
	if ControlDB == nil {
		return
	}
	ControlDB.Close()
	ControlDB = nil
	activeControlConfig = ControlConfig{}
}

// ControlConfigIsActive reports whether the currently open control pool was
// started from the supplied configuration. It is used to identify a safe,
// restart-required pending revision without exposing database credentials.
func ControlConfigIsActive(control ControlConfig) bool {
	controlMu.Lock()
	defer controlMu.Unlock()
	return ControlDB != nil && activeControlConfig == control
}

func resolveControlDatabasePassword(reference string) (string, error) {
	return resolveEnvironmentSecret(reference, "storage.control.password_secret_ref", "PostgreSQL control database")
}

func controlPostgreSQLDSN(control ControlConfig, password string) string {
	dsn := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(control.Username, password),
		Host:   fmt.Sprintf("%s:%d", control.Host, control.Port),
		Path:   control.Database,
	}
	query := dsn.Query()
	query.Set("sslmode", strings.ToLower(strings.TrimSpace(control.SSLMode)))
	query.Set("application_name", "aegis-control-plane")
	dsn.RawQuery = query.Encode()
	return dsn.String()
}
