package storage

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// PostgreSQLPreflightTimeout bounds every temporary connection attempt,
	// including dial, authentication, and Ping.
	PostgreSQLPreflightTimeout = 8 * time.Second
)

var (
	// ErrInvalidPostgreSQLPreflightConfig deliberately carries no input value so
	// callers can safely expose a stable error code without leaking credentials.
	ErrInvalidPostgreSQLPreflightConfig = errors.New("invalid postgresql preflight configuration")
	// ErrPostgreSQLPreflightFailed is intentionally opaque. pgx errors can
	// include connection details, so they must not cross the admin API boundary.
	ErrPostgreSQLPreflightFailed = errors.New("postgresql connection preflight failed")
)

// PostgreSQLPreflightConfig is an ephemeral administrator-supplied connection
// attempt. Password is never part of the persisted configuration model.
type PostgreSQLPreflightConfig struct {
	Host     string
	Port     int
	Database string
	Username string
	Password string
	SSLMode  string
}

// PostgreSQLPreflightResult contains only non-credential metadata suitable for
// returning to the administrator after a successful temporary Ping.
type PostgreSQLPreflightResult struct {
	Driver   string `json:"driver"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	SSLMode  string `json:"ssl_mode"`
}

// PostgreSQLPreflightRunner allows the admin handler to be tested without a
// local PostgreSQL service.
type PostgreSQLPreflightRunner interface {
	Preflight(context.Context, PostgreSQLPreflightConfig) (PostgreSQLPreflightResult, error)
}

type postgreSQLPreflightRunner struct{}

// NewPostgreSQLPreflightRunner returns the real pgx-backed temporary-pool
// runner. It creates no global pool and makes no runtime storage changes.
func NewPostgreSQLPreflightRunner() PostgreSQLPreflightRunner {
	return postgreSQLPreflightRunner{}
}

// Validate validates the ephemeral PostgreSQL endpoint before a connection is
// attempted. Error messages intentionally do not include credential values.
func (c PostgreSQLPreflightConfig) Validate() error {
	if !validPostgreSQLHost(c.Host) ||
		c.Port < 1 || c.Port > 65535 ||
		!validPostgreSQLIdentifier(c.Database) ||
		!validPostgreSQLIdentifier(c.Username) ||
		!validPostgreSQLSSLMode(c.SSLMode) ||
		len(c.Password) > 4096 || strings.ContainsRune(c.Password, '\x00') {
		return ErrInvalidPostgreSQLPreflightConfig
	}
	return nil
}

func (postgreSQLPreflightRunner) Preflight(ctx context.Context, config PostgreSQLPreflightConfig) (PostgreSQLPreflightResult, error) {
	if err := config.Validate(); err != nil {
		return PostgreSQLPreflightResult{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, PostgreSQLPreflightTimeout)
	defer cancel()

	poolConfig, err := pgxpool.ParseConfig(postgreSQLPreflightDSN(config))
	if err != nil {
		return PostgreSQLPreflightResult{}, ErrInvalidPostgreSQLPreflightConfig
	}
	// The preflight needs exactly one temporary connection. pgxpool is lazy, so
	// Ping below is the bounded, real connection/authentication check.
	poolConfig.MaxConns = 1
	poolConfig.MinConns = 0
	poolConfig.ConnConfig.ConnectTimeout = PostgreSQLPreflightTimeout

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return PostgreSQLPreflightResult{}, ErrPostgreSQLPreflightFailed
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return PostgreSQLPreflightResult{}, ErrPostgreSQLPreflightFailed
	}

	return PostgreSQLPreflightResult{
		Driver:   string(ControlDriverPostgreSQL),
		Host:     strings.TrimSpace(config.Host),
		Port:     config.Port,
		Database: strings.TrimSpace(config.Database),
		SSLMode:  normalizedPostgreSQLSSLMode(config.SSLMode),
	}, nil
}

func postgreSQLPreflightDSN(config PostgreSQLPreflightConfig) string {
	connectionURL := &url.URL{
		Scheme: "postgres",
		Host:   net.JoinHostPort(strings.TrimSpace(config.Host), fmt.Sprintf("%d", config.Port)),
		Path:   strings.TrimSpace(config.Database),
		User:   url.UserPassword(strings.TrimSpace(config.Username), config.Password),
	}
	query := connectionURL.Query()
	query.Set("sslmode", normalizedPostgreSQLSSLMode(config.SSLMode))
	query.Set("application_name", "aegis-postgresql-preflight")
	connectionURL.RawQuery = query.Encode()
	return connectionURL.String()
}

func validPostgreSQLHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n\x00/@?#\\") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func validPostgreSQLIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 63 && !strings.ContainsAny(value, "\x00\r\n")
}

func validPostgreSQLSSLMode(value string) bool {
	switch normalizedPostgreSQLSSLMode(value) {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
		return true
	default:
		return false
	}
}

func normalizedPostgreSQLSSLMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "require"
	}
	return value
}
