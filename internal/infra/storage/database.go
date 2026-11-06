package storage

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// DBDriver represents the database driver type
type DBDriver string

const (
	DriverPostgreSQL DBDriver = "postgresql"
	DriverClickHouse DBDriver = "clickhouse"

	DefaultAnalyticsRetentionDays = 30
	MaxAnalyticsRetentionDays     = 30
)

// AnalyticsMode controls whether event analytics participates in a
// process start. PostgreSQL is the default event store; ClickHouse is optional.
type AnalyticsMode string

const (
	AnalyticsModeRequired AnalyticsMode = "required"
	AnalyticsModeOptional AnalyticsMode = "optional"
	AnalyticsModeDisabled AnalyticsMode = "disabled"
)

// ControlDriver identifies the database engine used by the transactional
// control plane. It is intentionally separate from DBDriver, which configures
// the ClickHouse analytics store.
type ControlDriver string

const (
	ControlDriverPostgreSQL ControlDriver = "postgresql"
)

// StorageConfig contains the bootstrap configuration for persistent storage.
// The control database opens only during process startup after its secret
// reference has been resolved.
type StorageConfig struct {
	Control   ControlConfig   `json:"control" mapstructure:"control" yaml:"control"`
	Analytics AnalyticsConfig `json:"analytics" mapstructure:"analytics" yaml:"analytics"`
}

// ControlConfig describes the mandatory PostgreSQL control-plane database
// without ever carrying a password. PasswordSecretRef is resolved only at
// process startup and is never written to configuration, logs, or APIs.
type ControlConfig struct {
	Enabled           bool          `json:"enabled" mapstructure:"enabled" yaml:"enabled"`
	Driver            ControlDriver `json:"driver" mapstructure:"driver" yaml:"driver"`
	Host              string        `json:"host" mapstructure:"host" yaml:"host"`
	Port              int           `json:"port" mapstructure:"port" yaml:"port"`
	Database          string        `json:"database" mapstructure:"database" yaml:"database"`
	Username          string        `json:"username" mapstructure:"username" yaml:"username"`
	PasswordSecretRef string        `json:"password_secret_ref" mapstructure:"password_secret_ref" yaml:"password_secret_ref"`
	SSLMode           string        `json:"ssl_mode" mapstructure:"ssl_mode" yaml:"ssl_mode"`
}

// AnalyticsConfig describes the telemetry/event store (PostgreSQL by default,
// or optional ClickHouse). The password is always supplied through
// PasswordSecretRef and is resolved only during process startup; it is never
// persisted in configuration or returned to the browser.
type AnalyticsConfig struct {
	Mode              AnalyticsMode `json:"mode" mapstructure:"mode" yaml:"mode"`
	Driver            DBDriver      `json:"driver" mapstructure:"driver" yaml:"driver"`
	Host              string        `json:"host" mapstructure:"host" yaml:"host"`
	Port              int           `json:"port" mapstructure:"port" yaml:"port"`
	Database          string        `json:"database" mapstructure:"database" yaml:"database"`
	Username          string        `json:"username" mapstructure:"username" yaml:"username"`
	PasswordSecretRef string        `json:"password_secret_ref" mapstructure:"password_secret_ref" yaml:"password_secret_ref"`
	Secure            bool          `json:"secure" mapstructure:"secure" yaml:"secure"`
	RetentionDays     int           `json:"retention_days" mapstructure:"retention_days" yaml:"retention_days"`

	// Connection pool settings
	MaxOpenConns    int           `json:"max_open_conns" mapstructure:"max_open_conns" yaml:"max_open_conns"`
	MaxIdleConns    int           `json:"max_idle_conns" mapstructure:"max_idle_conns" yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime" mapstructure:"conn_max_lifetime" yaml:"conn_max_lifetime"`
}

// EffectiveDriver returns the normalized analytics driver, defaulting to PostgreSQL.
func (c AnalyticsConfig) EffectiveDriver() DBDriver {
	driver := strings.ToLower(strings.TrimSpace(string(c.Driver)))
	switch driver {
	case "", "postgres", "postgresql":
		return DriverPostgreSQL
	case "clickhouse":
		return DriverClickHouse
	default:
		return DBDriver(driver)
	}
}

// EffectiveRetentionDays returns the event retention window in days, defaulting
// to 30 days and capped at 30 days.
func (c AnalyticsConfig) EffectiveRetentionDays() int {
	if c.RetentionDays <= 0 || c.RetentionDays > MaxAnalyticsRetentionDays {
		return DefaultAnalyticsRetentionDays
	}
	return c.RetentionDays
}

// EffectiveMode makes PostgreSQL event analytics active by default in optional
// mode (so it never prevents the control plane from starting), while keeping
// ClickHouse opt-in when unconfigured.
func (c AnalyticsConfig) EffectiveMode() AnalyticsMode {
	mode := AnalyticsMode(strings.ToLower(strings.TrimSpace(string(c.Mode))))
	if mode == "" {
		if c.EffectiveDriver() == DriverPostgreSQL {
			return AnalyticsModeOptional
		}
		return AnalyticsModeDisabled
	}
	return mode
}

// Validate verifies only durable analytics metadata. A disabled analytics
// store intentionally needs no connection settings. The empty secret reference
// is permitted here so a fresh bootstrap configuration can be inspected and
// staged; startup itself requires the referenced secret.
func (c AnalyticsConfig) Validate() error {
	if c.RetentionDays < 0 || c.RetentionDays > MaxAnalyticsRetentionDays {
		return fmt.Errorf("storage.analytics.retention_days must be between 1 and %d", MaxAnalyticsRetentionDays)
	}
	switch c.EffectiveMode() {
	case AnalyticsModeRequired, AnalyticsModeOptional, AnalyticsModeDisabled:
	default:
		return fmt.Errorf("storage.analytics.mode must be required, optional, or disabled")
	}
	if c.EffectiveMode() == AnalyticsModeDisabled {
		return nil
	}
	if c.MaxOpenConns < 0 || c.MaxIdleConns < 0 {
		return errors.New("storage.analytics connection pool settings cannot be negative")
	}
	switch c.EffectiveDriver() {
	case DriverPostgreSQL:
		if strings.TrimSpace(c.Host) != "" && !validAnalyticsHost(c.Host) {
			return errors.New("storage.analytics.host is invalid")
		}
		if c.Port != 0 && (c.Port < 1 || c.Port > 65535) {
			return errors.New("storage.analytics.port must be 1-65535")
		}
		if strings.TrimSpace(c.Database) != "" && !validAnalyticsIdentifier(c.Database) {
			return errors.New("storage.analytics.database is invalid")
		}
		if strings.TrimSpace(c.Username) != "" && !validAnalyticsIdentifier(c.Username) {
			return errors.New("storage.analytics.username is invalid")
		}
		if c.PasswordSecretRef != "" && !validEnvironmentSecretReference(c.PasswordSecretRef) {
			return errors.New("storage.analytics.password_secret_ref must be an environment secret reference")
		}
		return nil
	case DriverClickHouse:
		if !validAnalyticsHost(c.Host) {
			return errors.New("storage.analytics.host is invalid")
		}
		if c.Port < 1 || c.Port > 65535 {
			return errors.New("storage.analytics.port must be 1-65535")
		}
		if !validAnalyticsIdentifier(c.Database) {
			return errors.New("storage.analytics.database is invalid")
		}
		if !validAnalyticsIdentifier(c.Username) {
			return errors.New("storage.analytics.username is invalid")
		}
		if c.PasswordSecretRef != "" && !validEnvironmentSecretReference(c.PasswordSecretRef) {
			return errors.New("storage.analytics.password_secret_ref must be an environment secret reference")
		}
		return nil
	default:
		return fmt.Errorf("storage.analytics.driver must be %q or %q", DriverPostgreSQL, DriverClickHouse)
	}
}

type clickHouseRuntimeConfig struct {
	Host            string
	Port            int
	Database        string
	Username        string
	Password        string
	Secure          bool
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

func (c AnalyticsConfig) runtimeConfig() (clickHouseRuntimeConfig, error) {
	if c.EffectiveMode() == AnalyticsModeDisabled {
		return clickHouseRuntimeConfig{}, errors.New("storage.analytics is disabled")
	}
	if err := c.Validate(); err != nil {
		return clickHouseRuntimeConfig{}, err
	}
	password, err := resolveAnalyticsDatabasePassword(c.PasswordSecretRef)
	if err != nil {
		return clickHouseRuntimeConfig{}, err
	}
	return clickHouseRuntimeConfig{
		Host:            c.Host,
		Port:            c.Port,
		Database:        c.Database,
		Username:        c.Username,
		Password:        password,
		Secure:          c.Secure,
		MaxOpenConns:    c.MaxOpenConns,
		MaxIdleConns:    c.MaxIdleConns,
		ConnMaxLifetime: c.ConnMaxLifetime,
	}, nil
}

func resolveAnalyticsDatabasePassword(reference string) (string, error) {
	return resolveEnvironmentSecret(reference, "storage.analytics.password_secret_ref", "ClickHouse analytics database")
}

func resolveEnvironmentSecret(reference, configKey, databaseName string) (string, error) {
	reference = strings.TrimSpace(reference)
	if !strings.HasPrefix(reference, "env:") {
		return "", fmt.Errorf("%s must use env:NAME", configKey)
	}
	name := strings.TrimPrefix(reference, "env:")
	password, ok := os.LookupEnv(name)
	if !ok || password == "" {
		return "", fmt.Errorf("%s secret %q is not available", databaseName, name)
	}
	return password, nil
}

func validEnvironmentSecretReference(reference string) bool {
	reference = strings.TrimSpace(reference)
	if !strings.HasPrefix(reference, "env:") {
		return false
	}
	name := strings.TrimPrefix(reference, "env:")
	if name == "" {
		return false
	}
	for index, char := range name {
		if (char >= 'A' && char <= 'Z') || char == '_' || (index > 0 && char >= '0' && char <= '9') {
			continue
		}
		return false
	}
	return true
}

func validAnalyticsHost(host string) bool {
	host = strings.TrimSpace(host)
	return host != "" && len(host) <= 253 && !strings.ContainsAny(host, " \t\r\n\x00/@?#\\")
}

func validAnalyticsIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for index, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '_' || (index > 0 && char >= '0' && char <= '9') {
			continue
		}
		return false
	}
	return true
}
