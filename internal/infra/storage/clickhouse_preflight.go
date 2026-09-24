package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// ClickHousePreflightTimeout bounds a transient operator connection test.
const ClickHousePreflightTimeout = 8 * time.Second

// ClickHousePreflightConfig is deliberately separate from AnalyticsConfig: it
// contains a short-lived password supplied only for a connection test.
type ClickHousePreflightConfig struct {
	Host     string
	Port     int
	Database string
	Username string
	Password string
	Secure   bool
}

func (c ClickHousePreflightConfig) Validate() error {
	if !validAnalyticsHost(c.Host) {
		return fmt.Errorf("invalid ClickHouse host")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid ClickHouse port")
	}
	if !validAnalyticsIdentifier(c.Database) {
		return fmt.Errorf("invalid ClickHouse database")
	}
	if !validAnalyticsIdentifier(c.Username) {
		return fmt.Errorf("invalid ClickHouse username")
	}
	if strings.TrimSpace(c.Password) == "" {
		return fmt.Errorf("ClickHouse password is required for preflight")
	}
	return nil
}

// ClickHousePreflightResult contains only non-sensitive connection metadata.
type ClickHousePreflightResult struct {
	Driver   string `json:"driver"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	Secure   bool   `json:"secure"`
}

// ClickHousePreflightRunner enables a fake-free, server-side connection test
// while retaining deterministic handler tests.
type ClickHousePreflightRunner interface {
	Preflight(context.Context, ClickHousePreflightConfig) (ClickHousePreflightResult, error)
}

type clickHousePreflightRunner struct{}

func NewClickHousePreflightRunner() ClickHousePreflightRunner {
	return clickHousePreflightRunner{}
}

func (clickHousePreflightRunner) Preflight(ctx context.Context, config ClickHousePreflightConfig) (ClickHousePreflightResult, error) {
	if err := config.Validate(); err != nil {
		return ClickHousePreflightResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, ClickHousePreflightTimeout)
	defer cancel()
	db := clickhouse.OpenDB(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", config.Host, config.Port)},
		Auth: clickhouse.Auth{
			Database: config.Database,
			Username: config.Username,
			Password: config.Password,
		},
		TLS:         clickhouseTLSConfig(config.Secure, config.Host),
		DialTimeout: ClickHousePreflightTimeout,
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
	})
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return ClickHousePreflightResult{}, fmt.Errorf("ping ClickHouse: %w", err)
	}
	return ClickHousePreflightResult{
		Driver:   string(DriverClickHouse),
		Host:     config.Host,
		Port:     config.Port,
		Database: config.Database,
		Secure:   config.Secure,
	}, nil
}
