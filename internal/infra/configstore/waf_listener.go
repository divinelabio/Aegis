package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartWAFChangeListener synchronizes WAF Core configuration from PostgreSQL
// after LISTEN setup and every reconnect.
func (s *Store) StartWAFChangeListener(ctx context.Context, apply func(context.Context, config.WAFDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("waf change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.WAFConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentWAF(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentWAF(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.WAFDocument) error) error {
	document, found, err := loadWAFFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current waf configuration: %w", err)
	}
	if !found {
		return errors.New("waf configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply waf configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
