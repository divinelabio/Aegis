package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartHTTPSecurityChangeListener synchronizes HTTP Security configuration from PostgreSQL
// after LISTEN setup and every reconnect.
func (s *Store) StartHTTPSecurityChangeListener(ctx context.Context, apply func(context.Context, config.HTTPSecurityDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("http security change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.HTTPSecurityConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentHTTPSecurity(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentHTTPSecurity(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.HTTPSecurityDocument) error) error {
	document, found, err := loadHTTPSecurityFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current http security configuration: %w", err)
	}
	if !found {
		return errors.New("http security configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply http security configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
