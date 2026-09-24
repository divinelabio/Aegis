package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartAPISecurityChangeListener synchronizes API Security configuration from PostgreSQL
// after LISTEN setup and every reconnect.
func (s *Store) StartAPISecurityChangeListener(ctx context.Context, apply func(context.Context, config.APISecurityDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("api security change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.APISecurityConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentAPISecurity(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentAPISecurity(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.APISecurityDocument) error) error {
	document, found, err := loadAPISecurityFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current api security configuration: %w", err)
	}
	if !found {
		return errors.New("api security configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply api security configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
