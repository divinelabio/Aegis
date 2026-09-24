package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartAccessControlChangeListener synchronizes Access Control configuration from PostgreSQL
// after LISTEN setup and every reconnect.
func (s *Store) StartAccessControlChangeListener(ctx context.Context, apply func(context.Context, config.AccessControlDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("access control change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.AccessControlConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentAccessControl(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentAccessControl(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.AccessControlDocument) error) error {
	document, found, err := loadAccessControlFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current access control configuration: %w", err)
	}
	if !found {
		return errors.New("access control configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply access control configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
