package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartInfrastructureChangeListener synchronizes trusted proxy behavior and
// proxy metadata from PostgreSQL after LISTEN setup and every reconnect.
func (s *Store) StartInfrastructureChangeListener(ctx context.Context, apply func(context.Context, config.InfrastructureDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("infrastructure change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.InfrastructureConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentInfrastructure(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentInfrastructure(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.InfrastructureDocument) error) error {
	document, found, err := loadInfrastructureFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current infrastructure configuration: %w", err)
	}
	if !found {
		return errors.New("infrastructure configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply infrastructure configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
