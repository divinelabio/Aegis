package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartReputationChangeListener synchronizes Reputation configuration from PostgreSQL
// after LISTEN setup and every reconnect.
func (s *Store) StartReputationChangeListener(ctx context.Context, apply func(context.Context, config.ReputationDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("reputation change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.ReputationConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentReputation(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentReputation(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.ReputationDocument) error) error {
	document, found, err := loadReputationFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current reputation configuration: %w", err)
	}
	if !found {
		return errors.New("reputation configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply reputation configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
