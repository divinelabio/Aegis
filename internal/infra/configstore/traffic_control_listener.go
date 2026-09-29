package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartTrafficControlChangeListener synchronizes Traffic Control configuration
// from PostgreSQL after LISTEN setup and every reconnect.
func (s *Store) StartTrafficControlChangeListener(ctx context.Context, apply func(context.Context, config.TrafficControlDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("traffic control change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.TrafficControlConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentTrafficControl(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentTrafficControl(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.TrafficControlDocument) error) error {
	document, found, err := loadTrafficControlFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current traffic control configuration: %w", err)
	}
	if !found {
		return errors.New("traffic control configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply traffic control configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
