package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartBotChangeListener synchronizes Bot Protection configuration from PostgreSQL
// after LISTEN setup and every reconnect.
func (s *Store) StartBotChangeListener(ctx context.Context, apply func(context.Context, config.BotDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("bot change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.BotConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentBot(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentBot(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.BotDocument) error) error {
	document, found, err := loadBotFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current bot configuration: %w", err)
	}
	if !found {
		return errors.New("bot configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply bot configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
