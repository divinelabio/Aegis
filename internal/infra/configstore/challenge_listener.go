package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartChallengeChangeListener synchronizes Smart Challenge configuration from PostgreSQL
// after LISTEN setup and every reconnect.
func (s *Store) StartChallengeChangeListener(ctx context.Context, apply func(context.Context, config.ChallengeDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("challenge change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.ChallengeConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentChallenge(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentChallenge(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.ChallengeDocument) error) error {
	document, found, err := loadChallengeFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current challenge configuration: %w", err)
	}
	if !found {
		return errors.New("challenge configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply challenge configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
