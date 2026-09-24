package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func (s *Store) StartStickySecretChangeListener(ctx context.Context, apply func(context.Context, config.StickySecretDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("sticky-session secret change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.StickySecretConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentStickySecret(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentStickySecret(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.StickySecretDocument) error) error {
	document, found, err := loadStickySecretFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current sticky-session secret configuration: %w", err)
	}
	if !found {
		return errors.New("sticky-session secret configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply sticky-session secret configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
