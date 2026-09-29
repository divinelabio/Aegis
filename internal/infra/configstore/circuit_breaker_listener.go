package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func (s *Store) StartCircuitBreakerChangeListener(ctx context.Context, apply func(context.Context, config.CircuitBreakerDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("circuit-breaker change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.CircuitBreakerConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentCircuitBreaker(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentCircuitBreaker(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.CircuitBreakerDocument) error) error {
	document, found, err := loadCircuitBreakerFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current circuit-breaker configuration: %w", err)
	}
	if !found {
		return errors.New("circuit-breaker configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply circuit-breaker configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
