package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func (s *Store) StartUpstreamRuntimeChangeListener(ctx context.Context, apply func(context.Context, config.UpstreamRuntimeDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("upstream runtime change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.UpstreamRuntimeConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentUpstreamRuntime(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentUpstreamRuntime(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.UpstreamRuntimeDocument) error) error {
	document, found, err := loadUpstreamRuntimeFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current upstream runtime configuration: %w", err)
	}
	if !found {
		return errors.New("upstream runtime configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply upstream runtime configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
