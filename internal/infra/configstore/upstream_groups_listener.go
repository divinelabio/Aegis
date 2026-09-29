package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func (s *Store) StartUpstreamGroupsChangeListener(ctx context.Context, apply func(context.Context, config.UpstreamGroupsDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("upstream Origin-pool change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.UpstreamGroupsConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentUpstreamGroups(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentUpstreamGroups(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.UpstreamGroupsDocument) error) error {
	document, found, err := loadUpstreamGroupsFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current upstream Origin-pool configuration: %w", err)
	}
	if !found {
		return errors.New("upstream Origin-pool configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply upstream Origin-pool configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
