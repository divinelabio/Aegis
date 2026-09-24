package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func (s *Store) StartLegacyRoutesChangeListener(ctx context.Context, apply func(context.Context, config.LegacyRoutesDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("legacy host-route change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.LegacyRoutesConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentLegacyRoutes(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentLegacyRoutes(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.LegacyRoutesDocument) error) error {
	groupsDocument, groupsFound, err := loadUpstreamGroupsFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current upstream Origin-pool configuration: %w", err)
	}
	if !groupsFound {
		return errors.New("upstream Origin-pool configuration document is missing")
	}
	document, found, err := loadLegacyRoutesFromConn(ctx, listener.Conn(), groupsDocument.Groups)
	if err != nil {
		return fmt.Errorf("load current legacy host-route configuration: %w", err)
	}
	if !found {
		return errors.New("legacy host-route configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply legacy host-route configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
