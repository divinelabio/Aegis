package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func (s *Store) StartRouteRulesChangeListener(ctx context.Context, apply func(context.Context, config.RouteRulesDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("route-rule change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.RouteRulesConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentRouteRules(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentRouteRules(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.RouteRulesDocument) error) error {
	groupsDocument, groupsFound, err := loadUpstreamGroupsFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current upstream Origin-pool configuration: %w", err)
	}
	if !groupsFound {
		return errors.New("upstream Origin-pool configuration document is missing")
	}
	document, found, err := loadRouteRulesFromConn(ctx, listener.Conn(), groupsDocument.Groups)
	if err != nil {
		return fmt.Errorf("load current route-rule configuration: %w", err)
	}
	if !found {
		return errors.New("route-rule configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply route-rule configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
