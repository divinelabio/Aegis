package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartSecurityTXTChangeListener keeps the public disclosure contact in sync
// across Aegis processes from the durable PostgreSQL document.
func (s *Store) StartSecurityTXTChangeListener(ctx context.Context, apply func(context.Context, config.SecurityTXTDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("Security.txt change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.SecurityTXTConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentSecurityTXT(ctx, listener, apply)
	}, false, reportError)
}

func deliverCurrentSecurityTXT(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.SecurityTXTDocument) error) error {
	document, found, err := loadSecurityTXTFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current Security.txt configuration: %w", err)
	}
	if !found {
		return errors.New("Security.txt configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply Security.txt configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
