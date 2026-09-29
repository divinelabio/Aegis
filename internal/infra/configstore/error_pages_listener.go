package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

const configurationChangeReconnectDelay = time.Second

var errConfigurationDocumentMissing = errors.New("configuration document is missing")

type configurationChangeNotification struct {
	Scope    string `json:"scope"`
	Revision int64  `json:"revision"`
}

// StartErrorPagesChangeListener keeps this process's Error Pages runtime
// synchronized with committed PostgreSQL configuration. The listener
// reconciles the durable document after every successful LISTEN, so dropped
// notifications and listener reconnects cannot leave a process stale.
func (s *Store) StartErrorPagesChangeListener(ctx context.Context, apply func(context.Context, config.ErrorPagesDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("Error Pages change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.ErrorPagesConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentErrorPages(ctx, listener, apply)
	}, false, reportError)
}

func (s *Store) openConfigurationChangeListener(ctx context.Context) (*pgxpool.Conn, error) {
	listener, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire configuration change listener: %w", err)
	}
	if _, err := listener.Exec(ctx, "LISTEN "+configurationChangeChannel); err != nil {
		listener.Release()
		return nil, fmt.Errorf("listen for configuration changes: %w", err)
	}
	return listener, nil
}

func deliverCurrentErrorPages(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.ErrorPagesDocument) error) error {
	document, found, err := loadErrorPagesFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current Error Pages configuration: %w", err)
	}
	if !found {
		return errors.New("Error Pages configuration document is missing")
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply Error Pages configuration revision %d: %w", document.Revision, err)
	}
	return nil
}

type configurationChangeReconciler func(context.Context, *pgxpool.Conn) error

func (s *Store) startConfigurationChangeListener(ctx context.Context, scope string, reconcile configurationChangeReconciler, allowMissingDocument bool, reportError func(error)) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL configuration store is unavailable")
	}
	if reconcile == nil {
		return errors.New("configuration change reconciler is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := normalizeScope(scope); err != nil {
		return fmt.Errorf("invalid configuration change scope: %w", err)
	}

	listener, err := s.openConfigurationChangeListener(ctx)
	if err != nil {
		return err
	}
	if err := reconcile(ctx, listener); err != nil && !(allowMissingDocument && errors.Is(err, errConfigurationDocumentMissing)) {
		listener.Release()
		return err
	}
	go s.listenForConfigurationChanges(ctx, listener, scope, reconcile, allowMissingDocument, reportError)
	return nil
}

func (s *Store) listenForConfigurationChanges(ctx context.Context, listener *pgxpool.Conn, scope string, reconcile configurationChangeReconciler, allowMissingDocument bool, reportError func(error)) {
	for {
		notification, err := listener.Conn().WaitForNotification(ctx)
		if err == nil {
			change, err := parseConfigurationChangeNotification(notification.Payload)
			if err != nil {
				reportConfigurationChangeError(reportError, fmt.Errorf("ignore invalid configuration change notification: %w", err))
				continue
			}
			if change.Scope != scope {
				continue
			}
			if err := reconcile(ctx, listener); err != nil && !(allowMissingDocument && errors.Is(err, errConfigurationDocumentMissing)) {
				reportConfigurationChangeError(reportError, err)
			}
			continue
		}

		listener.Release()
		if ctx.Err() != nil {
			return
		}
		reportConfigurationChangeError(reportError, fmt.Errorf("configuration change listener interrupted: %w", err))

		for {
			if !waitForConfigurationChangeReconnect(ctx) {
				return
			}
			listener, err = s.openConfigurationChangeListener(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				reportConfigurationChangeError(reportError, err)
				continue
			}
			if err := reconcile(ctx, listener); err != nil && !(allowMissingDocument && errors.Is(err, errConfigurationDocumentMissing)) {
				reportConfigurationChangeError(reportError, err)
			}
			break
		}
	}
}

func parseConfigurationChangeNotification(payload string) (configurationChangeNotification, error) {
	var notification configurationChangeNotification
	if err := json.Unmarshal([]byte(payload), &notification); err != nil {
		return configurationChangeNotification{}, fmt.Errorf("decode payload: %w", err)
	}
	scope, err := normalizeScope(notification.Scope)
	if err != nil {
		return configurationChangeNotification{}, fmt.Errorf("validate scope: %w", err)
	}
	if notification.Revision < 1 {
		return configurationChangeNotification{}, errors.New("revision is invalid")
	}
	notification.Scope = scope
	return notification, nil
}

func waitForConfigurationChangeReconnect(ctx context.Context) bool {
	timer := time.NewTimer(configurationChangeReconnectDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func reportConfigurationChangeError(reportError func(error), err error) {
	if reportError != nil && err != nil {
		reportError(err)
	}
}
