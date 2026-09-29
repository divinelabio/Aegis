package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StartCaptchaChangeListener reconciles the active CAPTCHA configuration from
// PostgreSQL after LISTEN and every reconnect.
func (s *Store) StartCaptchaChangeListener(ctx context.Context, apply func(context.Context, config.CaptchaDocument) error, reportError func(error)) error {
	if apply == nil {
		return errors.New("CAPTCHA change apply function is required")
	}
	return s.startConfigurationChangeListener(ctx, config.CaptchaConfigurationScope, func(ctx context.Context, listener *pgxpool.Conn) error {
		return deliverCurrentCaptcha(ctx, listener, apply)
	}, true, reportError)
}

func deliverCurrentCaptcha(ctx context.Context, listener *pgxpool.Conn, apply func(context.Context, config.CaptchaDocument) error) error {
	document, found, err := loadCaptchaFromConn(ctx, listener.Conn())
	if err != nil {
		return fmt.Errorf("load current CAPTCHA configuration: %w", err)
	}
	if !found {
		return fmt.Errorf("CAPTCHA configuration document: %w", errConfigurationDocumentMissing)
	}
	if err := apply(ctx, document); err != nil {
		return fmt.Errorf("apply CAPTCHA configuration revision %d: %w", document.Revision, err)
	}
	return nil
}
