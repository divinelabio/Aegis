package configstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5"
)

// LoadCaptcha loads a typed, secret-free CAPTCHA document.
func (s *Store) LoadCaptcha(ctx context.Context) (config.CaptchaDocument, bool, error) {
	document, found, err := s.Load(ctx, config.CaptchaConfigurationScope)
	return decodeCaptchaDocument(document, found, err)
}

func loadCaptchaFromConn(ctx context.Context, conn *pgx.Conn) (config.CaptchaDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.CaptchaConfigurationScope)
	return decodeCaptchaDocument(document, found, err)
}

func decodeCaptchaDocument(document Document, found bool, err error) (config.CaptchaDocument, bool, error) {
	if err != nil || !found {
		return config.CaptchaDocument{}, found, err
	}
	if document.SchemaVersion != config.CaptchaConfigurationSchemaVersion {
		return config.CaptchaDocument{}, false, fmt.Errorf("unsupported CAPTCHA configuration schema version %d", document.SchemaVersion)
	}
	var captchaConfig config.CaptchaConfig
	decoder := json.NewDecoder(bytes.NewReader(document.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&captchaConfig); err != nil {
		return config.CaptchaDocument{}, false, fmt.Errorf("decode CAPTCHA configuration document: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return config.CaptchaDocument{}, false, errors.New("CAPTCHA configuration document must contain one JSON object")
	}
	canonical, err := config.CanonicalCaptchaConfig(captchaConfig)
	if err != nil {
		return config.CaptchaDocument{}, false, fmt.Errorf("validate CAPTCHA configuration document: %w", err)
	}
	if canonical != captchaConfig {
		return config.CaptchaDocument{}, false, errors.New("CAPTCHA configuration document is not canonical or contains a secret")
	}
	return config.CaptchaDocument{Config: captchaConfig, Revision: document.Revision}, true, nil
}

// SaveCaptcha persists an optimistic, secret-free configuration revision.
func (s *Store) SaveCaptcha(ctx context.Context, expectedRevision int64, captchaConfig config.CaptchaConfig, actor, reason string) (config.CaptchaDocument, error) {
	canonical, err := config.CanonicalCaptchaConfig(captchaConfig)
	if err != nil {
		return config.CaptchaDocument{}, fmt.Errorf("validate CAPTCHA configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.CaptchaDocument{}, fmt.Errorf("encode CAPTCHA configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.CaptchaConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.CaptchaConfigurationSchemaVersion,
		Payload:          payload,
		Actor:            actor,
		Reason:           reason,
	})
	if err != nil {
		if errors.Is(err, ErrRevisionConflict) {
			actual := int64(0)
			var conflict *RevisionConflictError
			if errors.As(err, &conflict) {
				actual = conflict.Actual
			}
			return config.CaptchaDocument{}, &config.CaptchaRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.CaptchaDocument{}, err
	}
	return config.CaptchaDocument{Config: canonical, Revision: document.Revision}, nil
}
