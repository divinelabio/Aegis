package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5"
)

func (s *Store) LoadUpstreamRuntime(ctx context.Context) (config.UpstreamRuntimeDocument, bool, error) {
	document, found, err := s.Load(ctx, config.UpstreamRuntimeConfigurationScope)
	return decodeUpstreamRuntimeDocument(document, found, err)
}

func loadUpstreamRuntimeFromConn(ctx context.Context, conn *pgx.Conn) (config.UpstreamRuntimeDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.UpstreamRuntimeConfigurationScope)
	return decodeUpstreamRuntimeDocument(document, found, err)
}

func decodeUpstreamRuntimeDocument(document Document, found bool, err error) (config.UpstreamRuntimeDocument, bool, error) {
	if err != nil || !found {
		return config.UpstreamRuntimeDocument{}, found, err
	}
	if document.SchemaVersion != config.UpstreamRuntimeConfigurationSchemaVersion {
		return config.UpstreamRuntimeDocument{}, false, fmt.Errorf("unsupported upstream runtime configuration schema version %d", document.SchemaVersion)
	}
	var settings config.UpstreamRuntimeSettings
	if err := json.Unmarshal(document.Payload, &settings); err != nil {
		return config.UpstreamRuntimeDocument{}, false, fmt.Errorf("decode upstream runtime configuration document: %w", err)
	}
	canonical, err := config.CanonicalUpstreamRuntimeSettings(settings)
	if err != nil {
		return config.UpstreamRuntimeDocument{}, false, fmt.Errorf("validate upstream runtime configuration document: %w", err)
	}
	if canonical != settings {
		return config.UpstreamRuntimeDocument{}, false, errors.New("upstream runtime configuration document is not canonical")
	}
	return config.UpstreamRuntimeDocument{Settings: settings, Revision: document.Revision}, true, nil
}

func (s *Store) SaveUpstreamRuntime(ctx context.Context, expectedRevision int64, settings config.UpstreamRuntimeSettings, actor, reason string) (config.UpstreamRuntimeDocument, error) {
	canonical, err := config.CanonicalUpstreamRuntimeSettings(settings)
	if err != nil {
		return config.UpstreamRuntimeDocument{}, fmt.Errorf("validate upstream runtime configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.UpstreamRuntimeDocument{}, fmt.Errorf("encode upstream runtime configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{Scope: config.UpstreamRuntimeConfigurationScope, ExpectedRevision: expectedRevision, SchemaVersion: config.UpstreamRuntimeConfigurationSchemaVersion, Payload: payload, Actor: actor, Reason: reason})
	if err != nil {
		if errors.Is(err, ErrRevisionConflict) {
			actual := int64(0)
			var conflict *RevisionConflictError
			if errors.As(err, &conflict) {
				actual = conflict.Actual
			}
			return config.UpstreamRuntimeDocument{}, &config.UpstreamRuntimeRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.UpstreamRuntimeDocument{}, err
	}
	return config.UpstreamRuntimeDocument{Settings: canonical, Revision: document.Revision}, nil
}
