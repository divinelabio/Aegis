package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5"
)

// LoadErrorPages adapts the generic versioned-document store to the Error
// Pages domain. Validation remains in config so a corrupt database document
// can never be activated merely because it is valid JSON.
func (s *Store) LoadErrorPages(ctx context.Context) (config.ErrorPagesDocument, bool, error) {
	document, found, err := s.Load(ctx, config.ErrorPagesConfigurationScope)
	return decodeErrorPagesDocument(document, found, err)
}

func loadErrorPagesFromConn(ctx context.Context, conn *pgx.Conn) (config.ErrorPagesDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.ErrorPagesConfigurationScope)
	return decodeErrorPagesDocument(document, found, err)
}

func decodeErrorPagesDocument(document Document, found bool, err error) (config.ErrorPagesDocument, bool, error) {
	if err != nil || !found {
		return config.ErrorPagesDocument{}, found, err
	}
	if document.SchemaVersion != config.ErrorPagesConfigurationSchemaVersion {
		return config.ErrorPagesDocument{}, false, fmt.Errorf("unsupported Error Pages configuration schema version %d", document.SchemaVersion)
	}
	var pages config.ErrorPagesConfig
	if err := json.Unmarshal(document.Payload, &pages); err != nil {
		return config.ErrorPagesDocument{}, false, fmt.Errorf("decode Error Pages configuration document: %w", err)
	}
	if err := pages.Validate(); err != nil {
		return config.ErrorPagesDocument{}, false, fmt.Errorf("validate Error Pages configuration document: %w", err)
	}
	return config.ErrorPagesDocument{Config: pages, Revision: document.Revision}, true, nil
}

// SaveErrorPages persists one fully validated document with a compare-and-swap
// revision. Translation keeps handlers and the config domain independent from
// the generic storage package's error vocabulary.
func (s *Store) SaveErrorPages(ctx context.Context, expectedRevision int64, pages config.ErrorPagesConfig, actor, reason string) (config.ErrorPagesDocument, error) {
	if err := pages.Validate(); err != nil {
		return config.ErrorPagesDocument{}, fmt.Errorf("validate Error Pages configuration document: %w", err)
	}
	payload, err := json.Marshal(pages)
	if err != nil {
		return config.ErrorPagesDocument{}, fmt.Errorf("encode Error Pages configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.ErrorPagesConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.ErrorPagesConfigurationSchemaVersion,
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
			return config.ErrorPagesDocument{}, &config.ErrorPagesRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.ErrorPagesDocument{}, err
	}
	return config.ErrorPagesDocument{Config: pages, Revision: document.Revision}, nil
}
