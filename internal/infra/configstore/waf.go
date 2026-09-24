package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/sections"
	"github.com/jackc/pgx/v5"
)

// LoadWAF loads the WAF Core document from PostgreSQL.
func (s *Store) LoadWAF(ctx context.Context) (config.WAFDocument, bool, error) {
	document, found, err := s.Load(ctx, config.WAFConfigurationScope)
	return decodeWAFDocument(document, found, err)
}

func loadWAFFromConn(ctx context.Context, conn *pgx.Conn) (config.WAFDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.WAFConfigurationScope)
	return decodeWAFDocument(document, found, err)
}

func decodeWAFDocument(document Document, found bool, err error) (config.WAFDocument, bool, error) {
	if err != nil || !found {
		return config.WAFDocument{}, found, err
	}
	if document.SchemaVersion != config.WAFConfigurationSchemaVersion {
		return config.WAFDocument{}, false, fmt.Errorf("unsupported waf configuration schema version %d", document.SchemaVersion)
	}
	var sectionConfig sections.SectionConfig
	if err := json.Unmarshal(document.Payload, &sectionConfig); err != nil {
		return config.WAFDocument{}, false, fmt.Errorf("decode waf configuration document: %w", err)
	}
	canonical, err := config.CanonicalWAFSectionConfig(sectionConfig)
	if err != nil {
		return config.WAFDocument{}, false, fmt.Errorf("validate waf configuration document: %w", err)
	}
	return config.WAFDocument{Config: canonical, Revision: document.Revision}, true, nil
}

// SaveWAF commits a WAF Core document to PostgreSQL with CAS revision locking.
func (s *Store) SaveWAF(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (config.WAFDocument, error) {
	canonical, err := config.CanonicalWAFSectionConfig(next)
	if err != nil {
		return config.WAFDocument{}, fmt.Errorf("validate waf configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.WAFDocument{}, fmt.Errorf("encode waf configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.WAFConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.WAFConfigurationSchemaVersion,
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
			return config.WAFDocument{}, &config.WAFRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.WAFDocument{}, err
	}
	return config.WAFDocument{Config: canonical, Revision: document.Revision}, nil
}
