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

// LoadAPISecurity loads the API Security document from PostgreSQL.
func (s *Store) LoadAPISecurity(ctx context.Context) (config.APISecurityDocument, bool, error) {
	document, found, err := s.Load(ctx, config.APISecurityConfigurationScope)
	return decodeAPISecurityDocument(document, found, err)
}

func loadAPISecurityFromConn(ctx context.Context, conn *pgx.Conn) (config.APISecurityDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.APISecurityConfigurationScope)
	return decodeAPISecurityDocument(document, found, err)
}

func decodeAPISecurityDocument(document Document, found bool, err error) (config.APISecurityDocument, bool, error) {
	if err != nil || !found {
		return config.APISecurityDocument{}, found, err
	}
	if document.SchemaVersion != config.APISecurityConfigurationSchemaVersion {
		return config.APISecurityDocument{}, false, fmt.Errorf("unsupported api security configuration schema version %d", document.SchemaVersion)
	}
	var sectionConfig sections.SectionConfig
	if err := json.Unmarshal(document.Payload, &sectionConfig); err != nil {
		return config.APISecurityDocument{}, false, fmt.Errorf("decode api security configuration document: %w", err)
	}
	canonical, err := config.CanonicalAPISecuritySectionConfig(sectionConfig)
	if err != nil {
		return config.APISecurityDocument{}, false, fmt.Errorf("validate api security configuration document: %w", err)
	}
	return config.APISecurityDocument{Config: canonical, Revision: document.Revision}, true, nil
}

// SaveAPISecurity commits an API Security document to PostgreSQL with CAS revision locking.
func (s *Store) SaveAPISecurity(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (config.APISecurityDocument, error) {
	canonical, err := config.CanonicalAPISecuritySectionConfig(next)
	if err != nil {
		return config.APISecurityDocument{}, fmt.Errorf("validate api security configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.APISecurityDocument{}, fmt.Errorf("encode api security configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.APISecurityConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.APISecurityConfigurationSchemaVersion,
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
			return config.APISecurityDocument{}, &config.APISecurityRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.APISecurityDocument{}, err
	}
	return config.APISecurityDocument{Config: canonical, Revision: document.Revision}, nil
}
