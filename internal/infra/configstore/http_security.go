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

// LoadHTTPSecurity loads the HTTP Security document from PostgreSQL.
func (s *Store) LoadHTTPSecurity(ctx context.Context) (config.HTTPSecurityDocument, bool, error) {
	document, found, err := s.Load(ctx, config.HTTPSecurityConfigurationScope)
	return decodeHTTPSecurityDocument(document, found, err)
}

func loadHTTPSecurityFromConn(ctx context.Context, conn *pgx.Conn) (config.HTTPSecurityDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.HTTPSecurityConfigurationScope)
	return decodeHTTPSecurityDocument(document, found, err)
}

func decodeHTTPSecurityDocument(document Document, found bool, err error) (config.HTTPSecurityDocument, bool, error) {
	if err != nil || !found {
		return config.HTTPSecurityDocument{}, found, err
	}
	if document.SchemaVersion != config.HTTPSecurityConfigurationSchemaVersion {
		return config.HTTPSecurityDocument{}, false, fmt.Errorf("unsupported http security configuration schema version %d", document.SchemaVersion)
	}
	var sectionConfig sections.SectionConfig
	if err := json.Unmarshal(document.Payload, &sectionConfig); err != nil {
		return config.HTTPSecurityDocument{}, false, fmt.Errorf("decode http security configuration document: %w", err)
	}
	canonical, err := config.CanonicalHTTPSecuritySectionConfig(sectionConfig)
	if err != nil {
		return config.HTTPSecurityDocument{}, false, fmt.Errorf("validate http security configuration document: %w", err)
	}
	return config.HTTPSecurityDocument{Config: canonical, Revision: document.Revision}, true, nil
}

// SaveHTTPSecurity commits an HTTP Security document to PostgreSQL with CAS revision locking.
func (s *Store) SaveHTTPSecurity(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (config.HTTPSecurityDocument, error) {
	canonical, err := config.CanonicalHTTPSecuritySectionConfig(next)
	if err != nil {
		return config.HTTPSecurityDocument{}, fmt.Errorf("validate http security configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.HTTPSecurityDocument{}, fmt.Errorf("encode http security configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.HTTPSecurityConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.HTTPSecurityConfigurationSchemaVersion,
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
			return config.HTTPSecurityDocument{}, &config.HTTPSecurityRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.HTTPSecurityDocument{}, err
	}
	return config.HTTPSecurityDocument{Config: canonical, Revision: document.Revision}, nil
}
