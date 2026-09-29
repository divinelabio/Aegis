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

// LoadAccessControl loads the Access Control document from PostgreSQL.
func (s *Store) LoadAccessControl(ctx context.Context) (config.AccessControlDocument, bool, error) {
	document, found, err := s.Load(ctx, config.AccessControlConfigurationScope)
	return decodeAccessControlDocument(document, found, err)
}

func loadAccessControlFromConn(ctx context.Context, conn *pgx.Conn) (config.AccessControlDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.AccessControlConfigurationScope)
	return decodeAccessControlDocument(document, found, err)
}

func decodeAccessControlDocument(document Document, found bool, err error) (config.AccessControlDocument, bool, error) {
	if err != nil || !found {
		return config.AccessControlDocument{}, found, err
	}
	if document.SchemaVersion != config.AccessControlConfigurationSchemaVersion {
		return config.AccessControlDocument{}, false, fmt.Errorf("unsupported access control configuration schema version %d", document.SchemaVersion)
	}
	var sectionConfig sections.SectionConfig
	if err := json.Unmarshal(document.Payload, &sectionConfig); err != nil {
		return config.AccessControlDocument{}, false, fmt.Errorf("decode access control configuration document: %w", err)
	}
	canonical, err := config.CanonicalAccessControlSectionConfig(sectionConfig)
	if err != nil {
		return config.AccessControlDocument{}, false, fmt.Errorf("validate access control configuration document: %w", err)
	}
	return config.AccessControlDocument{Config: canonical, Revision: document.Revision}, true, nil
}

// SaveAccessControl commits an Access Control document to PostgreSQL with CAS revision locking.
func (s *Store) SaveAccessControl(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (config.AccessControlDocument, error) {
	canonical, err := config.CanonicalAccessControlSectionConfig(next)
	if err != nil {
		return config.AccessControlDocument{}, fmt.Errorf("validate access control configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.AccessControlDocument{}, fmt.Errorf("encode access control configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.AccessControlConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.AccessControlConfigurationSchemaVersion,
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
			return config.AccessControlDocument{}, &config.AccessControlRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.AccessControlDocument{}, err
	}
	return config.AccessControlDocument{Config: canonical, Revision: document.Revision}, nil
}
