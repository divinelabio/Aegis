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

// LoadTrafficControl loads the Traffic Control document from PostgreSQL.
func (s *Store) LoadTrafficControl(ctx context.Context) (config.TrafficControlDocument, bool, error) {
	document, found, err := s.Load(ctx, config.TrafficControlConfigurationScope)
	return decodeTrafficControlDocument(document, found, err)
}

func loadTrafficControlFromConn(ctx context.Context, conn *pgx.Conn) (config.TrafficControlDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.TrafficControlConfigurationScope)
	return decodeTrafficControlDocument(document, found, err)
}

func decodeTrafficControlDocument(document Document, found bool, err error) (config.TrafficControlDocument, bool, error) {
	if err != nil || !found {
		return config.TrafficControlDocument{}, found, err
	}
	if document.SchemaVersion != config.TrafficControlConfigurationSchemaVersion {
		return config.TrafficControlDocument{}, false, fmt.Errorf("unsupported traffic control configuration schema version %d", document.SchemaVersion)
	}
	var sectionConfig sections.SectionConfig
	if err := json.Unmarshal(document.Payload, &sectionConfig); err != nil {
		return config.TrafficControlDocument{}, false, fmt.Errorf("decode traffic control configuration document: %w", err)
	}
	canonical, err := config.CanonicalTrafficControlSectionConfig(sectionConfig)
	if err != nil {
		return config.TrafficControlDocument{}, false, fmt.Errorf("validate traffic control configuration document: %w", err)
	}
	return config.TrafficControlDocument{Config: canonical, Revision: document.Revision}, true, nil
}

// SaveTrafficControl commits a Traffic Control document to PostgreSQL.
func (s *Store) SaveTrafficControl(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (config.TrafficControlDocument, error) {
	canonical, err := config.CanonicalTrafficControlSectionConfig(next)
	if err != nil {
		return config.TrafficControlDocument{}, fmt.Errorf("validate traffic control configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.TrafficControlDocument{}, fmt.Errorf("encode traffic control configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.TrafficControlConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.TrafficControlConfigurationSchemaVersion,
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
			return config.TrafficControlDocument{}, &config.TrafficControlRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.TrafficControlDocument{}, err
	}
	return config.TrafficControlDocument{Config: canonical, Revision: document.Revision}, nil
}
