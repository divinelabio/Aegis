package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5"
)

// LoadReputation loads the Reputation document from PostgreSQL.
func (s *Store) LoadReputation(ctx context.Context) (config.ReputationDocument, bool, error) {
	document, found, err := s.Load(ctx, config.ReputationConfigurationScope)
	return decodeReputationDocument(document, found, err)
}

func loadReputationFromConn(ctx context.Context, conn *pgx.Conn) (config.ReputationDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.ReputationConfigurationScope)
	return decodeReputationDocument(document, found, err)
}

func decodeReputationDocument(document Document, found bool, err error) (config.ReputationDocument, bool, error) {
	if err != nil || !found {
		return config.ReputationDocument{}, found, err
	}
	if document.SchemaVersion != config.ReputationConfigurationSchemaVersion {
		return config.ReputationDocument{}, false, fmt.Errorf("unsupported reputation configuration schema version %d", document.SchemaVersion)
	}
	var repConfig config.ReputationConfig
	if err := json.Unmarshal(document.Payload, &repConfig); err != nil {
		return config.ReputationDocument{}, false, fmt.Errorf("decode reputation configuration document: %w", err)
	}
	canonical, err := config.CanonicalReputationConfig(repConfig)
	if err != nil {
		return config.ReputationDocument{}, false, fmt.Errorf("validate reputation configuration document: %w", err)
	}
	return config.ReputationDocument{Config: canonical, Revision: document.Revision}, true, nil
}

// SaveReputation commits a Reputation document to PostgreSQL with CAS revision locking.
func (s *Store) SaveReputation(ctx context.Context, expectedRevision int64, next config.ReputationConfig, actor, reason string) (config.ReputationDocument, error) {
	canonical, err := config.CanonicalReputationConfig(next)
	if err != nil {
		return config.ReputationDocument{}, fmt.Errorf("validate reputation configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.ReputationDocument{}, fmt.Errorf("encode reputation configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.ReputationConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.ReputationConfigurationSchemaVersion,
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
			return config.ReputationDocument{}, &config.ReputationRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.ReputationDocument{}, err
	}
	return config.ReputationDocument{Config: canonical, Revision: document.Revision}, nil
}
