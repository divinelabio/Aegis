package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5"
)

// LoadChallenge loads the Smart Challenge document from PostgreSQL.
func (s *Store) LoadChallenge(ctx context.Context) (config.ChallengeDocument, bool, error) {
	document, found, err := s.Load(ctx, config.ChallengeConfigurationScope)
	return decodeChallengeDocument(document, found, err)
}

func loadChallengeFromConn(ctx context.Context, conn *pgx.Conn) (config.ChallengeDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.ChallengeConfigurationScope)
	return decodeChallengeDocument(document, found, err)
}

func decodeChallengeDocument(document Document, found bool, err error) (config.ChallengeDocument, bool, error) {
	if err != nil || !found {
		return config.ChallengeDocument{}, found, err
	}
	if document.SchemaVersion != config.ChallengeConfigurationSchemaVersion {
		return config.ChallengeDocument{}, false, fmt.Errorf("unsupported challenge configuration schema version %d", document.SchemaVersion)
	}
	var challengeConfig config.ChallengeConfig
	if err := json.Unmarshal(document.Payload, &challengeConfig); err != nil {
		return config.ChallengeDocument{}, false, fmt.Errorf("decode challenge configuration document: %w", err)
	}
	canonical, err := config.CanonicalChallengeConfig(challengeConfig)
	if err != nil {
		return config.ChallengeDocument{}, false, fmt.Errorf("validate challenge configuration document: %w", err)
	}
	return config.ChallengeDocument{Config: canonical, Revision: document.Revision}, true, nil
}

// SaveChallenge commits a Smart Challenge document to PostgreSQL with CAS revision locking.
func (s *Store) SaveChallenge(ctx context.Context, expectedRevision int64, next config.ChallengeConfig, actor, reason string) (config.ChallengeDocument, error) {
	canonical, err := config.CanonicalChallengeConfig(next)
	if err != nil {
		return config.ChallengeDocument{}, fmt.Errorf("validate challenge configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.ChallengeDocument{}, fmt.Errorf("encode challenge configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.ChallengeConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.ChallengeConfigurationSchemaVersion,
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
			return config.ChallengeDocument{}, &config.ChallengeRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.ChallengeDocument{}, err
	}
	return config.ChallengeDocument{Config: canonical, Revision: document.Revision}, nil
}
