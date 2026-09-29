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

// LoadBot loads the Bot Protection document from PostgreSQL.
func (s *Store) LoadBot(ctx context.Context) (config.BotDocument, bool, error) {
	document, found, err := s.Load(ctx, config.BotConfigurationScope)
	return decodeBotDocument(document, found, err)
}

func loadBotFromConn(ctx context.Context, conn *pgx.Conn) (config.BotDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.BotConfigurationScope)
	return decodeBotDocument(document, found, err)
}

func decodeBotDocument(document Document, found bool, err error) (config.BotDocument, bool, error) {
	if err != nil || !found {
		return config.BotDocument{}, found, err
	}
	if document.SchemaVersion != config.BotConfigurationSchemaVersion {
		return config.BotDocument{}, false, fmt.Errorf("unsupported bot configuration schema version %d", document.SchemaVersion)
	}
	var sectionConfig sections.SectionConfig
	if err := json.Unmarshal(document.Payload, &sectionConfig); err != nil {
		return config.BotDocument{}, false, fmt.Errorf("decode bot configuration document: %w", err)
	}
	canonical, err := config.CanonicalBotSectionConfig(sectionConfig)
	if err != nil {
		return config.BotDocument{}, false, fmt.Errorf("validate bot configuration document: %w", err)
	}
	return config.BotDocument{Config: canonical, Revision: document.Revision}, true, nil
}

// SaveBot commits a Bot Protection document to PostgreSQL with CAS revision locking.
func (s *Store) SaveBot(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (config.BotDocument, error) {
	canonical, err := config.CanonicalBotSectionConfig(next)
	if err != nil {
		return config.BotDocument{}, fmt.Errorf("validate bot configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.BotDocument{}, fmt.Errorf("encode bot configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.BotConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.BotConfigurationSchemaVersion,
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
			return config.BotDocument{}, &config.BotRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.BotDocument{}, err
	}
	return config.BotDocument{Config: canonical, Revision: document.Revision}, nil
}
