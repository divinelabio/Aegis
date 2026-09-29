package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5"
)

// LoadInfrastructure adapts the generic versioned-document store to the
// complete ingress trust contract. The config package remains responsible for
// validating values before any request-path activation.
func (s *Store) LoadInfrastructure(ctx context.Context) (config.InfrastructureDocument, bool, error) {
	document, found, err := s.Load(ctx, config.InfrastructureConfigurationScope)
	return decodeInfrastructureDocument(document, found, err)
}

func loadInfrastructureFromConn(ctx context.Context, conn *pgx.Conn) (config.InfrastructureDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.InfrastructureConfigurationScope)
	return decodeInfrastructureDocument(document, found, err)
}

func decodeInfrastructureDocument(document Document, found bool, err error) (config.InfrastructureDocument, bool, error) {
	if err != nil || !found {
		return config.InfrastructureDocument{}, found, err
	}
	if document.SchemaVersion != config.InfrastructureConfigurationSchemaVersion {
		return config.InfrastructureDocument{}, false, fmt.Errorf("unsupported infrastructure configuration schema version %d", document.SchemaVersion)
	}
	var infrastructure config.InfrastructureConfig
	if err := json.Unmarshal(document.Payload, &infrastructure); err != nil {
		return config.InfrastructureDocument{}, false, fmt.Errorf("decode infrastructure configuration document: %w", err)
	}
	canonical, err := config.CanonicalInfrastructureConfig(infrastructure, 0)
	if err != nil {
		return config.InfrastructureDocument{}, false, fmt.Errorf("validate infrastructure configuration document: %w", err)
	}
	if !reflect.DeepEqual(canonical, infrastructure) {
		return config.InfrastructureDocument{}, false, errors.New("infrastructure configuration document is not canonical")
	}
	return config.InfrastructureDocument{Config: infrastructure, Revision: document.Revision}, true, nil
}

// SaveInfrastructure persists one canonical ingress trust document with
// compare-and-swap revision control.
func (s *Store) SaveInfrastructure(ctx context.Context, expectedRevision int64, infrastructure config.InfrastructureConfig, actor, reason string) (config.InfrastructureDocument, error) {
	canonical, err := config.CanonicalInfrastructureConfig(infrastructure, 0)
	if err != nil {
		return config.InfrastructureDocument{}, fmt.Errorf("validate infrastructure configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.InfrastructureDocument{}, fmt.Errorf("encode infrastructure configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.InfrastructureConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.InfrastructureConfigurationSchemaVersion,
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
			return config.InfrastructureDocument{}, &config.InfrastructureRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.InfrastructureDocument{}, err
	}
	return config.InfrastructureDocument{Config: canonical, Revision: document.Revision}, nil
}
