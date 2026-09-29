package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5"
)

func (s *Store) LoadCircuitBreaker(ctx context.Context) (config.CircuitBreakerDocument, bool, error) {
	document, found, err := s.Load(ctx, config.CircuitBreakerConfigurationScope)
	return decodeCircuitBreakerDocument(document, found, err)
}

func loadCircuitBreakerFromConn(ctx context.Context, conn *pgx.Conn) (config.CircuitBreakerDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.CircuitBreakerConfigurationScope)
	return decodeCircuitBreakerDocument(document, found, err)
}

func decodeCircuitBreakerDocument(document Document, found bool, err error) (config.CircuitBreakerDocument, bool, error) {
	if err != nil || !found {
		return config.CircuitBreakerDocument{}, found, err
	}
	if document.SchemaVersion != config.CircuitBreakerConfigurationSchemaVersion {
		return config.CircuitBreakerDocument{}, false, fmt.Errorf("unsupported circuit-breaker configuration schema version %d", document.SchemaVersion)
	}
	var policy config.CircuitBreakerConfig
	if err := json.Unmarshal(document.Payload, &policy); err != nil {
		return config.CircuitBreakerDocument{}, false, fmt.Errorf("decode circuit-breaker configuration document: %w", err)
	}
	canonical, err := config.CanonicalCircuitBreakerConfig(policy)
	if err != nil {
		return config.CircuitBreakerDocument{}, false, fmt.Errorf("validate circuit-breaker configuration document: %w", err)
	}
	if canonical != policy {
		return config.CircuitBreakerDocument{}, false, errors.New("circuit-breaker configuration document is not canonical")
	}
	return config.CircuitBreakerDocument{Config: policy, Revision: document.Revision}, true, nil
}

func (s *Store) SaveCircuitBreaker(ctx context.Context, expectedRevision int64, policy config.CircuitBreakerConfig, actor, reason string) (config.CircuitBreakerDocument, error) {
	canonical, err := config.CanonicalCircuitBreakerConfig(policy)
	if err != nil {
		return config.CircuitBreakerDocument{}, fmt.Errorf("validate circuit-breaker configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.CircuitBreakerDocument{}, fmt.Errorf("encode circuit-breaker configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{Scope: config.CircuitBreakerConfigurationScope, ExpectedRevision: expectedRevision, SchemaVersion: config.CircuitBreakerConfigurationSchemaVersion, Payload: payload, Actor: actor, Reason: reason})
	if err != nil {
		if errors.Is(err, ErrRevisionConflict) {
			actual := int64(0)
			var conflict *RevisionConflictError
			if errors.As(err, &conflict) {
				actual = conflict.Actual
			}
			return config.CircuitBreakerDocument{}, &config.CircuitBreakerRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.CircuitBreakerDocument{}, err
	}
	return config.CircuitBreakerDocument{Config: canonical, Revision: document.Revision}, nil
}
