package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5"
)

func (s *Store) LoadStickySecret(ctx context.Context) (config.StickySecretDocument, bool, error) {
	document, found, err := s.Load(ctx, config.StickySecretConfigurationScope)
	return decodeStickySecretDocument(document, found, err)
}

func loadStickySecretFromConn(ctx context.Context, conn *pgx.Conn) (config.StickySecretDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.StickySecretConfigurationScope)
	return decodeStickySecretDocument(document, found, err)
}

func decodeStickySecretDocument(document Document, found bool, err error) (config.StickySecretDocument, bool, error) {
	if err != nil || !found {
		return config.StickySecretDocument{}, found, err
	}
	if document.SchemaVersion != config.StickySecretConfigurationSchemaVersion {
		return config.StickySecretDocument{}, false, fmt.Errorf("unsupported sticky-session secret configuration schema version %d", document.SchemaVersion)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(document.Payload, &payload); err != nil {
		return config.StickySecretDocument{}, false, fmt.Errorf("decode sticky-session secret configuration document: %w", err)
	}
	if len(payload) != 1 {
		return config.StickySecretDocument{}, false, errors.New("sticky-session secret configuration document must contain only secret_ref")
	}
	rawReference, ok := payload["secret_ref"]
	if !ok {
		return config.StickySecretDocument{}, false, errors.New("sticky-session secret configuration document must contain secret_ref")
	}
	var reference string
	if err := json.Unmarshal(rawReference, &reference); err != nil {
		return config.StickySecretDocument{}, false, fmt.Errorf("decode sticky-session secret reference: %w", err)
	}
	canonical, err := config.CanonicalStickySecretReference(reference)
	if err != nil {
		return config.StickySecretDocument{}, false, fmt.Errorf("validate sticky-session secret configuration document: %w", err)
	}
	if canonical != reference {
		return config.StickySecretDocument{}, false, errors.New("sticky-session secret configuration document is not canonical")
	}
	return config.StickySecretDocument{SecretRef: reference, Revision: document.Revision}, true, nil
}

func (s *Store) SaveStickySecret(ctx context.Context, expectedRevision int64, reference, actor, reason string) (config.StickySecretDocument, error) {
	canonical, err := config.CanonicalStickySecretReference(reference)
	if err != nil {
		return config.StickySecretDocument{}, fmt.Errorf("validate sticky-session secret configuration document: %w", err)
	}
	payload, err := json.Marshal(struct {
		SecretRef string `json:"secret_ref"`
	}{SecretRef: canonical})
	if err != nil {
		return config.StickySecretDocument{}, fmt.Errorf("encode sticky-session secret configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{Scope: config.StickySecretConfigurationScope, ExpectedRevision: expectedRevision, SchemaVersion: config.StickySecretConfigurationSchemaVersion, Payload: payload, Actor: actor, Reason: reason})
	if err != nil {
		if errors.Is(err, ErrRevisionConflict) {
			actual := int64(0)
			var conflict *RevisionConflictError
			if errors.As(err, &conflict) {
				actual = conflict.Actual
			}
			return config.StickySecretDocument{}, &config.StickySecretRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.StickySecretDocument{}, err
	}
	return config.StickySecretDocument{SecretRef: canonical, Revision: document.Revision}, nil
}
