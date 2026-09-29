package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/jackc/pgx/v5"
)

// LoadSecurityTXT adapts the generic document store to the public disclosure
// document. Stored values must already use the canonical contact format.
func (s *Store) LoadSecurityTXT(ctx context.Context) (config.SecurityTXTDocument, bool, error) {
	document, found, err := s.Load(ctx, config.SecurityTXTConfigurationScope)
	return decodeSecurityTXTDocument(document, found, err)
}

func loadSecurityTXTFromConn(ctx context.Context, conn *pgx.Conn) (config.SecurityTXTDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.SecurityTXTConfigurationScope)
	return decodeSecurityTXTDocument(document, found, err)
}

func decodeSecurityTXTDocument(document Document, found bool, err error) (config.SecurityTXTDocument, bool, error) {
	if err != nil || !found {
		return config.SecurityTXTDocument{}, found, err
	}
	if document.SchemaVersion != config.SecurityTXTConfigurationSchemaVersion {
		return config.SecurityTXTDocument{}, false, fmt.Errorf("unsupported Security.txt configuration schema version %d", document.SchemaVersion)
	}
	var securityTXT config.SecurityTXTConfig
	if err := json.Unmarshal(document.Payload, &securityTXT); err != nil {
		return config.SecurityTXTDocument{}, false, fmt.Errorf("decode Security.txt configuration document: %w", err)
	}
	canonical, err := config.CanonicalSecurityTXTConfig(securityTXT)
	if err != nil {
		return config.SecurityTXTDocument{}, false, fmt.Errorf("validate Security.txt configuration document: %w", err)
	}
	if canonical != securityTXT {
		return config.SecurityTXTDocument{}, false, errors.New("Security.txt configuration document is not canonical")
	}
	return config.SecurityTXTDocument{Config: securityTXT, Revision: document.Revision}, true, nil
}

// SaveSecurityTXT persists one canonical document using a compare-and-swap
// revision and maps generic storage conflicts into the typed domain error.
func (s *Store) SaveSecurityTXT(ctx context.Context, expectedRevision int64, securityTXT config.SecurityTXTConfig, actor, reason string) (config.SecurityTXTDocument, error) {
	canonical, err := config.CanonicalSecurityTXTConfig(securityTXT)
	if err != nil {
		return config.SecurityTXTDocument{}, fmt.Errorf("validate Security.txt configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.SecurityTXTDocument{}, fmt.Errorf("encode Security.txt configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{
		Scope:            config.SecurityTXTConfigurationScope,
		ExpectedRevision: expectedRevision,
		SchemaVersion:    config.SecurityTXTConfigurationSchemaVersion,
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
			return config.SecurityTXTDocument{}, &config.SecurityTXTRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.SecurityTXTDocument{}, err
	}
	return config.SecurityTXTDocument{Config: canonical, Revision: document.Revision}, nil
}
