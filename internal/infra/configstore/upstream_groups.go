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

func (s *Store) LoadUpstreamGroups(ctx context.Context) (config.UpstreamGroupsDocument, bool, error) {
	document, found, err := s.Load(ctx, config.UpstreamGroupsConfigurationScope)
	return decodeUpstreamGroupsDocument(document, found, err)
}

func loadUpstreamGroupsFromConn(ctx context.Context, conn *pgx.Conn) (config.UpstreamGroupsDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.UpstreamGroupsConfigurationScope)
	return decodeUpstreamGroupsDocument(document, found, err)
}

func decodeUpstreamGroupsDocument(document Document, found bool, err error) (config.UpstreamGroupsDocument, bool, error) {
	if err != nil || !found {
		return config.UpstreamGroupsDocument{}, found, err
	}
	if document.SchemaVersion != config.UpstreamGroupsConfigurationSchemaVersion {
		return config.UpstreamGroupsDocument{}, false, fmt.Errorf("unsupported upstream Origin-pool configuration schema version %d", document.SchemaVersion)
	}
	var groups []config.UpstreamGroup
	if err := json.Unmarshal(document.Payload, &groups); err != nil {
		return config.UpstreamGroupsDocument{}, false, fmt.Errorf("decode upstream Origin-pool configuration document: %w", err)
	}
	canonical, err := config.CanonicalUpstreamGroups(groups)
	if err != nil {
		return config.UpstreamGroupsDocument{}, false, fmt.Errorf("validate upstream Origin-pool configuration document: %w", err)
	}
	if !reflect.DeepEqual(canonical, groups) {
		return config.UpstreamGroupsDocument{}, false, errors.New("upstream Origin-pool configuration document is not canonical")
	}
	return config.UpstreamGroupsDocument{Groups: config.CloneUpstreamGroups(groups), Revision: document.Revision}, true, nil
}

func (s *Store) SaveUpstreamGroups(ctx context.Context, expectedRevision int64, groups []config.UpstreamGroup, actor, reason string) (config.UpstreamGroupsDocument, error) {
	canonical, err := config.CanonicalUpstreamGroups(groups)
	if err != nil {
		return config.UpstreamGroupsDocument{}, fmt.Errorf("validate upstream Origin-pool configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.UpstreamGroupsDocument{}, fmt.Errorf("encode upstream Origin-pool configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{Scope: config.UpstreamGroupsConfigurationScope, ExpectedRevision: expectedRevision, SchemaVersion: config.UpstreamGroupsConfigurationSchemaVersion, Payload: payload, Actor: actor, Reason: reason})
	if err != nil {
		if errors.Is(err, ErrRevisionConflict) {
			actual := int64(0)
			var conflict *RevisionConflictError
			if errors.As(err, &conflict) {
				actual = conflict.Actual
			}
			return config.UpstreamGroupsDocument{}, &config.UpstreamGroupsRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.UpstreamGroupsDocument{}, err
	}
	return config.UpstreamGroupsDocument{Groups: canonical, Revision: document.Revision}, nil
}
