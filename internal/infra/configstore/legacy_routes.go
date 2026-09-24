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

func (s *Store) LoadLegacyRoutes(ctx context.Context) (config.LegacyRoutesDocument, bool, error) {
	document, found, err := s.Load(ctx, config.LegacyRoutesConfigurationScope)
	return decodeLegacyRoutesDocument(document, found, err, nil)
}

func loadLegacyRoutesFromConn(ctx context.Context, conn *pgx.Conn, groups []config.UpstreamGroup) (config.LegacyRoutesDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.LegacyRoutesConfigurationScope)
	return decodeLegacyRoutesDocument(document, found, err, groups)
}

func decodeLegacyRoutesDocument(document Document, found bool, err error, groups []config.UpstreamGroup) (config.LegacyRoutesDocument, bool, error) {
	if err != nil || !found {
		return config.LegacyRoutesDocument{}, found, err
	}
	if document.SchemaVersion != config.LegacyRoutesConfigurationSchemaVersion {
		return config.LegacyRoutesDocument{}, false, fmt.Errorf("unsupported legacy host-route configuration schema version %d", document.SchemaVersion)
	}
	var routes map[string]string
	if err := json.Unmarshal(document.Payload, &routes); err != nil {
		return config.LegacyRoutesDocument{}, false, fmt.Errorf("decode legacy host-route configuration document: %w", err)
	}
	if groups == nil {
		current := config.GetGlobalConfig()
		if current != nil {
			groups = current.Upstream.Groups
		}
	}
	canonical, err := config.CanonicalLegacyRoutesForGroups(routes, groups)
	if err != nil {
		return config.LegacyRoutesDocument{}, false, fmt.Errorf("validate legacy host-route configuration document: %w", err)
	}
	if !reflect.DeepEqual(canonical, routes) {
		return config.LegacyRoutesDocument{}, false, errors.New("legacy host-route configuration document is not canonical")
	}
	return config.LegacyRoutesDocument{Routes: config.CloneLegacyRoutes(routes), Revision: document.Revision}, true, nil
}

func (s *Store) SaveLegacyRoutes(ctx context.Context, expectedRevision int64, routes map[string]string, actor, reason string) (config.LegacyRoutesDocument, error) {
	canonical, err := config.CanonicalLegacyRoutes(routes)
	if err != nil {
		return config.LegacyRoutesDocument{}, fmt.Errorf("validate legacy host-route configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.LegacyRoutesDocument{}, fmt.Errorf("encode legacy host-route configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{Scope: config.LegacyRoutesConfigurationScope, ExpectedRevision: expectedRevision, SchemaVersion: config.LegacyRoutesConfigurationSchemaVersion, Payload: payload, Actor: actor, Reason: reason})
	if err != nil {
		if errors.Is(err, ErrRevisionConflict) {
			actual := int64(0)
			var conflict *RevisionConflictError
			if errors.As(err, &conflict) {
				actual = conflict.Actual
			}
			return config.LegacyRoutesDocument{}, &config.LegacyRoutesRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.LegacyRoutesDocument{}, err
	}
	return config.LegacyRoutesDocument{Routes: config.CloneLegacyRoutes(canonical), Revision: document.Revision}, nil
}
