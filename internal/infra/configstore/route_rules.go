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

func (s *Store) LoadRouteRules(ctx context.Context) (config.RouteRulesDocument, bool, error) {
	document, found, err := s.Load(ctx, config.RouteRulesConfigurationScope)
	return decodeRouteRulesDocument(document, found, err, nil)
}

func loadRouteRulesFromConn(ctx context.Context, conn *pgx.Conn, groups []config.UpstreamGroup) (config.RouteRulesDocument, bool, error) {
	document, found, err := loadConfigurationDocument(ctx, conn, config.RouteRulesConfigurationScope)
	return decodeRouteRulesDocument(document, found, err, groups)
}

func decodeRouteRulesDocument(document Document, found bool, err error, groups []config.UpstreamGroup) (config.RouteRulesDocument, bool, error) {
	if err != nil || !found {
		return config.RouteRulesDocument{}, found, err
	}
	if document.SchemaVersion != config.RouteRulesConfigurationSchemaVersion {
		return config.RouteRulesDocument{}, false, fmt.Errorf("unsupported route-rule configuration schema version %d", document.SchemaVersion)
	}
	var rules []config.RouteConfig
	if err := json.Unmarshal(document.Payload, &rules); err != nil {
		return config.RouteRulesDocument{}, false, fmt.Errorf("decode route-rule configuration document: %w", err)
	}
	if groups == nil {
		current := config.GetGlobalConfig()
		if current != nil {
			groups = current.Upstream.Groups
		}
	}
	canonical, err := config.NormalizeAndValidateRouteRules(rules, groups)
	if err != nil {
		return config.RouteRulesDocument{}, false, fmt.Errorf("validate route-rule configuration document: %w", err)
	}
	if !reflect.DeepEqual(canonical, rules) {
		return config.RouteRulesDocument{}, false, errors.New("route-rule configuration document is not canonical")
	}
	return config.RouteRulesDocument{Rules: config.CloneRouteConfigs(rules), Revision: document.Revision}, true, nil
}

func (s *Store) SaveRouteRules(ctx context.Context, expectedRevision int64, rules []config.RouteConfig, actor, reason string) (config.RouteRulesDocument, error) {
	current := config.GetGlobalConfig()
	var groups []config.UpstreamGroup
	if current != nil {
		groups = current.Upstream.Groups
	}
	canonical, err := config.NormalizeAndValidateRouteRules(rules, groups)
	if err != nil {
		return config.RouteRulesDocument{}, fmt.Errorf("validate route-rule configuration document: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return config.RouteRulesDocument{}, fmt.Errorf("encode route-rule configuration document: %w", err)
	}
	document, err := s.Save(ctx, SaveInput{Scope: config.RouteRulesConfigurationScope, ExpectedRevision: expectedRevision, SchemaVersion: config.RouteRulesConfigurationSchemaVersion, Payload: payload, Actor: actor, Reason: reason})
	if err != nil {
		if errors.Is(err, ErrRevisionConflict) {
			actual := int64(0)
			var conflict *RevisionConflictError
			if errors.As(err, &conflict) {
				actual = conflict.Actual
			}
			return config.RouteRulesDocument{}, &config.RouteRulesRevisionConflictError{Expected: expectedRevision, Actual: actual}
		}
		return config.RouteRulesDocument{}, err
	}
	return config.RouteRulesDocument{Rules: canonical, Revision: document.Revision}, nil
}
