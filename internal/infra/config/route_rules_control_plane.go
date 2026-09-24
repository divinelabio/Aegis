package config

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
)

const (
	RouteRulesConfigurationScope         = "upstream.routes"
	RouteRulesConfigurationSchemaVersion = 1
)

var ErrRouteRulesRevisionConflict = errors.New("route-rule configuration revision conflict")

// RouteRulesRevisionConflictError reports a stale complete-document update.
type RouteRulesRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *RouteRulesRevisionConflictError) Error() string {
	if e == nil {
		return ErrRouteRulesRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrRouteRulesRevisionConflict, e.Expected, e.Actual)
}

func (e *RouteRulesRevisionConflictError) Unwrap() error {
	return ErrRouteRulesRevisionConflict
}

// RouteRulesDocument owns advanced route rules only. Legacy host mappings,
// pool definitions, circuit-breaker policy, and sticky credentials retain
// independent migration boundaries.
type RouteRulesDocument struct {
	Rules    []RouteConfig
	Revision int64
}

type RouteRulesStore interface {
	LoadRouteRules(context.Context) (RouteRulesDocument, bool, error)
	SaveRouteRules(ctx context.Context, expectedRevision int64, rules []RouteConfig, actor, reason string) (RouteRulesDocument, error)
}

type RouteRulesActivator func([]RouteConfig) error
type RouteRulesControlPlaneMutator func(func([]RouteConfig) ([]RouteConfig, error)) ([]RouteConfig, error)

var (
	routeRulesControlPlaneManaged bool
	routeRulesControlPlaneMu      sync.Mutex
	routeRulesActivator           RouteRulesActivator
	routeRulesMutatorMu           sync.RWMutex
	routeRulesControlPlaneMutator RouteRulesControlPlaneMutator
)

func SetRouteRulesActivator(activator RouteRulesActivator) {
	routeRulesControlPlaneMu.Lock()
	routeRulesActivator = activator
	routeRulesControlPlaneMu.Unlock()
}

// SetRouteRulesControlPlaneMutator connects internal route clients (notably
// Edge Access) to PostgreSQL once the control plane has started.
func SetRouteRulesControlPlaneMutator(mutator RouteRulesControlPlaneMutator) {
	routeRulesMutatorMu.Lock()
	routeRulesControlPlaneMutator = mutator
	routeRulesMutatorMu.Unlock()
}

func CanonicalRouteRules(rules []RouteConfig) ([]RouteConfig, error) {
	return canonicalRouteRules(rules, currentUpstreamGroupsForRouteRules(nil))
}

func canonicalRouteRules(rules []RouteConfig, groups []UpstreamGroup) ([]RouteConfig, error) {
	normalized, err := NormalizeAndValidateRouteRules(rules, groups)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

// InitializeRouteRulesControlPlane imports YAML once, then keeps PostgreSQL
// authoritative across ordinary reloads and SIGHUP.
func InitializeRouteRulesControlPlane(ctx context.Context, store RouteRulesStore, cfg *Config) (RouteRulesDocument, bool, error) {
	if store == nil {
		return RouteRulesDocument{}, false, errors.New("route-rule control-plane store is unavailable")
	}
	if cfg == nil {
		return RouteRulesDocument{}, false, errors.New("route-rule bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadRouteRules(ctx)
	if err != nil {
		return RouteRulesDocument{}, false, fmt.Errorf("load route-rule control-plane document: %w", err)
	}
	imported := false
	if !found {
		rules, err := canonicalRouteRules(cfg.Upstream.Rules, cfg.Upstream.Groups)
		if err != nil {
			return RouteRulesDocument{}, false, fmt.Errorf("validate route-rule bootstrap configuration: %w", err)
		}
		document, err = store.SaveRouteRules(ctx, 0, rules, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrRouteRulesRevisionConflict) {
				document, found, err = store.LoadRouteRules(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("route-rule document disappeared after a revision conflict")
				}
			}
			if err != nil {
				return RouteRulesDocument{}, false, fmt.Errorf("import route-rule YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}
	if err := applyRouteRulesControlPlaneDocument(document, cfg); err != nil {
		return RouteRulesDocument{}, false, err
	}
	return document, imported, nil
}

func SaveRouteRulesControlPlane(ctx context.Context, store RouteRulesStore, rules []RouteConfig, actor, reason string) (RouteRulesDocument, error) {
	if store == nil {
		return RouteRulesDocument{}, errors.New("route-rule control-plane store is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadRouteRules(ctx)
	if err != nil {
		return RouteRulesDocument{}, fmt.Errorf("%w: load current route-rule configuration: %v", ErrRoutePersistence, err)
	}
	expectedRevision := int64(0)
	if found {
		if err := validateCanonicalRouteRulesDocument(current, nil); err != nil {
			return RouteRulesDocument{}, fmt.Errorf("validate current route-rule configuration: %w", err)
		}
		expectedRevision = current.Revision
	}
	return saveRouteRulesControlPlane(ctx, store, expectedRevision, rules, actor, reason)
}

func MutateRouteRulesControlPlane(ctx context.Context, store RouteRulesStore, mutator func([]RouteConfig) ([]RouteConfig, error), actor, reason string) (RouteRulesDocument, error) {
	if store == nil {
		return RouteRulesDocument{}, errors.New("route-rule control-plane store is unavailable")
	}
	if mutator == nil {
		return RouteRulesDocument{}, errors.New("route-rule mutator is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadRouteRules(ctx)
	if err != nil {
		return RouteRulesDocument{}, fmt.Errorf("%w: load current route-rule configuration: %v", ErrRoutePersistence, err)
	}
	if !found {
		return RouteRulesDocument{}, errors.New("route-rule configuration is unavailable")
	}
	if err := validateCanonicalRouteRulesDocument(current, nil); err != nil {
		return RouteRulesDocument{}, fmt.Errorf("validate current route-rule configuration: %w", err)
	}
	updated, err := mutator(CloneRouteConfigs(current.Rules))
	if err != nil {
		return RouteRulesDocument{}, err
	}
	return saveRouteRulesControlPlane(ctx, store, current.Revision, updated, actor, reason)
}

func saveRouteRulesControlPlane(ctx context.Context, store RouteRulesStore, expectedRevision int64, rules []RouteConfig, actor, reason string) (RouteRulesDocument, error) {
	canonical, err := CanonicalRouteRules(rules)
	if err != nil {
		return RouteRulesDocument{}, fmt.Errorf("%w: %v", ErrRouteValidation, err)
	}
	document, err := store.SaveRouteRules(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		if errors.Is(err, ErrRouteRulesRevisionConflict) {
			return RouteRulesDocument{}, err
		}
		return RouteRulesDocument{}, fmt.Errorf("%w: %v", ErrRoutePersistence, err)
	}
	if err := ApplyRouteRulesControlPlaneDocument(document); err != nil {
		return RouteRulesDocument{}, fmt.Errorf("%w: activate saved route-rule configuration: %v", ErrRoutePersistence, err)
	}
	return document, nil
}

func ApplyRouteRulesControlPlaneDocument(document RouteRulesDocument) error {
	return applyRouteRulesControlPlaneDocument(document, nil)
}

func applyRouteRulesControlPlaneDocument(document RouteRulesDocument, bootstrap *Config) error {
	if err := validateCanonicalRouteRulesDocument(document, bootstrap); err != nil {
		return err
	}

	routeRulesControlPlaneMu.Lock()
	defer routeRulesControlPlaneMu.Unlock()
	if routeRulesActivator != nil {
		if err := routeRulesActivator(CloneRouteConfigs(document.Rules)); err != nil {
			return fmt.Errorf("activate route rules: %w", err)
		}
	}
	activateRouteRulesControlPlaneConfig(bootstrap, document.Rules)
	return nil
}

func validateCanonicalRouteRulesDocument(document RouteRulesDocument, bootstrap *Config) error {
	if document.Revision < 1 {
		return errors.New("route-rule configuration revision is invalid")
	}
	canonical, err := canonicalRouteRules(document.Rules, currentUpstreamGroupsForRouteRules(bootstrap))
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(canonical, document.Rules) {
		return errors.New("route-rule configuration document is not canonical")
	}
	return nil
}

func currentUpstreamGroupsForRouteRules(bootstrap *Config) []UpstreamGroup {
	if bootstrap != nil {
		return CloneUpstreamGroups(bootstrap.Upstream.Groups)
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if GlobalConfig == nil {
		return nil
	}
	return CloneUpstreamGroups(GlobalConfig.Upstream.Groups)
}

func activateRouteRulesControlPlaneConfig(bootstrap *Config, rules []RouteConfig) {
	configMu.Lock()
	if GlobalConfig != nil {
		activated := *GlobalConfig
		activated.Upstream.Rules = CloneRouteConfigs(rules)
		GlobalConfig = &activated
	} else if bootstrap != nil {
		activated := *bootstrap
		activated.Upstream.Rules = CloneRouteConfigs(rules)
		GlobalConfig = &activated
	}
	routeRulesControlPlaneManaged = true
	if bootstrap != nil {
		bootstrap.Upstream.Rules = CloneRouteConfigs(rules)
	}
	configMu.Unlock()
}

func preserveManagedRouteRules(cfg *Config) {
	if cfg == nil {
		return
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if !routeRulesControlPlaneManaged || GlobalConfig == nil {
		return
	}
	cfg.Upstream.Rules = CloneRouteConfigs(GlobalConfig.Upstream.Rules)
}

func routeRulesControlPlaneIsManaged() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return routeRulesControlPlaneManaged
}

func routeRulesMutator() RouteRulesControlPlaneMutator {
	routeRulesMutatorMu.RLock()
	defer routeRulesMutatorMu.RUnlock()
	return routeRulesControlPlaneMutator
}
