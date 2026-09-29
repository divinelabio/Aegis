package config

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

const (
	LegacyRoutesConfigurationScope         = "upstream.legacy_routes"
	LegacyRoutesConfigurationSchemaVersion = 1
	MaxLegacyHostRoutes                    = 10000
)

var ErrLegacyRoutesRevisionConflict = errors.New("legacy host-route configuration revision conflict")

// LegacyRoutesRevisionConflictError reports a stale complete mapping update.
type LegacyRoutesRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *LegacyRoutesRevisionConflictError) Error() string {
	if e == nil {
		return ErrLegacyRoutesRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrLegacyRoutesRevisionConflict, e.Expected, e.Actual)
}

func (e *LegacyRoutesRevisionConflictError) Unwrap() error {
	return ErrLegacyRoutesRevisionConflict
}

// LegacyRoutesDocument owns the legacy host-to-Origin mapping only. Advanced
// rules, Origin pools, breaker policy, and sticky credentials retain separate
// control-plane boundaries.
type LegacyRoutesDocument struct {
	Routes   map[string]string
	Revision int64
}

type LegacyRoutesStore interface {
	LoadLegacyRoutes(context.Context) (LegacyRoutesDocument, bool, error)
	SaveLegacyRoutes(ctx context.Context, expectedRevision int64, routes map[string]string, actor, reason string) (LegacyRoutesDocument, error)
}

// LegacyRoutesActivator applies a committed mapping to the proxy request path.
type LegacyRoutesActivator func(map[string]string) error

var (
	legacyRoutesControlPlaneManaged bool
	legacyRoutesControlPlaneMu      sync.Mutex
	legacyRoutesActivator           LegacyRoutesActivator
)

func SetLegacyRoutesActivator(activator LegacyRoutesActivator) {
	legacyRoutesControlPlaneMu.Lock()
	legacyRoutesActivator = activator
	legacyRoutesControlPlaneMu.Unlock()
}

// CanonicalLegacyRoutes normalizes mapping keys and targets using the active
// Origin pool set. It is suitable for API and document validation.
func CanonicalLegacyRoutes(routes map[string]string) (map[string]string, error) {
	return CanonicalLegacyRoutesForGroups(routes, currentUpstreamGroupsForLegacyRoutes(nil))
}

// CanonicalLegacyRoutesForGroups validates a mapping against an explicit
// Origin-pool snapshot. PostgreSQL listeners use it to avoid relying on a
// process-local configuration that may be behind the durable pool document.
func CanonicalLegacyRoutesForGroups(routes map[string]string, groups []UpstreamGroup) (map[string]string, error) {
	if len(routes) > MaxLegacyHostRoutes {
		return nil, fmt.Errorf("legacy host-route count %d exceeds limit %d", len(routes), MaxLegacyHostRoutes)
	}
	canonical := make(map[string]string, len(routes))
	for host, target := range routes {
		host = strings.TrimSpace(host)
		target = strings.TrimSpace(target)
		if _, exists := canonical[host]; exists {
			return nil, fmt.Errorf("duplicate legacy host route %q after normalization", host)
		}
		canonical[host] = target
	}
	if err := ValidateLegacyRouteUpstreamReferences(canonical, groups); err != nil {
		return nil, err
	}
	return canonical, nil
}

// CloneLegacyRoutes returns an independent snapshot while preserving the
// distinction between an absent map and an explicit empty document.
func CloneLegacyRoutes(routes map[string]string) map[string]string {
	if routes == nil {
		return nil
	}
	cloned := make(map[string]string, len(routes))
	for host, target := range routes {
		cloned[host] = target
	}
	return cloned
}

// InitializeLegacyRoutesControlPlane imports YAML once, then keeps PostgreSQL
// authoritative across ordinary saves and SIGHUP reloads.
func InitializeLegacyRoutesControlPlane(ctx context.Context, store LegacyRoutesStore, cfg *Config) (LegacyRoutesDocument, bool, error) {
	if store == nil {
		return LegacyRoutesDocument{}, false, errors.New("legacy host-route control-plane store is unavailable")
	}
	if cfg == nil {
		return LegacyRoutesDocument{}, false, errors.New("legacy host-route bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadLegacyRoutes(ctx)
	if err != nil {
		return LegacyRoutesDocument{}, false, fmt.Errorf("load legacy host-route control-plane document: %w", err)
	}
	imported := false
	if !found {
		routes, err := CanonicalLegacyRoutesForGroups(cfg.Upstream.Routes, cfg.Upstream.Groups)
		if err != nil {
			return LegacyRoutesDocument{}, false, fmt.Errorf("validate legacy host-route bootstrap configuration: %w", err)
		}
		document, err = store.SaveLegacyRoutes(ctx, 0, routes, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrLegacyRoutesRevisionConflict) {
				document, found, err = store.LoadLegacyRoutes(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("legacy host-route document disappeared after a revision conflict")
				}
			}
			if err != nil {
				return LegacyRoutesDocument{}, false, fmt.Errorf("import legacy host-route YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}
	if err := applyLegacyRoutesControlPlaneDocument(document, cfg); err != nil {
		return LegacyRoutesDocument{}, false, err
	}
	return document, imported, nil
}

// SaveLegacyRoutesControlPlane commits a complete mapping before replacing
// proxy host-route selection state.
func SaveLegacyRoutesControlPlane(ctx context.Context, store LegacyRoutesStore, routes map[string]string, actor, reason string) (LegacyRoutesDocument, error) {
	if store == nil {
		return LegacyRoutesDocument{}, errors.New("legacy host-route control-plane store is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadLegacyRoutes(ctx)
	if err != nil {
		return LegacyRoutesDocument{}, fmt.Errorf("load current legacy host-route configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		if err := validateCanonicalLegacyRoutesDocument(current, nil); err != nil {
			return LegacyRoutesDocument{}, fmt.Errorf("validate current legacy host-route configuration: %w", err)
		}
		expectedRevision = current.Revision
	}
	canonical, err := CanonicalLegacyRoutes(routes)
	if err != nil {
		return LegacyRoutesDocument{}, fmt.Errorf("validate legacy host-route configuration: %w", err)
	}
	document, err := store.SaveLegacyRoutes(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return LegacyRoutesDocument{}, err
	}
	if err := ApplyLegacyRoutesControlPlaneDocument(document); err != nil {
		return LegacyRoutesDocument{}, fmt.Errorf("activate saved legacy host-route configuration: %w", err)
	}
	return document, nil
}

func ApplyLegacyRoutesControlPlaneDocument(document LegacyRoutesDocument) error {
	return applyLegacyRoutesControlPlaneDocument(document, nil)
}

func applyLegacyRoutesControlPlaneDocument(document LegacyRoutesDocument, bootstrap *Config) error {
	if err := validateCanonicalLegacyRoutesDocument(document, bootstrap); err != nil {
		return err
	}

	legacyRoutesControlPlaneMu.Lock()
	defer legacyRoutesControlPlaneMu.Unlock()
	if legacyRoutesActivator != nil {
		if err := legacyRoutesActivator(CloneLegacyRoutes(document.Routes)); err != nil {
			return fmt.Errorf("activate legacy host routes: %w", err)
		}
	}
	activateLegacyRoutesControlPlaneConfig(bootstrap, document.Routes)
	return nil
}

func validateCanonicalLegacyRoutesDocument(document LegacyRoutesDocument, bootstrap *Config) error {
	if document.Revision < 1 {
		return errors.New("legacy host-route configuration revision is invalid")
	}
	canonical, err := CanonicalLegacyRoutesForGroups(document.Routes, currentUpstreamGroupsForLegacyRoutes(bootstrap))
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(canonical, document.Routes) {
		return errors.New("legacy host-route configuration document is not canonical")
	}
	return nil
}

func currentUpstreamGroupsForLegacyRoutes(bootstrap *Config) []UpstreamGroup {
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

func activateLegacyRoutesControlPlaneConfig(bootstrap *Config, routes map[string]string) {
	configMu.Lock()
	if GlobalConfig != nil {
		activated := *GlobalConfig
		activated.Upstream.Routes = CloneLegacyRoutes(routes)
		GlobalConfig = &activated
	} else if bootstrap != nil {
		activated := *bootstrap
		activated.Upstream.Routes = CloneLegacyRoutes(routes)
		GlobalConfig = &activated
	}
	legacyRoutesControlPlaneManaged = true
	if bootstrap != nil {
		bootstrap.Upstream.Routes = CloneLegacyRoutes(routes)
	}
	configMu.Unlock()
}

func preserveManagedLegacyRoutes(cfg *Config) {
	if cfg == nil {
		return
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if !legacyRoutesControlPlaneManaged || GlobalConfig == nil {
		return
	}
	cfg.Upstream.Routes = CloneLegacyRoutes(GlobalConfig.Upstream.Routes)
}
