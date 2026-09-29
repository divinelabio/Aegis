package config

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

const (
	UpstreamGroupsConfigurationScope         = "upstream.origin_pools"
	UpstreamGroupsConfigurationSchemaVersion = 1
)

var ErrUpstreamGroupsRevisionConflict = errors.New("upstream Origin-pool configuration revision conflict")

// UpstreamGroupsRevisionConflictError reports a stale complete-document write.
// Callers must reload rather than silently replacing a concurrent pool edit.
type UpstreamGroupsRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *UpstreamGroupsRevisionConflictError) Error() string {
	if e == nil {
		return ErrUpstreamGroupsRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrUpstreamGroupsRevisionConflict, e.Expected, e.Actual)
}

func (e *UpstreamGroupsRevisionConflictError) Unwrap() error {
	return ErrUpstreamGroupsRevisionConflict
}

// UpstreamGroupsDocument owns the complete named Origin-pool collection. Route
// rules stay in their own document because they reference these names.
type UpstreamGroupsDocument struct {
	Groups   []UpstreamGroup
	Revision int64
}

type UpstreamGroupsStore interface {
	LoadUpstreamGroups(context.Context) (UpstreamGroupsDocument, bool, error)
	SaveUpstreamGroups(ctx context.Context, expectedRevision int64, groups []UpstreamGroup, actor, reason string) (UpstreamGroupsDocument, error)
}

var upstreamGroupsControlPlaneManaged bool

func CanonicalUpstreamGroups(groups []UpstreamGroup) ([]UpstreamGroup, error) {
	normalized, err := NormalizeAndValidateUpstreamGroups(groups)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

// InitializeUpstreamGroupsControlPlane imports the YAML pool collection once.
// Once a PostgreSQL document exists, it remains authoritative across reloads.
func InitializeUpstreamGroupsControlPlane(ctx context.Context, store UpstreamGroupsStore, cfg *Config) (UpstreamGroupsDocument, bool, error) {
	if store == nil {
		return UpstreamGroupsDocument{}, false, errors.New("upstream Origin-pool control-plane store is unavailable")
	}
	if cfg == nil {
		return UpstreamGroupsDocument{}, false, errors.New("upstream Origin-pool bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadUpstreamGroups(ctx)
	if err != nil {
		return UpstreamGroupsDocument{}, false, fmt.Errorf("load upstream Origin-pool control-plane document: %w", err)
	}
	imported := false
	if !found {
		groups, err := CanonicalUpstreamGroups(cfg.Upstream.Groups)
		if err != nil {
			return UpstreamGroupsDocument{}, false, fmt.Errorf("validate upstream Origin-pool bootstrap configuration: %w", err)
		}
		if err := validateUpstreamGroupReferences(groups); err != nil {
			return UpstreamGroupsDocument{}, false, err
		}
		document, err = store.SaveUpstreamGroups(ctx, 0, groups, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrUpstreamGroupsRevisionConflict) {
				document, found, err = store.LoadUpstreamGroups(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("upstream Origin-pool document disappeared after a revision conflict")
				}
			}
			if err != nil {
				return UpstreamGroupsDocument{}, false, fmt.Errorf("import upstream Origin-pool YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}
	if err := applyUpstreamGroupsControlPlaneDocument(document, cfg); err != nil {
		return UpstreamGroupsDocument{}, false, err
	}
	return document, imported, nil
}

// SaveUpstreamGroupsControlPlane saves a complete Origin-pool document using
// compare-and-swap and then applies it to the active proxy runtime.
func SaveUpstreamGroupsControlPlane(ctx context.Context, store UpstreamGroupsStore, groups []UpstreamGroup, actor, reason string) (UpstreamGroupsDocument, error) {
	if store == nil {
		return UpstreamGroupsDocument{}, errors.New("upstream Origin-pool control-plane store is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadUpstreamGroups(ctx)
	if err != nil {
		return UpstreamGroupsDocument{}, fmt.Errorf("load current upstream Origin-pool configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		if err := validateCanonicalUpstreamGroupsDocument(current); err != nil {
			return UpstreamGroupsDocument{}, fmt.Errorf("validate current upstream Origin-pool configuration: %w", err)
		}
		expectedRevision = current.Revision
	}
	return saveUpstreamGroupsControlPlane(ctx, store, expectedRevision, groups, actor, reason)
}

// MutateUpstreamGroupsControlPlane applies a collection mutation against the
// latest stored document. The CAS protects concurrent admin writers.
func MutateUpstreamGroupsControlPlane(ctx context.Context, store UpstreamGroupsStore, mutator func([]UpstreamGroup) ([]UpstreamGroup, error), actor, reason string) (UpstreamGroupsDocument, error) {
	if store == nil {
		return UpstreamGroupsDocument{}, errors.New("upstream Origin-pool control-plane store is unavailable")
	}
	if mutator == nil {
		return UpstreamGroupsDocument{}, errors.New("upstream Origin-pool mutator is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadUpstreamGroups(ctx)
	if err != nil {
		return UpstreamGroupsDocument{}, fmt.Errorf("load current upstream Origin-pool configuration: %w", err)
	}
	if !found {
		return UpstreamGroupsDocument{}, errors.New("upstream Origin-pool configuration is unavailable")
	}
	if err := validateCanonicalUpstreamGroupsDocument(current); err != nil {
		return UpstreamGroupsDocument{}, fmt.Errorf("validate current upstream Origin-pool configuration: %w", err)
	}
	updated, err := mutator(CloneUpstreamGroups(current.Groups))
	if err != nil {
		return UpstreamGroupsDocument{}, err
	}
	return saveUpstreamGroupsControlPlane(ctx, store, current.Revision, updated, actor, reason)
}

func saveUpstreamGroupsControlPlane(ctx context.Context, store UpstreamGroupsStore, expectedRevision int64, groups []UpstreamGroup, actor, reason string) (UpstreamGroupsDocument, error) {
	canonical, err := CanonicalUpstreamGroups(groups)
	if err != nil {
		return UpstreamGroupsDocument{}, fmt.Errorf("%w: %v", ErrUpstreamValidation, err)
	}
	if err := validateUpstreamGroupReferences(canonical); err != nil {
		return UpstreamGroupsDocument{}, err
	}
	document, err := store.SaveUpstreamGroups(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return UpstreamGroupsDocument{}, err
	}
	if err := ApplyUpstreamGroupsControlPlaneDocument(document); err != nil {
		return UpstreamGroupsDocument{}, fmt.Errorf("activate saved upstream Origin-pool configuration: %w", err)
	}
	return document, nil
}

func ApplyUpstreamGroupsControlPlaneDocument(document UpstreamGroupsDocument) error {
	return applyUpstreamGroupsControlPlaneDocument(document, nil)
}

func applyUpstreamGroupsControlPlaneDocument(document UpstreamGroupsDocument, bootstrap *Config) error {
	if err := validateCanonicalUpstreamGroupsDocument(document); err != nil {
		return err
	}
	if err := validateUpstreamGroupReferences(document.Groups); err != nil {
		return err
	}

	// The runtime-tuning and Origin-pool documents both rebuild the same
	// upstream manager and transport, so their activation is serialized.
	upstreamRuntimeControlPlaneMu.Lock()
	defer upstreamRuntimeControlPlaneMu.Unlock()
	base := currentUpstreamForRuntimeActivation(bootstrap)
	nextUpstream := base
	nextUpstream.Groups = CloneUpstreamGroups(document.Groups)
	if upstreamRuntimeActivator != nil {
		if err := upstreamRuntimeActivator(nextUpstream); err != nil {
			return fmt.Errorf("activate upstream Origin pools: %w", err)
		}
	}
	activateUpstreamGroupsControlPlaneConfig(bootstrap, document.Groups)
	return nil
}

func validateCanonicalUpstreamGroupsDocument(document UpstreamGroupsDocument) error {
	if document.Revision < 1 {
		return errors.New("upstream Origin-pool configuration revision is invalid")
	}
	canonical, err := CanonicalUpstreamGroups(document.Groups)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(canonical, document.Groups) {
		return errors.New("upstream Origin-pool configuration document is not canonical")
	}
	return nil
}

func validateUpstreamGroupReferences(groups []UpstreamGroup) error {
	configMu.RLock()
	if GlobalConfig == nil {
		configMu.RUnlock()
		return errors.New("configuration is not loaded")
	}
	routes := CloneRouteConfigs(GlobalConfig.Upstream.Rules)
	legacyRoutes := make(map[string]string, len(GlobalConfig.Upstream.Routes))
	for host, target := range GlobalConfig.Upstream.Routes {
		legacyRoutes[host] = target
	}
	stickySecret := GlobalConfig.Upstream.StickySecret
	configMu.RUnlock()
	if stickySessionsEnabled(groups) && len(strings.TrimSpace(stickySecret)) < 32 {
		return fmt.Errorf("%w: configure a sticky-session env secret reference before enabling sticky sessions", ErrUpstreamValidation)
	}
	if err := ValidateRouteUpstreamReferences(routes, groups); err != nil {
		return err
	}
	if err := ValidateLegacyRouteUpstreamReferences(legacyRoutes, groups); err != nil {
		return fmt.Errorf("%w: %v", ErrUpstreamDependency, err)
	}
	return nil
}

func activateUpstreamGroupsControlPlaneConfig(bootstrap *Config, groups []UpstreamGroup) {
	configMu.Lock()
	if GlobalConfig != nil {
		activated := *GlobalConfig
		activated.Upstream.Groups = CloneUpstreamGroups(groups)
		GlobalConfig = &activated
	} else if bootstrap != nil {
		activated := *bootstrap
		activated.Upstream.Groups = CloneUpstreamGroups(groups)
		GlobalConfig = &activated
	}
	upstreamGroupsControlPlaneManaged = true
	if bootstrap != nil {
		bootstrap.Upstream.Groups = CloneUpstreamGroups(groups)
	}
	configMu.Unlock()
}

func preserveManagedUpstreamGroups(cfg *Config) {
	if cfg == nil {
		return
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if !upstreamGroupsControlPlaneManaged || GlobalConfig == nil {
		return
	}
	cfg.Upstream.Groups = CloneUpstreamGroups(GlobalConfig.Upstream.Groups)
}

func upstreamGroupsControlPlaneIsManaged() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return upstreamGroupsControlPlaneManaged
}
