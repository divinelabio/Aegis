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
	InfrastructureConfigurationScope         = "infrastructure"
	InfrastructureConfigurationSchemaVersion = 1
)

var ErrInfrastructureRevisionConflict = errors.New("infrastructure configuration revision conflict")

// InfrastructureRevisionConflictError reports a stale complete-document save.
// Callers use errors.Is(err, ErrInfrastructureRevisionConflict) to return HTTP
// 409 rather than overwriting another operator's ingress trust change.
type InfrastructureRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *InfrastructureRevisionConflictError) Error() string {
	if e == nil {
		return ErrInfrastructureRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrInfrastructureRevisionConflict, e.Expected, e.Actual)
}

func (e *InfrastructureRevisionConflictError) Unwrap() error {
	return ErrInfrastructureRevisionConflict
}

// InfrastructureDocument is the complete ingress trust contract persisted by
// the control plane. Revision is assigned by the durable store.
type InfrastructureDocument struct {
	Config   InfrastructureConfig
	Revision int64
}

// InfrastructureStore lets the configuration domain own validation and
// last-known-good activation without depending on a PostgreSQL implementation.
type InfrastructureStore interface {
	LoadInfrastructure(context.Context) (InfrastructureDocument, bool, error)
	SaveInfrastructure(ctx context.Context, expectedRevision int64, next InfrastructureConfig, actor, reason string) (InfrastructureDocument, error)
}

// InfrastructureRuntimeActivator makes a committed document effective in the
// request path. It must retain the previous live runtime on error. The main
// process wires it to the RealIP resolver and proxy metadata runtime after
// those components are created.
type InfrastructureRuntimeActivator func(InfrastructureConfig) error

var (
	infrastructureControlPlaneManaged bool
	infrastructureControlPlaneMu      sync.Mutex
	infrastructureRuntimeActivator    InfrastructureRuntimeActivator
)

// SetInfrastructureRuntimeActivator registers the request-path activation
// boundary. It is intentionally optional during bootstrap: the document is
// loaded before the proxy components are constructed, and those components are
// then built from the activated configuration.
func SetInfrastructureRuntimeActivator(activator InfrastructureRuntimeActivator) {
	infrastructureControlPlaneMu.Lock()
	infrastructureRuntimeActivator = activator
	infrastructureControlPlaneMu.Unlock()
}

// CanonicalInfrastructureConfig applies stable defaults, validates the ingress
// trust boundary, and deep-copies caller-owned collections before persistence.
func CanonicalInfrastructureConfig(next InfrastructureConfig, serverPort int) (InfrastructureConfig, error) {
	next = NormalizeInfrastructureConfig(cloneInfrastructureConfig(next), serverPort)
	if err := ValidateInfrastructureConfig(next); err != nil {
		return InfrastructureConfig{}, err
	}
	return cloneInfrastructureConfig(next), nil
}

// InitializeInfrastructureControlPlane imports YAML once when PostgreSQL has
// no document. Afterward the database is authoritative on startup and SIGHUP;
// an old config.yaml must never reclaim ingress-trust behavior.
func InitializeInfrastructureControlPlane(ctx context.Context, store InfrastructureStore, cfg *Config) (InfrastructureDocument, bool, error) {
	if store == nil {
		return InfrastructureDocument{}, false, errors.New("infrastructure control-plane store is unavailable")
	}
	if cfg == nil {
		return InfrastructureDocument{}, false, errors.New("infrastructure bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadInfrastructure(ctx)
	if err != nil {
		return InfrastructureDocument{}, false, fmt.Errorf("load infrastructure control-plane document: %w", err)
	}
	imported := false
	if !found {
		bootstrap, err := CanonicalInfrastructureConfig(cfg.Infrastructure, cfg.Server.Port)
		if err != nil {
			return InfrastructureDocument{}, false, fmt.Errorf("validate infrastructure bootstrap configuration: %w", err)
		}
		document, err = store.SaveInfrastructure(ctx, 0, bootstrap, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrInfrastructureRevisionConflict) {
				document, found, err = store.LoadInfrastructure(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("infrastructure document disappeared after a revision conflict")
				}
			}
			if err != nil {
				return InfrastructureDocument{}, false, fmt.Errorf("import infrastructure YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}
	if err := applyInfrastructureControlPlaneDocument(document, cfg); err != nil {
		return InfrastructureDocument{}, false, err
	}
	return cloneInfrastructureDocument(document), imported, nil
}

// SaveInfrastructureControlPlane commits a complete canonical ingress-trust
// document before changing request identity behavior. If PostgreSQL rejects
// the write, the last-known-good resolver and configuration remain active.
func SaveInfrastructureControlPlane(ctx context.Context, store InfrastructureStore, next InfrastructureConfig, actor, reason string) (InfrastructureDocument, error) {
	if store == nil {
		return InfrastructureDocument{}, errors.New("infrastructure control-plane store is unavailable")
	}
	canonical, err := CanonicalInfrastructureConfig(next, infrastructureControlPlaneServerPort())
	if err != nil {
		return InfrastructureDocument{}, fmt.Errorf("validate infrastructure configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadInfrastructure(ctx)
	if err != nil {
		return InfrastructureDocument{}, fmt.Errorf("load current infrastructure configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		if err := validateCanonicalInfrastructureDocument(current, infrastructureControlPlaneServerPort()); err != nil {
			return InfrastructureDocument{}, fmt.Errorf("validate current infrastructure configuration: %w", err)
		}
		expectedRevision = current.Revision
	}
	document, err := store.SaveInfrastructure(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return InfrastructureDocument{}, err
	}
	if err := ApplyInfrastructureControlPlaneDocument(document); err != nil {
		return InfrastructureDocument{}, fmt.Errorf("activate saved infrastructure configuration: %w", err)
	}
	return cloneInfrastructureDocument(document), nil
}

// ApplyInfrastructureControlPlaneDocument validates and activates a committed
// PostgreSQL document. It is called by every process's change listener, so an
// invalid or noncanonical document cannot replace last-known-good client IP
// resolution or proxy metadata.
func ApplyInfrastructureControlPlaneDocument(document InfrastructureDocument) error {
	return applyInfrastructureControlPlaneDocument(document, nil)
}

func applyInfrastructureControlPlaneDocument(document InfrastructureDocument, bootstrap *Config) error {
	serverPort := infrastructureControlPlaneServerPort()
	if bootstrap != nil {
		serverPort = bootstrap.Server.Port
	}
	if err := validateCanonicalInfrastructureDocument(document, serverPort); err != nil {
		return err
	}
	next := cloneInfrastructureConfig(document.Config)

	infrastructureControlPlaneMu.Lock()
	defer infrastructureControlPlaneMu.Unlock()
	if infrastructureRuntimeActivator != nil {
		if err := infrastructureRuntimeActivator(cloneInfrastructureConfig(next)); err != nil {
			return fmt.Errorf("activate infrastructure runtime: %w", err)
		}
	}
	activateInfrastructureControlPlaneConfig(bootstrap, next)
	return nil
}

func validateCanonicalInfrastructureDocument(document InfrastructureDocument, serverPort int) error {
	if document.Revision < 1 {
		return errors.New("infrastructure configuration revision is invalid")
	}
	canonical, err := CanonicalInfrastructureConfig(document.Config, serverPort)
	if err != nil {
		return fmt.Errorf("validate infrastructure configuration: %w", err)
	}
	if !reflect.DeepEqual(canonical, document.Config) {
		return errors.New("infrastructure configuration document is not canonical")
	}
	return nil
}

// ContainsInfrastructureUpdate identifies flattened generic-config writes
// that would otherwise create a second YAML authority for proxy trust.
func ContainsInfrastructureUpdate(updates map[string]interface{}) bool {
	for key := range updates {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == InfrastructureConfigurationScope || strings.HasPrefix(key, InfrastructureConfigurationScope+".") {
			return true
		}
	}
	return false
}

func activateInfrastructureControlPlaneConfig(bootstrap *Config, next InfrastructureConfig) {
	next = cloneInfrastructureConfig(next)
	configMu.Lock()
	if GlobalConfig != nil {
		activated := *GlobalConfig
		activated.Infrastructure = next
		GlobalConfig = &activated
	} else if bootstrap != nil {
		activated := *bootstrap
		activated.Infrastructure = next
		GlobalConfig = &activated
	}
	infrastructureControlPlaneManaged = true
	if bootstrap != nil {
		bootstrap.Infrastructure = cloneInfrastructureConfig(next)
	}
	configMu.Unlock()
}

// preserveManagedInfrastructure overlays the active PostgreSQL document into a
// YAML-derived config on generic saves and SIGHUP reloads.
func preserveManagedInfrastructure(cfg *Config) {
	if cfg == nil {
		return
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if !infrastructureControlPlaneManaged || GlobalConfig == nil {
		return
	}
	cfg.Infrastructure = cloneInfrastructureConfig(GlobalConfig.Infrastructure)
}

func infrastructureControlPlaneServerPort() int {
	configMu.RLock()
	defer configMu.RUnlock()
	if GlobalConfig == nil {
		return 0
	}
	return GlobalConfig.Server.Port
}

func infrastructureControlPlaneIsManaged() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return infrastructureControlPlaneManaged
}

func cloneInfrastructureConfig(input InfrastructureConfig) InfrastructureConfig {
	clone := input
	clone.TrustedProxies.CIDRs = append([]string(nil), input.TrustedProxies.CIDRs...)
	clone.TrustedProxies.RealIPHeaders = append([]string(nil), input.TrustedProxies.RealIPHeaders...)
	clone.TrustedProxies.SourceURLs = append([]string(nil), input.TrustedProxies.SourceURLs...)
	clone.TrustedProxies.SourceFiles = append([]string(nil), input.TrustedProxies.SourceFiles...)
	return clone
}

func cloneInfrastructureDocument(input InfrastructureDocument) InfrastructureDocument {
	clone := input
	clone.Config = cloneInfrastructureConfig(input.Config)
	return clone
}
