package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	UpstreamRuntimeConfigurationScope         = "upstream.runtime_settings"
	UpstreamRuntimeConfigurationSchemaVersion = 1
)

var ErrUpstreamRuntimeRevisionConflict = errors.New("upstream runtime configuration revision conflict")

// UpstreamRuntimeRevisionConflictError reports a stale complete-document
// update. Handlers map it to HTTP 409 to avoid silently replacing a concurrent
// Origin runtime-tuning update.
type UpstreamRuntimeRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *UpstreamRuntimeRevisionConflictError) Error() string {
	if e == nil {
		return ErrUpstreamRuntimeRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrUpstreamRuntimeRevisionConflict, e.Expected, e.Actual)
}

func (e *UpstreamRuntimeRevisionConflictError) Unwrap() error {
	return ErrUpstreamRuntimeRevisionConflict
}

// UpstreamRuntimeDocument owns only the Settings-page subset of upstream
// configuration. Origin pools and routing rules retain their dedicated APIs
// and will migrate as independent, reference-safe documents.
type UpstreamRuntimeDocument struct {
	Settings UpstreamRuntimeSettings
	Revision int64
}

type UpstreamRuntimeStore interface {
	LoadUpstreamRuntime(context.Context) (UpstreamRuntimeDocument, bool, error)
	SaveUpstreamRuntime(ctx context.Context, expectedRevision int64, settings UpstreamRuntimeSettings, actor, reason string) (UpstreamRuntimeDocument, error)
}

// UpstreamRuntimeActivator receives a full upstream snapshot with the durable
// runtime fields overlaid. It must retain the active request path on error.
type UpstreamRuntimeActivator func(UpstreamConfig) error

var (
	upstreamRuntimeControlPlaneManaged bool
	upstreamRuntimeControlPlaneMu      sync.Mutex
	upstreamRuntimeActivator           UpstreamRuntimeActivator
)

func SetUpstreamRuntimeActivator(activator UpstreamRuntimeActivator) {
	upstreamRuntimeControlPlaneMu.Lock()
	upstreamRuntimeActivator = activator
	upstreamRuntimeControlPlaneMu.Unlock()
}

// CanonicalUpstreamRuntimeSettings applies stable defaults and validates only
// the Settings-page fields. It does not inspect route or Origin-pool state.
func CanonicalUpstreamRuntimeSettings(next UpstreamRuntimeSettings) (UpstreamRuntimeSettings, error) {
	next.Target = strings.TrimSpace(next.Target)
	if next.Target != "" {
		if err := validateRouteBackend(UpstreamTarget{URL: next.Target, Weight: 1}); err != nil {
			return UpstreamRuntimeSettings{}, fmt.Errorf("invalid upstream.target: %w", err)
		}
	}
	if next.HealthCheckConcurrency <= 0 {
		next.HealthCheckConcurrency = 32
	}
	if next.HealthCheckConcurrency > 256 {
		return UpstreamRuntimeSettings{}, errors.New("upstream.health_check_concurrency must be between 1 and 256")
	}
	if next.MaxIdleConns <= 0 {
		next.MaxIdleConns = 1000
	}
	if next.MaxIdleConnsPerHost <= 0 {
		next.MaxIdleConnsPerHost = 20
	}
	if next.MaxConnsPerHost <= 0 {
		next.MaxConnsPerHost = 100
	}
	if next.MaxIdleConns > 10000 || next.MaxIdleConnsPerHost > 2000 || next.MaxConnsPerHost > 10000 {
		return UpstreamRuntimeSettings{}, errors.New("upstream connection-pool limits exceed safe maximums")
	}
	next.IdleTimeout = strings.TrimSpace(next.IdleTimeout)
	if next.IdleTimeout == "" {
		next.IdleTimeout = "90s"
	}
	if duration, err := time.ParseDuration(next.IdleTimeout); err != nil || duration < time.Second || duration > 10*time.Minute {
		return UpstreamRuntimeSettings{}, errors.New("upstream.idle_timeout must be between 1s and 10m")
	}
	next.TLSHandshakeTimeout = strings.TrimSpace(next.TLSHandshakeTimeout)
	if next.TLSHandshakeTimeout == "" {
		next.TLSHandshakeTimeout = "10s"
	}
	if duration, err := time.ParseDuration(next.TLSHandshakeTimeout); err != nil || duration < time.Second || duration > 2*time.Minute {
		return UpstreamRuntimeSettings{}, errors.New("upstream.tls_timeout must be between 1s and 2m")
	}
	return next, nil
}

// InitializeUpstreamRuntimeControlPlane imports YAML once. PostgreSQL is then
// authoritative for runtime tuning on both startup and SIGHUP reloads.
func InitializeUpstreamRuntimeControlPlane(ctx context.Context, store UpstreamRuntimeStore, cfg *Config) (UpstreamRuntimeDocument, bool, error) {
	if store == nil {
		return UpstreamRuntimeDocument{}, false, errors.New("upstream runtime control-plane store is unavailable")
	}
	if cfg == nil {
		return UpstreamRuntimeDocument{}, false, errors.New("upstream runtime bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadUpstreamRuntime(ctx)
	if err != nil {
		return UpstreamRuntimeDocument{}, false, fmt.Errorf("load upstream runtime control-plane document: %w", err)
	}
	imported := false
	if !found {
		bootstrap, err := CanonicalUpstreamRuntimeSettings(upstreamRuntimeSettingsFromConfig(cfg.Upstream))
		if err != nil {
			return UpstreamRuntimeDocument{}, false, fmt.Errorf("validate upstream runtime bootstrap configuration: %w", err)
		}
		document, err = store.SaveUpstreamRuntime(ctx, 0, bootstrap, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrUpstreamRuntimeRevisionConflict) {
				document, found, err = store.LoadUpstreamRuntime(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("upstream runtime document disappeared after a revision conflict")
				}
			}
			if err != nil {
				return UpstreamRuntimeDocument{}, false, fmt.Errorf("import upstream runtime YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}
	if err := applyUpstreamRuntimeControlPlaneDocument(document, cfg); err != nil {
		return UpstreamRuntimeDocument{}, false, err
	}
	return document, imported, nil
}

// SaveUpstreamRuntimeControlPlane commits complete runtime tuning before
// replacing proxy or health-manager state.
func SaveUpstreamRuntimeControlPlane(ctx context.Context, store UpstreamRuntimeStore, settings UpstreamRuntimeSettings, actor, reason string) (UpstreamRuntimeDocument, error) {
	if store == nil {
		return UpstreamRuntimeDocument{}, errors.New("upstream runtime control-plane store is unavailable")
	}
	canonical, err := CanonicalUpstreamRuntimeSettings(settings)
	if err != nil {
		return UpstreamRuntimeDocument{}, fmt.Errorf("validate upstream runtime configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadUpstreamRuntime(ctx)
	if err != nil {
		return UpstreamRuntimeDocument{}, fmt.Errorf("load current upstream runtime configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		if err := validateCanonicalUpstreamRuntimeDocument(current); err != nil {
			return UpstreamRuntimeDocument{}, fmt.Errorf("validate current upstream runtime configuration: %w", err)
		}
		expectedRevision = current.Revision
	}
	document, err := store.SaveUpstreamRuntime(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return UpstreamRuntimeDocument{}, err
	}
	if err := ApplyUpstreamRuntimeControlPlaneDocument(document); err != nil {
		return UpstreamRuntimeDocument{}, fmt.Errorf("activate saved upstream runtime configuration: %w", err)
	}
	return document, nil
}

func ApplyUpstreamRuntimeControlPlaneDocument(document UpstreamRuntimeDocument) error {
	return applyUpstreamRuntimeControlPlaneDocument(document, nil)
}

func applyUpstreamRuntimeControlPlaneDocument(document UpstreamRuntimeDocument, bootstrap *Config) error {
	if err := validateCanonicalUpstreamRuntimeDocument(document); err != nil {
		return err
	}

	upstreamRuntimeControlPlaneMu.Lock()
	defer upstreamRuntimeControlPlaneMu.Unlock()
	base := currentUpstreamForRuntimeActivation(bootstrap)
	nextUpstream := upstreamConfigWithRuntimeSettings(base, document.Settings)
	if upstreamRuntimeActivator != nil {
		if err := upstreamRuntimeActivator(nextUpstream); err != nil {
			return fmt.Errorf("activate upstream runtime: %w", err)
		}
	}
	activateUpstreamRuntimeControlPlaneConfig(bootstrap, document.Settings)
	return nil
}

func validateCanonicalUpstreamRuntimeDocument(document UpstreamRuntimeDocument) error {
	if document.Revision < 1 {
		return errors.New("upstream runtime configuration revision is invalid")
	}
	canonical, err := CanonicalUpstreamRuntimeSettings(document.Settings)
	if err != nil {
		return err
	}
	if canonical != document.Settings {
		return errors.New("upstream runtime configuration document is not canonical")
	}
	return nil
}

func ContainsUpstreamRuntimeUpdate(updates map[string]interface{}) bool {
	for key := range updates {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "upstream" || strings.HasPrefix(key, "upstream.") {
			return true
		}
	}
	return false
}

func currentUpstreamForRuntimeActivation(bootstrap *Config) UpstreamConfig {
	if bootstrap != nil {
		return bootstrap.Upstream
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if GlobalConfig == nil {
		return UpstreamConfig{}
	}
	return GlobalConfig.Upstream
}

func activateUpstreamRuntimeControlPlaneConfig(bootstrap *Config, settings UpstreamRuntimeSettings) {
	configMu.Lock()
	if GlobalConfig != nil {
		activated := *GlobalConfig
		activated.Upstream = upstreamConfigWithRuntimeSettings(activated.Upstream, settings)
		GlobalConfig = &activated
	} else if bootstrap != nil {
		activated := *bootstrap
		activated.Upstream = upstreamConfigWithRuntimeSettings(activated.Upstream, settings)
		GlobalConfig = &activated
	}
	upstreamRuntimeControlPlaneManaged = true
	if bootstrap != nil {
		bootstrap.Upstream = upstreamConfigWithRuntimeSettings(bootstrap.Upstream, settings)
	}
	configMu.Unlock()
}

func preserveManagedUpstreamRuntimeSettings(cfg *Config) {
	if cfg == nil {
		return
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if !upstreamRuntimeControlPlaneManaged || GlobalConfig == nil {
		return
	}
	cfg.Upstream = upstreamConfigWithRuntimeSettings(cfg.Upstream, upstreamRuntimeSettingsFromConfig(GlobalConfig.Upstream))
}

func upstreamRuntimeControlPlaneIsManaged() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return upstreamRuntimeControlPlaneManaged
}

func upstreamConfigWithRuntimeSettings(upstream UpstreamConfig, settings UpstreamRuntimeSettings) UpstreamConfig {
	upstream.Target = settings.Target
	upstream.InsecureSkipVerify = settings.InsecureSkipVerify
	upstream.MaxIdleConns = settings.MaxIdleConns
	upstream.MaxIdlePerHost = settings.MaxIdleConnsPerHost
	upstream.MaxConnsPerHost = settings.MaxConnsPerHost
	upstream.IdleTimeout = settings.IdleTimeout
	upstream.TLSHandshake = settings.TLSHandshakeTimeout
	upstream.HealthConcurrency = settings.HealthCheckConcurrency
	return upstream
}
