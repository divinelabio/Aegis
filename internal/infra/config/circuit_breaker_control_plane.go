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
	CircuitBreakerConfigurationScope         = "upstream.circuit_breaker"
	CircuitBreakerConfigurationSchemaVersion = 1
)

var ErrCircuitBreakerRevisionConflict = errors.New("circuit-breaker configuration revision conflict")

// CircuitBreakerRevisionConflictError reports a stale complete-policy update.
type CircuitBreakerRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *CircuitBreakerRevisionConflictError) Error() string {
	if e == nil {
		return ErrCircuitBreakerRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrCircuitBreakerRevisionConflict, e.Expected, e.Actual)
}

func (e *CircuitBreakerRevisionConflictError) Unwrap() error {
	return ErrCircuitBreakerRevisionConflict
}

// CircuitBreakerDocument owns only the global upstream circuit-breaker policy.
// Routing, Origin pools, connection tuning, and sticky credentials retain
// independent migration boundaries.
type CircuitBreakerDocument struct {
	Config   CircuitBreakerConfig
	Revision int64
}

type CircuitBreakerStore interface {
	LoadCircuitBreaker(context.Context) (CircuitBreakerDocument, bool, error)
	SaveCircuitBreaker(ctx context.Context, expectedRevision int64, policy CircuitBreakerConfig, actor, reason string) (CircuitBreakerDocument, error)
}

// CircuitBreakerActivator applies a committed policy to the request path.
type CircuitBreakerActivator func(CircuitBreakerConfig) error

var (
	circuitBreakerControlPlaneManaged bool
	circuitBreakerControlPlaneMu      sync.Mutex
	circuitBreakerActivator           CircuitBreakerActivator
)

func SetCircuitBreakerActivator(activator CircuitBreakerActivator) {
	circuitBreakerControlPlaneMu.Lock()
	circuitBreakerActivator = activator
	circuitBreakerControlPlaneMu.Unlock()
}

// CanonicalCircuitBreakerConfig applies stable defaults and validates the
// policy independently of connection-pool and route settings.
func CanonicalCircuitBreakerConfig(policy CircuitBreakerConfig) (CircuitBreakerConfig, error) {
	if policy.Threshold <= 0 {
		policy.Threshold = 5
	}
	if policy.Threshold > 1000 {
		return CircuitBreakerConfig{}, errors.New("upstream.circuit_breaker.threshold must be between 1 and 1000")
	}
	policy.Timeout = strings.TrimSpace(policy.Timeout)
	if policy.Timeout == "" {
		policy.Timeout = "30s"
	}
	if duration, err := time.ParseDuration(policy.Timeout); err != nil || duration < time.Second || duration > time.Hour {
		return CircuitBreakerConfig{}, errors.New("upstream.circuit_breaker.timeout must be between 1s and 1h")
	}
	return policy, nil
}

// InitializeCircuitBreakerControlPlane imports YAML once. PostgreSQL then
// remains authoritative across generic saves and SIGHUP reloads.
func InitializeCircuitBreakerControlPlane(ctx context.Context, store CircuitBreakerStore, cfg *Config) (CircuitBreakerDocument, bool, error) {
	if store == nil {
		return CircuitBreakerDocument{}, false, errors.New("circuit-breaker control-plane store is unavailable")
	}
	if cfg == nil {
		return CircuitBreakerDocument{}, false, errors.New("circuit-breaker bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadCircuitBreaker(ctx)
	if err != nil {
		return CircuitBreakerDocument{}, false, fmt.Errorf("load circuit-breaker control-plane document: %w", err)
	}
	imported := false
	if !found {
		bootstrap, err := CanonicalCircuitBreakerConfig(cfg.Upstream.CircuitBreaker)
		if err != nil {
			return CircuitBreakerDocument{}, false, fmt.Errorf("validate circuit-breaker bootstrap configuration: %w", err)
		}
		document, err = store.SaveCircuitBreaker(ctx, 0, bootstrap, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrCircuitBreakerRevisionConflict) {
				document, found, err = store.LoadCircuitBreaker(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("circuit-breaker document disappeared after a revision conflict")
				}
			}
			if err != nil {
				return CircuitBreakerDocument{}, false, fmt.Errorf("import circuit-breaker YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}
	if err := applyCircuitBreakerControlPlaneDocument(document, cfg); err != nil {
		return CircuitBreakerDocument{}, false, err
	}
	return document, imported, nil
}

// SaveCircuitBreakerControlPlane commits the complete policy before changing
// the request-path breaker state.
func SaveCircuitBreakerControlPlane(ctx context.Context, store CircuitBreakerStore, policy CircuitBreakerConfig, actor, reason string) (CircuitBreakerDocument, error) {
	if store == nil {
		return CircuitBreakerDocument{}, errors.New("circuit-breaker control-plane store is unavailable")
	}
	canonical, err := CanonicalCircuitBreakerConfig(policy)
	if err != nil {
		return CircuitBreakerDocument{}, fmt.Errorf("validate circuit-breaker configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadCircuitBreaker(ctx)
	if err != nil {
		return CircuitBreakerDocument{}, fmt.Errorf("load current circuit-breaker configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		if err := validateCanonicalCircuitBreakerDocument(current); err != nil {
			return CircuitBreakerDocument{}, fmt.Errorf("validate current circuit-breaker configuration: %w", err)
		}
		expectedRevision = current.Revision
	}
	document, err := store.SaveCircuitBreaker(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return CircuitBreakerDocument{}, err
	}
	if err := ApplyCircuitBreakerControlPlaneDocument(document); err != nil {
		return CircuitBreakerDocument{}, fmt.Errorf("activate saved circuit-breaker configuration: %w", err)
	}
	return document, nil
}

func ApplyCircuitBreakerControlPlaneDocument(document CircuitBreakerDocument) error {
	return applyCircuitBreakerControlPlaneDocument(document, nil)
}

func applyCircuitBreakerControlPlaneDocument(document CircuitBreakerDocument, bootstrap *Config) error {
	if err := validateCanonicalCircuitBreakerDocument(document); err != nil {
		return err
	}

	circuitBreakerControlPlaneMu.Lock()
	defer circuitBreakerControlPlaneMu.Unlock()
	if circuitBreakerActivator != nil {
		if err := circuitBreakerActivator(document.Config); err != nil {
			return fmt.Errorf("activate circuit-breaker policy: %w", err)
		}
	}
	activateCircuitBreakerControlPlaneConfig(bootstrap, document.Config)
	return nil
}

func validateCanonicalCircuitBreakerDocument(document CircuitBreakerDocument) error {
	if document.Revision < 1 {
		return errors.New("circuit-breaker configuration revision is invalid")
	}
	canonical, err := CanonicalCircuitBreakerConfig(document.Config)
	if err != nil {
		return err
	}
	if canonical != document.Config {
		return errors.New("circuit-breaker configuration document is not canonical")
	}
	return nil
}

func activateCircuitBreakerControlPlaneConfig(bootstrap *Config, policy CircuitBreakerConfig) {
	configMu.Lock()
	if GlobalConfig != nil {
		activated := *GlobalConfig
		activated.Upstream.CircuitBreaker = policy
		GlobalConfig = &activated
	} else if bootstrap != nil {
		activated := *bootstrap
		activated.Upstream.CircuitBreaker = policy
		GlobalConfig = &activated
	}
	circuitBreakerControlPlaneManaged = true
	if bootstrap != nil {
		bootstrap.Upstream.CircuitBreaker = policy
	}
	configMu.Unlock()
}

func preserveManagedCircuitBreaker(cfg *Config) {
	if cfg == nil {
		return
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if !circuitBreakerControlPlaneManaged || GlobalConfig == nil {
		return
	}
	cfg.Upstream.CircuitBreaker = GlobalConfig.Upstream.CircuitBreaker
}
