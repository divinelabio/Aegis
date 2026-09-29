package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	StickySecretConfigurationScope         = "upstream.sticky_secret"
	StickySecretConfigurationSchemaVersion = 1
)

var (
	ErrStickySecretRevisionConflict        = errors.New("sticky-session secret configuration revision conflict")
	ErrStickySecretLegacyMigrationRequired = errors.New("sticky-session legacy clear-text secret must be migrated to an environment reference")
	ErrStickySecretConfigurationValidation = errors.New("sticky-session secret configuration is invalid")
)

// StickySecretRevisionConflictError reports a stale secret-reference update.
type StickySecretRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *StickySecretRevisionConflictError) Error() string {
	if e == nil {
		return ErrStickySecretRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrStickySecretRevisionConflict, e.Expected, e.Actual)
}

func (e *StickySecretRevisionConflictError) Unwrap() error { return ErrStickySecretRevisionConflict }

// StickySecretDocument stores the name of the deployment-provided secret, not
// its value. An empty reference is valid only while no Origin pool enables
// sticky sessions.
type StickySecretDocument struct {
	SecretRef string
	Revision  int64
}

type StickySecretStore interface {
	LoadStickySecret(context.Context) (StickySecretDocument, bool, error)
	SaveStickySecret(ctx context.Context, expectedRevision int64, secretRef, actor, reason string) (StickySecretDocument, error)
}

// StickySecretRuntimeActivator replaces only the immutable cookie signer. It
// must not rebuild Origin pools, transports, or health-check workers.
type StickySecretRuntimeActivator func(secret string) error

var (
	stickySecretControlPlaneManaged bool
	stickySecretControlPlaneMu      sync.Mutex
	stickySecretRuntimeActivator    StickySecretRuntimeActivator
)

func SetStickySecretRuntimeActivator(activator StickySecretRuntimeActivator) {
	stickySecretControlPlaneMu.Lock()
	stickySecretRuntimeActivator = activator
	stickySecretControlPlaneMu.Unlock()
}

// CanonicalStickySecretReference accepts either an empty reference for a
// currently unused sticky-session feature or a strict environment reference.
func CanonicalStickySecretReference(reference string) (string, error) {
	reference = strings.TrimSpace(reference)
	if reference != "" && !validStickySecretEnvironmentReference(reference) {
		return "", fmt.Errorf("%w: sticky-session secret reference must use env:NAME", ErrStickySecretConfigurationValidation)
	}
	return reference, nil
}

// ResolveStickySecretReference is deliberately the only boundary that reads
// the credential value. The reference can be persisted and audited safely;
// the value remains process-local.
func ResolveStickySecretReference(reference string) (string, error) {
	reference, err := CanonicalStickySecretReference(reference)
	if err != nil {
		return "", err
	}
	if reference == "" {
		return "", fmt.Errorf("%w: sticky-session secret reference is required", ErrStickySecretConfigurationValidation)
	}
	name := strings.TrimPrefix(reference, "env:")
	secret, ok := os.LookupEnv(name)
	if !ok || len(strings.TrimSpace(secret)) < 32 {
		return "", fmt.Errorf("%w: sticky-session secret environment variable %q is unavailable or shorter than 32 characters", ErrStickySecretConfigurationValidation, name)
	}
	return secret, nil
}

func validStickySecretEnvironmentReference(reference string) bool {
	if !strings.HasPrefix(reference, "env:") || len(reference) > 260 {
		return false
	}
	name := strings.TrimPrefix(reference, "env:")
	if name == "" || !(name[0] == '_' || name[0] >= 'A' && name[0] <= 'Z') {
		return false
	}
	for _, char := range name {
		if !(char == '_' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

// InitializeStickySecretControlPlane imports a YAML env reference once. A
// legacy clear-text credential stays YAML-only until an operator provisions it
// in the deployment environment and saves an env: reference through the API.
func InitializeStickySecretControlPlane(ctx context.Context, store StickySecretStore, cfg *Config) (StickySecretDocument, bool, error) {
	if store == nil {
		return StickySecretDocument{}, false, errors.New("sticky-session secret control-plane store is unavailable")
	}
	if cfg == nil {
		return StickySecretDocument{}, false, errors.New("sticky-session secret bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadStickySecret(ctx)
	if err != nil {
		return StickySecretDocument{}, false, fmt.Errorf("load sticky-session secret control-plane document: %w", err)
	}
	imported := false
	if !found {
		if stickySessionsEnabled(cfg.Upstream.Groups) && strings.TrimSpace(cfg.Upstream.StickySecret) != "" && strings.TrimSpace(cfg.Upstream.StickySecretRef) == "" {
			return StickySecretDocument{}, false, ErrStickySecretLegacyMigrationRequired
		}
		bootstrap, err := CanonicalStickySecretReference(cfg.Upstream.StickySecretRef)
		if err != nil {
			return StickySecretDocument{}, false, fmt.Errorf("validate sticky-session secret bootstrap configuration: %w", err)
		}
		document, err = store.SaveStickySecret(ctx, 0, bootstrap, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrStickySecretRevisionConflict) {
				document, found, err = store.LoadStickySecret(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("sticky-session secret document disappeared after a revision conflict")
				}
			}
			if err != nil {
				return StickySecretDocument{}, false, fmt.Errorf("import sticky-session secret YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}
	if err := applyStickySecretControlPlaneDocument(document, cfg); err != nil {
		return StickySecretDocument{}, false, err
	}
	return document, imported, nil
}

// SaveStickySecretControlPlane writes a reference before swapping the live
// signer. The reference must resolve successfully, so an invalid deployment
// variable cannot sign out every sticky-session client unexpectedly.
func SaveStickySecretControlPlane(ctx context.Context, store StickySecretStore, secretRef, actor, reason string) (StickySecretDocument, error) {
	if store == nil {
		return StickySecretDocument{}, errors.New("sticky-session secret control-plane store is unavailable")
	}
	secretRef, err := CanonicalStickySecretReference(secretRef)
	if err != nil {
		return StickySecretDocument{}, err
	}
	if secretRef == "" {
		return StickySecretDocument{}, fmt.Errorf("%w: sticky-session secret reference is required", ErrStickySecretConfigurationValidation)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadStickySecret(ctx)
	if err != nil {
		return StickySecretDocument{}, fmt.Errorf("load current sticky-session secret configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		if err := validateCanonicalStickySecretDocument(current); err != nil {
			return StickySecretDocument{}, fmt.Errorf("validate current sticky-session secret configuration: %w", err)
		}
		expectedRevision = current.Revision
	}
	if _, err := ResolveStickySecretReference(secretRef); err != nil {
		return StickySecretDocument{}, err
	}
	document, err := store.SaveStickySecret(ctx, expectedRevision, secretRef, actor, reason)
	if err != nil {
		return StickySecretDocument{}, err
	}
	if err := ApplyStickySecretControlPlaneDocument(document); err != nil {
		return StickySecretDocument{}, fmt.Errorf("activate saved sticky-session secret configuration: %w", err)
	}
	return document, nil
}

func ApplyStickySecretControlPlaneDocument(document StickySecretDocument) error {
	return applyStickySecretControlPlaneDocument(document, nil)
}

func applyStickySecretControlPlaneDocument(document StickySecretDocument, bootstrap *Config) error {
	if err := validateCanonicalStickySecretDocument(document); err != nil {
		return err
	}

	stickySecretControlPlaneMu.Lock()
	defer stickySecretControlPlaneMu.Unlock()
	base := currentUpstreamForRuntimeActivation(bootstrap)
	secret := ""
	if document.SecretRef != "" {
		resolved, err := ResolveStickySecretReference(document.SecretRef)
		if err != nil {
			return err
		}
		secret = resolved
	} else if stickySessionsEnabled(base.Groups) {
		return fmt.Errorf("%w: sticky-session secret reference is required while sticky sessions are enabled", ErrStickySecretConfigurationValidation)
	}
	if secret != "" && stickySecretRuntimeActivator != nil {
		if err := stickySecretRuntimeActivator(secret); err != nil {
			return fmt.Errorf("activate sticky-session signer: %w", err)
		}
	}
	activateStickySecretControlPlaneConfig(bootstrap, document.SecretRef, secret)
	return nil
}

func validateCanonicalStickySecretDocument(document StickySecretDocument) error {
	if document.Revision < 1 {
		return errors.New("sticky-session secret configuration revision is invalid")
	}
	canonical, err := CanonicalStickySecretReference(document.SecretRef)
	if err != nil {
		return err
	}
	if canonical != document.SecretRef {
		return errors.New("sticky-session secret configuration document is not canonical")
	}
	return nil
}

func stickySessionsEnabled(groups []UpstreamGroup) bool {
	for _, group := range groups {
		if group.Sticky.Enabled {
			return true
		}
	}
	return false
}

func activateStickySecretControlPlaneConfig(bootstrap *Config, reference, secret string) {
	configMu.Lock()
	if GlobalConfig != nil {
		activated := *GlobalConfig
		activated.Upstream.StickySecretRef = reference
		activated.Upstream.StickySecret = secret
		GlobalConfig = &activated
	} else if bootstrap != nil {
		activated := *bootstrap
		activated.Upstream.StickySecretRef = reference
		activated.Upstream.StickySecret = secret
		GlobalConfig = &activated
	}
	stickySecretControlPlaneManaged = true
	if bootstrap != nil {
		bootstrap.Upstream.StickySecretRef = reference
		bootstrap.Upstream.StickySecret = secret
	}
	configMu.Unlock()
}

func preserveManagedStickySecret(cfg *Config) {
	if cfg == nil {
		return
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if !stickySecretControlPlaneManaged || GlobalConfig == nil {
		return
	}
	cfg.Upstream.StickySecretRef = GlobalConfig.Upstream.StickySecretRef
	cfg.Upstream.StickySecret = GlobalConfig.Upstream.StickySecret
}

func stickySecretControlPlaneIsManaged() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return stickySecretControlPlaneManaged
}

// stripManagedStickySecretFromSettings removes both the legacy value and its
// reference from YAML once PostgreSQL owns the setting. The current process
// keeps the resolved value in GlobalConfig, and a restart restores it from the
// durable control-plane document.
func stripManagedStickySecretFromSettings(settings map[string]interface{}) {
	if !stickySecretControlPlaneIsManaged() {
		return
	}
	upstream, ok := settings["upstream"].(map[string]interface{})
	if !ok {
		return
	}
	delete(upstream, "sticky_secret")
	delete(upstream, "sticky_secret_ref")
	settings["upstream"] = upstream
}

// ScrubManagedStickySecretFromYAML removes a stale legacy credential as soon
// as a reference has been committed and activated. The document remains the
// restart authority; this only eliminates the obsolete YAML copy.
func ScrubManagedStickySecretFromYAML() error {
	if !stickySecretControlPlaneIsManaged() {
		return nil
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	settings := GetCurrentConfig()
	upstream, ok := settings["upstream"].(map[string]interface{})
	if !ok {
		return nil
	}
	_, hasSecret := upstream["sticky_secret"]
	_, hasReference := upstream["sticky_secret_ref"]
	if !hasSecret && !hasReference {
		return nil
	}
	if err := writeCurrentConfigAtomically(); err != nil {
		return fmt.Errorf("scrub managed sticky-session secret from YAML: %w", err)
	}
	return nil
}

// StickySecretStatus is safe for API responses: it never includes a secret
// value or the deployment's environment-variable naming convention.
type StickySecretStatus struct {
	Configured         bool  `json:"configured"`
	MigrationRequired  bool  `json:"migration_required"`
	YAMLCleanupPending bool  `json:"yaml_cleanup_pending"`
	Revision           int64 `json:"revision"`
}

func StickySecretConfigurationStatus(document StickySecretDocument, found bool) StickySecretStatus {
	status := StickySecretStatus{Revision: document.Revision}
	if found {
		status.Configured = strings.TrimSpace(document.SecretRef) != ""
	}
	configMu.RLock()
	if GlobalConfig != nil {
		status.MigrationRequired = stickySessionsEnabled(GlobalConfig.Upstream.Groups) && strings.TrimSpace(GlobalConfig.Upstream.StickySecret) != "" && strings.TrimSpace(GlobalConfig.Upstream.StickySecretRef) == ""
	}
	configMu.RUnlock()
	status.YAMLCleanupPending = stickySecretYAMLCleanupPending()
	return status
}

func stickySecretYAMLCleanupPending() bool {
	if !stickySecretControlPlaneIsManaged() {
		return false
	}
	upstream, ok := GetCurrentConfig()["upstream"].(map[string]interface{})
	if !ok {
		return false
	}
	_, hasSecret := upstream["sticky_secret"]
	_, hasReference := upstream["sticky_secret_ref"]
	return hasSecret || hasReference
}
