package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	CaptchaConfigurationScope         = "modules.captcha"
	CaptchaConfigurationSchemaVersion = 1
)

var (
	ErrCaptchaRevisionConflict              = errors.New("CAPTCHA configuration revision conflict")
	ErrCaptchaLegacySecretMigrationRequired = errors.New("CAPTCHA legacy clear-text credential must be migrated to an environment reference")
)

// CaptchaRevisionConflictError reports a concurrent durable update.
type CaptchaRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *CaptchaRevisionConflictError) Error() string {
	if e == nil {
		return ErrCaptchaRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrCaptchaRevisionConflict, e.Expected, e.Actual)
}

func (e *CaptchaRevisionConflictError) Unwrap() error { return ErrCaptchaRevisionConflict }

// CaptchaDocument is the durable, secret-free form of the CAPTCHA module.
// SecretKey is always empty; only SecretKeyRef is persisted.
type CaptchaDocument struct {
	Config   CaptchaConfig
	Revision int64
}

// CaptchaStore keeps configuration-domain validation independent from the
// PostgreSQL document-store implementation.
type CaptchaStore interface {
	LoadCaptcha(context.Context) (CaptchaDocument, bool, error)
	SaveCaptcha(ctx context.Context, expectedRevision int64, next CaptchaConfig, actor, reason string) (CaptchaDocument, error)
}

// CaptchaRuntimeActivator resolves the environment secret and updates the
// running module before its global configuration snapshot is replaced.
type CaptchaRuntimeActivator func(CaptchaConfig) error

var (
	captchaControlPlaneManaged bool
	captchaControlPlaneMu      sync.Mutex
	captchaRuntimeActivator    CaptchaRuntimeActivator
)

// SetCaptchaRuntimeActivator registers the process-local runtime activation
// boundary. A nil activator is useful in config-only tests; production
// registers the CAPTCHA manager before loading PostgreSQL documents.
func SetCaptchaRuntimeActivator(activator CaptchaRuntimeActivator) {
	captchaControlPlaneMu.Lock()
	captchaRuntimeActivator = activator
	captchaControlPlaneMu.Unlock()
}

// CanonicalCaptchaConfig validates a secret-free persistent CAPTCHA document.
// It intentionally clears SecretKey so no write path can copy a provider
// credential from YAML or runtime memory into PostgreSQL.
func CanonicalCaptchaConfig(next CaptchaConfig) (CaptchaConfig, error) {
	next.ProviderName = strings.TrimSpace(next.ProviderName)
	next.SiteKey = strings.TrimSpace(next.SiteKey)
	next.SecretKeyRef = strings.TrimSpace(next.SecretKeyRef)
	next.SecretKey = ""

	if next.SecretKeyRef != "" && !validCaptchaEnvironmentSecretReference(next.SecretKeyRef) {
		return CaptchaConfig{}, errors.New("captcha secret key reference must use env:NAME")
	}
	if !next.Enabled {
		return next, nil
	}
	if !supportedCaptchaProvider(next.ProviderName) {
		return CaptchaConfig{}, fmt.Errorf("unsupported captcha provider %q", next.ProviderName)
	}
	if next.SiteKey == "" {
		return CaptchaConfig{}, errors.New("captcha site key is required when captcha is enabled")
	}
	if next.SecretKeyRef == "" {
		return CaptchaConfig{}, errors.New("captcha secret key reference is required when captcha is enabled")
	}
	if next.ProviderName == "recaptcha_v3" && (next.ScoreThreshold < 0 || next.ScoreThreshold > 1) {
		return CaptchaConfig{}, errors.New("recaptcha v3 score threshold must be between 0 and 1")
	}
	return next, nil
}

func supportedCaptchaProvider(provider string) bool {
	switch provider {
	case "recaptcha_v2", "recaptcha_v3", "hcaptcha", "turnstile", "mtcaptcha", "friendlycaptcha":
		return true
	default:
		return false
	}
}

func validCaptchaEnvironmentSecretReference(reference string) bool {
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

// InitializeCaptchaControlPlane imports a secret-free YAML value once. An
// enabled legacy clear-text credential remains YAML-only until its operator
// replaces it with an env: reference, preventing secret exfiltration.
func InitializeCaptchaControlPlane(ctx context.Context, store CaptchaStore, cfg *Config) (CaptchaDocument, bool, error) {
	if store == nil {
		return CaptchaDocument{}, false, errors.New("CAPTCHA control-plane store is unavailable")
	}
	if cfg == nil {
		return CaptchaDocument{}, false, errors.New("CAPTCHA bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadCaptcha(ctx)
	if err != nil {
		return CaptchaDocument{}, false, fmt.Errorf("load CAPTCHA control-plane document: %w", err)
	}
	imported := false
	if !found {
		if cfg.Modules.Captcha.Enabled && strings.TrimSpace(cfg.Modules.Captcha.SecretKey) != "" && strings.TrimSpace(cfg.Modules.Captcha.SecretKeyRef) == "" {
			return CaptchaDocument{}, false, ErrCaptchaLegacySecretMigrationRequired
		}
		bootstrap, err := CanonicalCaptchaConfig(cfg.Modules.Captcha)
		if err != nil {
			return CaptchaDocument{}, false, fmt.Errorf("validate CAPTCHA bootstrap configuration: %w", err)
		}
		document, err = store.SaveCaptcha(ctx, 0, bootstrap, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrCaptchaRevisionConflict) {
				document, found, err = store.LoadCaptcha(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("CAPTCHA document disappeared after a revision conflict")
				}
			}
			if err != nil {
				return CaptchaDocument{}, false, fmt.Errorf("import CAPTCHA YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}
	if err := ApplyCaptchaControlPlaneDocument(document); err != nil {
		return CaptchaDocument{}, false, fmt.Errorf("activate stored CAPTCHA configuration: %w", err)
	}
	if cfg != nil {
		cfg.Modules.Captcha = document.Config
	}
	return document, imported, nil
}

// SaveCaptchaControlPlane commits a complete, secret-free document before
// changing the runtime. Failed writes or failed secret resolution retain the
// previous CAPTCHA configuration.
func SaveCaptchaControlPlane(ctx context.Context, store CaptchaStore, next CaptchaConfig, actor, reason string) (CaptchaDocument, error) {
	if store == nil {
		return CaptchaDocument{}, errors.New("CAPTCHA control-plane store is unavailable")
	}
	next, err := CanonicalCaptchaConfig(next)
	if err != nil {
		return CaptchaDocument{}, fmt.Errorf("validate CAPTCHA configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadCaptcha(ctx)
	if err != nil {
		return CaptchaDocument{}, fmt.Errorf("load current CAPTCHA configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		if err := validateCaptchaDocument(current); err != nil {
			return CaptchaDocument{}, fmt.Errorf("validate current CAPTCHA configuration: %w", err)
		}
		expectedRevision = current.Revision
	}
	document, err := store.SaveCaptcha(ctx, expectedRevision, next, actor, reason)
	if err != nil {
		return CaptchaDocument{}, err
	}
	if err := ApplyCaptchaControlPlaneDocument(document); err != nil {
		return CaptchaDocument{}, fmt.Errorf("activate saved CAPTCHA configuration: %w", err)
	}
	return document, nil
}

// ApplyCaptchaControlPlaneDocument resolves and activates a committed
// document. Runtime resolution occurs before GlobalConfig changes.
func ApplyCaptchaControlPlaneDocument(document CaptchaDocument) error {
	if err := validateCaptchaDocument(document); err != nil {
		return err
	}
	captchaControlPlaneMu.Lock()
	defer captchaControlPlaneMu.Unlock()
	if captchaRuntimeActivator != nil {
		if err := captchaRuntimeActivator(document.Config); err != nil {
			return fmt.Errorf("activate CAPTCHA runtime: %w", err)
		}
	}
	activateCaptchaControlPlaneConfig(document.Config)
	return nil
}

func validateCaptchaDocument(document CaptchaDocument) error {
	if document.Revision < 1 {
		return errors.New("CAPTCHA configuration revision is invalid")
	}
	canonical, err := CanonicalCaptchaConfig(document.Config)
	if err != nil {
		return err
	}
	if canonical != document.Config {
		return errors.New("CAPTCHA configuration is not canonical or contains a secret")
	}
	return nil
}

func activateCaptchaControlPlaneConfig(next CaptchaConfig) {
	configMu.Lock()
	if GlobalConfig != nil {
		activated := *GlobalConfig
		activated.Modules.Captcha = next
		GlobalConfig = &activated
	}
	captchaControlPlaneManaged = true
	configMu.Unlock()
}

func preserveManagedCaptcha(cfg *Config) {
	if cfg == nil {
		return
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if !captchaControlPlaneManaged || GlobalConfig == nil {
		return
	}
	cfg.Modules.Captcha = GlobalConfig.Modules.Captcha
}
