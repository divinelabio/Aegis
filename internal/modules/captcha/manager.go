package captcha

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// ProviderType enum for supported captcha providers
type ProviderType string

const (
	ProviderNone        ProviderType = "none"
	ProviderRecaptchaV2 ProviderType = "recaptcha_v2"
	ProviderRecaptchaV3 ProviderType = "recaptcha_v3"
	ProviderHCaptcha    ProviderType = "hcaptcha"
	ProviderTurnstile   ProviderType = "turnstile"
	ProviderMTCaptcha   ProviderType = "mtcaptcha"
	ProviderFriendly    ProviderType = "friendlycaptcha"
)

// Provider interface that all captcha backends must implement
type Provider interface {
	// Name returns the display name of the provider
	Name() string
	// Render returns the HTML snippet to embed the captcha widget
	Render() string
	// Verify validates the token submitted by the client
	Verify(token, remoteIP, expectedHostname string) (bool, error)
}

// Config holds the configuration for the Captcha module
type Config struct {
	Enabled        bool         `json:"enabled" mapstructure:"enabled"`
	ProviderName   ProviderType `json:"provider_name" mapstructure:"provider_name"`
	SiteKey        string       `json:"site_key" mapstructure:"site_key"`
	SecretKey      string       `json:"-" mapstructure:"-"`
	SecretKeyRef   string       `json:"secret_key_ref" mapstructure:"secret_key_ref"`
	ScoreThreshold float64      `json:"score_threshold" mapstructure:"score_threshold"`
}

// PublicConfig is the operator-safe CAPTCHA configuration view. It never
// includes a provider credential or its environment variable reference.
type PublicConfig struct {
	Enabled                    bool         `json:"enabled"`
	ProviderName               ProviderType `json:"provider_name"`
	SiteKey                    string       `json:"site_key"`
	ScoreThreshold             float64      `json:"score_threshold"`
	SecretKeyConfigured        bool         `json:"secret_key_configured"`
	SecretKeyMigrationRequired bool         `json:"secret_key_migration_required"`
}

// Manager handles the active captcha provider
type Manager struct {
	config Config
	active Provider
	mu     sync.RWMutex
}

var (
	instance *Manager
	once     sync.Once
)

// GetManager returns the singleton instance
func GetManager() *Manager {
	once.Do(func() {
		instance = &Manager{
			config: Config{ProviderName: ProviderNone},
		}
	})
	return instance
}

// UpdateConfig updates the manager configuration and re-initializes the provider
func (m *Manager) UpdateConfig(cfg Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
	m.loadProvider()
}

// ValidateConfig rejects enabled configurations that cannot safely verify a
// challenge. Disabled CAPTCHA intentionally needs no provider credentials.
func ValidateConfig(cfg Config) error {
	if !cfg.Enabled {
		return nil
	}

	switch cfg.ProviderName {
	case ProviderRecaptchaV2, ProviderRecaptchaV3, ProviderHCaptcha, ProviderMTCaptcha, ProviderTurnstile, ProviderFriendly:
	default:
		return fmt.Errorf("unsupported captcha provider %q", cfg.ProviderName)
	}

	if strings.TrimSpace(cfg.SiteKey) == "" {
		return fmt.Errorf("captcha site key is required when captcha is enabled")
	}
	if strings.TrimSpace(cfg.SecretKey) == "" {
		return fmt.Errorf("captcha secret key is required when captcha is enabled")
	}
	if cfg.ProviderName == ProviderRecaptchaV3 && (cfg.ScoreThreshold < 0 || cfg.ScoreThreshold > 1) {
		return fmt.Errorf("recaptcha v3 score threshold must be between 0 and 1")
	}

	return nil
}

// ResolveConfig resolves a provider credential from its env: reference before
// it enters the runtime-only Config. A non-empty legacy SecretKey is accepted
// temporarily so existing deployments can migrate without an outage.
func ResolveConfig(cfg Config) (Config, error) {
	cfg.SecretKeyRef = strings.TrimSpace(cfg.SecretKeyRef)
	if cfg.Enabled && cfg.SecretKeyRef != "" {
		secret, err := resolveEnvironmentSecret(cfg.SecretKeyRef)
		if err != nil {
			return Config{}, err
		}
		cfg.SecretKey = secret
	}
	if err := ValidateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// PrepareConfigUpdate preserves an already configured secret reference when
// an operator changes non-secret settings. A legacy clear-text credential must
// be replaced by an env: reference before an enabled configuration is saved.
func PrepareConfigUpdate(current, updates Config) (Config, error) {
	updates.SecretKeyRef = strings.TrimSpace(updates.SecretKeyRef)
	if updates.SecretKeyRef == "" && current.SecretKeyRef != "" {
		updates.SecretKeyRef = current.SecretKeyRef
	}
	if updates.Enabled && updates.SecretKeyRef == "" && strings.TrimSpace(current.SecretKey) != "" {
		return Config{}, fmt.Errorf("migrate the existing captcha credential to an environment reference before saving")
	}
	return ResolveConfig(updates)
}

func resolveEnvironmentSecret(reference string) (string, error) {
	if !validEnvironmentSecretReference(reference) {
		return "", fmt.Errorf("captcha secret key reference must use env:NAME")
	}
	name := strings.TrimPrefix(reference, "env:")
	secret, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("captcha secret environment variable %q is not available", name)
	}
	return secret, nil
}

func validEnvironmentSecretReference(reference string) bool {
	reference = strings.TrimSpace(reference)
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

// GetConfig returns the current config
func (m *Manager) GetConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// PublicConfig returns the safe-to-display portion of the active config.
func (m *Manager) PublicConfig() PublicConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return PublicConfig{
		Enabled:                    m.config.Enabled,
		ProviderName:               m.config.ProviderName,
		SiteKey:                    m.config.SiteKey,
		ScoreThreshold:             m.config.ScoreThreshold,
		SecretKeyConfigured:        m.config.SecretKeyRef != "" || strings.TrimSpace(m.config.SecretKey) != "",
		SecretKeyMigrationRequired: m.config.Enabled && m.config.SecretKeyRef == "" && strings.TrimSpace(m.config.SecretKey) != "",
	}
}

// VerifyToken checks a token against the active provider
func (m *Manager) VerifyToken(token, remoteIP, expectedHostname string) bool {
	m.mu.RLock()
	provider := m.active
	enabled := m.config.Enabled
	m.mu.RUnlock()

	if !enabled {
		return true
	}
	if provider == nil {
		return false
	}

	valid, err := provider.Verify(token, remoteIP, expectedHostname)
	if err != nil {
		// Log error?
		return false
	}
	return valid
}

// RenderWidget returns the HTML for the widget
func (m *Manager) RenderWidget() string {
	m.mu.RLock()
	provider := m.active
	enabled := m.config.Enabled
	m.mu.RUnlock()

	if !enabled || provider == nil {
		return "<!-- Captcha Disabled -->"
	}

	return provider.Render()
}

// Internal: Load the provider based on config
func (m *Manager) loadProvider() {
	// This will be populated as we add providers
	switch m.config.ProviderName {
	case ProviderRecaptchaV2:
		m.active = &RecaptchaV2Provider{SiteKey: m.config.SiteKey, SecretKey: m.config.SecretKey}
	case ProviderRecaptchaV3:
		threshold := m.config.ScoreThreshold
		if threshold == 0 {
			threshold = 0.5 // Default threshold
		}
		m.active = &RecaptchaV3Provider{SiteKey: m.config.SiteKey, SecretKey: m.config.SecretKey, ScoreThreshold: threshold}
	case ProviderHCaptcha:
		m.active = &HCaptchaProvider{SiteKey: m.config.SiteKey, SecretKey: m.config.SecretKey}
	case ProviderMTCaptcha:
		m.active = &MTCaptchaProvider{SiteKey: m.config.SiteKey, SecretKey: m.config.SecretKey}
	case ProviderTurnstile:
		m.active = &TurnstileProvider{SiteKey: m.config.SiteKey, SecretKey: m.config.SecretKey}
	case ProviderFriendly:
		m.active = &FriendlyCaptchaProvider{SiteKey: m.config.SiteKey, APIKey: m.config.SecretKey}
	default:
		m.active = nil
	}
}
