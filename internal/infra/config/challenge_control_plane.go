package config

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

const (
	// ChallengeConfigurationScope is the persistence scope for Smart Challenge in PostgreSQL.
	ChallengeConfigurationScope         = "modules.challenge"
	ChallengeConfigurationSchemaVersion = 1
)

var ErrChallengeRevisionConflict = errors.New("challenge configuration revision conflict")

// ChallengeRevisionConflictError reports a stale document write.
type ChallengeRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *ChallengeRevisionConflictError) Error() string {
	if e == nil {
		return ErrChallengeRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrChallengeRevisionConflict, e.Expected, e.Actual)
}

func (e *ChallengeRevisionConflictError) Unwrap() error {
	return ErrChallengeRevisionConflict
}

// ChallengeConfig holds configuration for the Smart Challenge engine.
type ChallengeConfig struct {
	Enabled            bool   `json:"enabled" mapstructure:"enabled"`
	Mode               string `json:"mode" mapstructure:"mode"` // "managed", "captcha", "hybrid"
	Preset             string `json:"preset" mapstructure:"preset"`
	InvisibleEnabled   bool   `json:"invisible_enabled" mapstructure:"invisible_enabled"`
	ManagedEnabled     bool   `json:"managed_enabled" mapstructure:"managed_enabled"`
	InteractiveEnabled bool   `json:"interactive_enabled" mapstructure:"interactive_enabled"`
	InteractiveStyle   string `json:"interactive_style" mapstructure:"interactive_style"`
	CaptchaEnabled     bool   `json:"captcha_enabled" mapstructure:"captcha_enabled"`
	EscalationPolicy   string `json:"escalation_policy" mapstructure:"escalation_policy"`
	CooldownSeconds    int    `json:"cooldown_seconds" mapstructure:"cooldown_seconds"`
	MaxFailures        int    `json:"max_failures" mapstructure:"max_failures"`
	FailureAction      string `json:"failure_action" mapstructure:"failure_action"`
	Theme              string `json:"theme" mapstructure:"theme"` // "dark", "light"
	CustomTitle        string `json:"custom_title" mapstructure:"custom_title"`
	CustomMessage      string `json:"custom_message" mapstructure:"custom_message"`
	CookieTTL          int    `json:"cookie_ttl" mapstructure:"cookie_ttl"`         // Seconds
	PoWDifficulty      int    `json:"pow_difficulty" mapstructure:"pow_difficulty"` // e.g. 4
}

// DefaultChallengeConfig returns production defaults for Smart Challenge.
func DefaultChallengeConfig() ChallengeConfig {
	return ChallengeConfig{
		Enabled:            true,
		Mode:               "managed",
		Preset:             "balanced",
		InvisibleEnabled:   true,
		ManagedEnabled:     true,
		InteractiveEnabled: true,
		InteractiveStyle:   "hold",
		CaptchaEnabled:     false,
		EscalationPolicy:   "progressive",
		CooldownSeconds:    1800,
		MaxFailures:        3,
		FailureAction:      "block",
		Theme:              "dark",
		CustomTitle:        "Checking your browser...",
		CustomMessage:      "Please wait a moment while we verify your request.",
		CookieTTL:          3600,
		PoWDifficulty:      0,
	}
}

// ChallengeDocument represents the durable document in PostgreSQL.
type ChallengeDocument struct {
	Config   ChallengeConfig `json:"config"`
	Revision int64           `json:"revision"`
}

// ChallengeStore defines the PostgreSQL persistence boundary for Smart Challenge.
type ChallengeStore interface {
	LoadChallenge(context.Context) (ChallengeDocument, bool, error)
	SaveChallenge(ctx context.Context, expectedRevision int64, next ChallengeConfig, actor, reason string) (ChallengeDocument, error)
}

// ChallengeRuntimeActivator updates the in-memory smart challenge engine when a document is activated.
type ChallengeRuntimeActivator func(ChallengeConfig) error

var (
	challengePlaneManaged   bool
	challengePlaneMu        sync.Mutex
	challengeActivator      ChallengeRuntimeActivator
	challengeLatestDocument ChallengeDocument
)

// SetChallengeRuntimeActivator registers the runtime update callback for Smart Challenge.
func SetChallengeRuntimeActivator(activator ChallengeRuntimeActivator) {
	challengePlaneMu.Lock()
	defer challengePlaneMu.Unlock()
	challengeActivator = activator
}

// CanonicalChallengeConfig normalizes and validates Smart Challenge configuration.
func CanonicalChallengeConfig(input ChallengeConfig) (ChallengeConfig, error) {
	if input.Mode == "" {
		input.Mode = "managed"
	}
	if input.Preset == "" {
		input.Preset = "balanced"
	}
	if input.InteractiveStyle == "" {
		input.InteractiveStyle = "hold"
	}
	if input.EscalationPolicy == "" {
		input.EscalationPolicy = "progressive"
	}
	if input.FailureAction == "" {
		input.FailureAction = "block"
	}
	if input.Theme == "" {
		input.Theme = "dark"
	}
	if input.CooldownSeconds <= 0 {
		input.CooldownSeconds = 1800
	}
	if input.MaxFailures <= 0 {
		input.MaxFailures = 3
	}
	if input.CookieTTL <= 0 {
		input.CookieTTL = 3600
	}
	return input, nil
}

// InitializeChallengeControlPlane loads the authoritative Smart Challenge document from PostgreSQL
// or imports default configuration on first boot.
func InitializeChallengeControlPlane(ctx context.Context, store ChallengeStore, cfg *Config) (ChallengeDocument, bool, error) {
	if store == nil {
		return ChallengeDocument{}, false, errors.New("challenge control-plane store is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadChallenge(ctx)
	if err != nil {
		return ChallengeDocument{}, false, fmt.Errorf("load challenge control-plane document: %w", err)
	}

	imported := false
	if !found {
		initialConfig := DefaultChallengeConfig()
		canonical, err := CanonicalChallengeConfig(initialConfig)
		if err != nil {
			return ChallengeDocument{}, false, fmt.Errorf("validate challenge default configuration: %w", err)
		}
		document, err = store.SaveChallenge(ctx, 0, canonical, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrChallengeRevisionConflict) {
				document, found, err = store.LoadChallenge(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("challenge document disappeared after revision conflict")
				}
			}
			if err != nil {
				return ChallengeDocument{}, false, fmt.Errorf("import challenge configuration: %w", err)
			}
		} else {
			imported = true
		}
	}

	if err := applyChallengeControlPlaneDocument(document, cfg); err != nil {
		return ChallengeDocument{}, false, err
	}
	return cloneChallengeDocument(document), imported, nil
}

// SaveChallengeControlPlane commits a validated Smart Challenge document to PostgreSQL with CAS revision locking.
func SaveChallengeControlPlane(ctx context.Context, store ChallengeStore, next ChallengeConfig, actor, reason string) (ChallengeDocument, error) {
	if store == nil {
		return ChallengeDocument{}, errors.New("challenge control-plane store is unavailable")
	}
	canonical, err := CanonicalChallengeConfig(next)
	if err != nil {
		return ChallengeDocument{}, fmt.Errorf("validate challenge configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadChallenge(ctx)
	if err != nil {
		return ChallengeDocument{}, fmt.Errorf("load current challenge configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		expectedRevision = current.Revision
	}
	document, err := store.SaveChallenge(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return ChallengeDocument{}, err
	}
	if err := ApplyChallengeControlPlaneDocument(document); err != nil {
		return ChallengeDocument{}, fmt.Errorf("activate saved challenge configuration: %w", err)
	}
	return cloneChallengeDocument(document), nil
}

// ApplyChallengeControlPlaneDocument validates and activates a committed Smart Challenge document.
func ApplyChallengeControlPlaneDocument(document ChallengeDocument) error {
	return applyChallengeControlPlaneDocument(document, nil)
}

func applyChallengeControlPlaneDocument(document ChallengeDocument, bootstrap *Config) error {
	if document.Revision < 1 {
		return errors.New("challenge configuration revision is invalid")
	}
	canonical, err := CanonicalChallengeConfig(document.Config)
	if err != nil {
		return err
	}

	challengePlaneMu.Lock()
	defer challengePlaneMu.Unlock()

	if challengeActivator != nil {
		if err := challengeActivator(canonical); err != nil {
			return fmt.Errorf("activate challenge runtime: %w", err)
		}
	}

	challengePlaneManaged = true
	challengeLatestDocument = cloneChallengeDocument(document)
	return nil
}

func preserveManagedChallenge(cfg *Config) {
	challengePlaneMu.Lock()
	managed := challengePlaneManaged
	latest := cloneChallengeDocument(challengeLatestDocument)
	challengePlaneMu.Unlock()

	if !managed || cfg == nil || latest.Revision < 1 {
		return
	}
}

func cloneChallengeDocument(doc ChallengeDocument) ChallengeDocument {
	return ChallengeDocument{
		Config:   doc.Config,
		Revision: doc.Revision,
	}
}
