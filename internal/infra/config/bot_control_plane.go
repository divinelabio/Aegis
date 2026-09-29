package config

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/divinelab-io/aegis/internal/sections"
)

const (
	// BotConfigurationScope is the persistence scope for Bot Protection in PostgreSQL.
	BotConfigurationScope         = "sections.bot_protection"
	BotConfigurationSchemaVersion = 1
)

var ErrBotRevisionConflict = errors.New("bot protection configuration revision conflict")

// BotRevisionConflictError reports a stale document write.
type BotRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *BotRevisionConflictError) Error() string {
	if e == nil {
		return ErrBotRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrBotRevisionConflict, e.Expected, e.Actual)
}

func (e *BotRevisionConflictError) Unwrap() error {
	return ErrBotRevisionConflict
}

// BotDocument represents the durable Bot Protection document in PostgreSQL.
type BotDocument struct {
	Config   sections.SectionConfig `json:"config"`
	Revision int64                  `json:"revision"`
}

// BotStore defines the PostgreSQL persistence boundary for Bot Protection.
type BotStore interface {
	LoadBot(context.Context) (BotDocument, bool, error)
	SaveBot(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (BotDocument, error)
}

// BotRuntimeActivator updates the in-memory Bot Protection engine when a document is activated.
type BotRuntimeActivator func(sections.SectionConfig) error

var (
	botPlaneManaged   bool
	botPlaneMu        sync.Mutex
	botActivator      BotRuntimeActivator
	botLatestDocument BotDocument
)

// SetBotRuntimeActivator registers the runtime update callback for Bot Protection.
func SetBotRuntimeActivator(activator BotRuntimeActivator) {
	botPlaneMu.Lock()
	defer botPlaneMu.Unlock()
	botActivator = activator
}

// CanonicalBotSectionConfig normalizes and validates Bot Protection configuration.
func CanonicalBotSectionConfig(input sections.SectionConfig) (sections.SectionConfig, error) {
	settings := input.Settings
	if settings == nil {
		settings = make(map[string]interface{})
	}
	protectionLevel := input.ProtectionLevel
	if protectionLevel < 1 || protectionLevel > 5 {
		protectionLevel = 3
	}
	settings["enabled"] = input.Enabled
	settings["protection_level"] = protectionLevel

	return sections.SectionConfig{
		Enabled:         input.Enabled,
		ProtectionLevel: protectionLevel,
		Settings:        settings,
	}, nil
}

// InitializeBotControlPlane loads the authoritative Bot Protection document from PostgreSQL
// or imports bootstrap YAML on first boot.
func InitializeBotControlPlane(ctx context.Context, store BotStore, cfg *Config) (BotDocument, bool, error) {
	if store == nil {
		return BotDocument{}, false, errors.New("bot control-plane store is unavailable")
	}
	if cfg == nil {
		return BotDocument{}, false, errors.New("bot bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadBot(ctx)
	if err != nil {
		return BotDocument{}, false, fmt.Errorf("load bot control-plane document: %w", err)
	}

	imported := false
	if !found {
		bootstrapMap := cfg.GetSectionsConfigMap()
		botSection, exists := bootstrapMap["bot_protection"]
		if !exists {
			botSection = sections.SectionConfig{
				Enabled:         true,
				ProtectionLevel: 3,
				Settings:        cfg.Sections.Bot,
			}
		}
		canonical, err := CanonicalBotSectionConfig(botSection)
		if err != nil {
			return BotDocument{}, false, fmt.Errorf("validate bot bootstrap configuration: %w", err)
		}
		document, err = store.SaveBot(ctx, 0, canonical, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrBotRevisionConflict) {
				document, found, err = store.LoadBot(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("bot document disappeared after revision conflict")
				}
			}
			if err != nil {
				return BotDocument{}, false, fmt.Errorf("import bot YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}

	if err := applyBotControlPlaneDocument(document, cfg); err != nil {
		return BotDocument{}, false, err
	}
	return cloneBotDocument(document), imported, nil
}

// SaveBotControlPlane commits a validated Bot Protection document to PostgreSQL with CAS revision locking.
func SaveBotControlPlane(ctx context.Context, store BotStore, next sections.SectionConfig, actor, reason string) (BotDocument, error) {
	if store == nil {
		return BotDocument{}, errors.New("bot control-plane store is unavailable")
	}
	canonical, err := CanonicalBotSectionConfig(next)
	if err != nil {
		return BotDocument{}, fmt.Errorf("validate bot configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadBot(ctx)
	if err != nil {
		return BotDocument{}, fmt.Errorf("load current bot configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		expectedRevision = current.Revision
	}
	document, err := store.SaveBot(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return BotDocument{}, err
	}
	if err := ApplyBotControlPlaneDocument(document); err != nil {
		return BotDocument{}, fmt.Errorf("activate saved bot configuration: %w", err)
	}
	return cloneBotDocument(document), nil
}

// ApplyBotControlPlaneDocument validates and activates a committed Bot Protection document.
func ApplyBotControlPlaneDocument(document BotDocument) error {
	return applyBotControlPlaneDocument(document, nil)
}

func applyBotControlPlaneDocument(document BotDocument, bootstrap *Config) error {
	if document.Revision < 1 {
		return errors.New("bot configuration revision is invalid")
	}
	canonical, err := CanonicalBotSectionConfig(document.Config)
	if err != nil {
		return err
	}

	botPlaneMu.Lock()
	defer botPlaneMu.Unlock()

	if botActivator != nil {
		if err := botActivator(canonical); err != nil {
			return fmt.Errorf("activate bot runtime: %w", err)
		}
	}

	botPlaneManaged = true
	botLatestDocument = cloneBotDocument(document)
	activateBotConfig(bootstrap, canonical)
	return nil
}

func activateBotConfig(bootstrap *Config, canonical sections.SectionConfig) {
	configMu.Lock()
	defer configMu.Unlock()

	apply := func(target *Config) {
		if target == nil {
			return
		}
		if target.Sections.Bot == nil {
			target.Sections.Bot = make(map[string]interface{})
		}
		for k, v := range canonical.Settings {
			target.Sections.Bot[k] = v
		}
		target.Sections.Bot["enabled"] = canonical.Enabled
		target.Sections.Bot["protection_level"] = canonical.ProtectionLevel
	}

	apply(GlobalConfig)
	apply(bootstrap)
}

func preserveManagedBot(cfg *Config) {
	botPlaneMu.Lock()
	managed := botPlaneManaged
	latest := cloneBotDocument(botLatestDocument)
	botPlaneMu.Unlock()

	if !managed || cfg == nil || latest.Revision < 1 {
		return
	}
	if cfg.Sections.Bot == nil {
		cfg.Sections.Bot = make(map[string]interface{})
	}
	for k, v := range latest.Config.Settings {
		cfg.Sections.Bot[k] = v
	}
	cfg.Sections.Bot["enabled"] = latest.Config.Enabled
	cfg.Sections.Bot["protection_level"] = latest.Config.ProtectionLevel
}

func cloneBotDocument(doc BotDocument) BotDocument {
	clonedSettings := make(map[string]interface{}, len(doc.Config.Settings))
	for k, v := range doc.Config.Settings {
		clonedSettings[k] = v
	}
	return BotDocument{
		Config: sections.SectionConfig{
			Enabled:         doc.Config.Enabled,
			ProtectionLevel: doc.Config.ProtectionLevel,
			Settings:        clonedSettings,
		},
		Revision: doc.Revision,
	}
}
