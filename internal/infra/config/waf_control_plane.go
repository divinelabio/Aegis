package config

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/divinelab-io/aegis/internal/sections"
)

const (
	// WAFConfigurationScope is the persistence scope for WAF Core in PostgreSQL.
	WAFConfigurationScope         = "sections.waf_core"
	WAFConfigurationSchemaVersion = 1
)

var ErrWAFRevisionConflict = errors.New("waf configuration revision conflict")

// WAFRevisionConflictError reports a stale document write.
type WAFRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *WAFRevisionConflictError) Error() string {
	if e == nil {
		return ErrWAFRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrWAFRevisionConflict, e.Expected, e.Actual)
}

func (e *WAFRevisionConflictError) Unwrap() error {
	return ErrWAFRevisionConflict
}

// WAFDocument represents the durable WAF section document in PostgreSQL.
type WAFDocument struct {
	Config   sections.SectionConfig `json:"config"`
	Revision int64                  `json:"revision"`
}

// WAFStore defines the PostgreSQL persistence boundary for WAF Core.
type WAFStore interface {
	LoadWAF(context.Context) (WAFDocument, bool, error)
	SaveWAF(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (WAFDocument, error)
}

// WAFRuntimeActivator updates the in-memory WAF engine when a new document is activated.
type WAFRuntimeActivator func(sections.SectionConfig) error

var (
	wafPlaneManaged   bool
	wafPlaneMu        sync.Mutex
	wafActivator      WAFRuntimeActivator
	wafLatestDocument WAFDocument
)

// SetWAFRuntimeActivator registers the runtime update callback for WAF Core.
func SetWAFRuntimeActivator(activator WAFRuntimeActivator) {
	wafPlaneMu.Lock()
	defer wafPlaneMu.Unlock()
	wafActivator = activator
}

// CanonicalWAFSectionConfig normalizes and validates WAF Core configuration.
func CanonicalWAFSectionConfig(input sections.SectionConfig) (sections.SectionConfig, error) {
	settings := input.Settings
	if settings == nil {
		settings = make(map[string]interface{})
	}
	protectionLevel := input.ProtectionLevel
	if protectionLevel < 1 || protectionLevel > 5 {
		protectionLevel = 1
	}
	if mode, _ := settings["mode"].(string); mode == "" {
		if modeUpper, _ := settings["Mode"].(string); modeUpper != "" {
			settings["mode"] = modeUpper
		} else {
			settings["mode"] = "blocking"
		}
	}
	settings["enabled"] = input.Enabled
	settings["protection_level"] = protectionLevel

	return sections.SectionConfig{
		Enabled:         input.Enabled,
		ProtectionLevel: protectionLevel,
		Settings:        settings,
	}, nil
}

// InitializeWAFControlPlane loads the authoritative WAF document from PostgreSQL
// or imports bootstrap YAML on first boot.
func InitializeWAFControlPlane(ctx context.Context, store WAFStore, cfg *Config) (WAFDocument, bool, error) {
	if store == nil {
		return WAFDocument{}, false, errors.New("waf control-plane store is unavailable")
	}
	if cfg == nil {
		return WAFDocument{}, false, errors.New("waf bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadWAF(ctx)
	if err != nil {
		return WAFDocument{}, false, fmt.Errorf("load waf control-plane document: %w", err)
	}

	imported := false
	if !found {
		bootstrapMap := cfg.GetSectionsConfigMap()
		wafSection, exists := bootstrapMap["waf_core"]
		if !exists {
			wafSection = sections.SectionConfig{
				Enabled:         cfg.Sections.WAFCore.Enabled,
				ProtectionLevel: cfg.Sections.WAFCore.ProtectionLevel,
				Settings:        structToMap(cfg.Sections.WAFCore),
			}
		}
		canonical, err := CanonicalWAFSectionConfig(wafSection)
		if err != nil {
			return WAFDocument{}, false, fmt.Errorf("validate waf bootstrap configuration: %w", err)
		}
		document, err = store.SaveWAF(ctx, 0, canonical, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrWAFRevisionConflict) {
				document, found, err = store.LoadWAF(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("waf document disappeared after revision conflict")
				}
			}
			if err != nil {
				return WAFDocument{}, false, fmt.Errorf("import waf YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}

	if err := applyWAFControlPlaneDocument(document, cfg); err != nil {
		return WAFDocument{}, false, err
	}
	return cloneWAFDocument(document), imported, nil
}

// SaveWAFControlPlane commits a validated WAF Core document to PostgreSQL with CAS revision locking.
func SaveWAFControlPlane(ctx context.Context, store WAFStore, next sections.SectionConfig, actor, reason string) (WAFDocument, error) {
	if store == nil {
		return WAFDocument{}, errors.New("waf control-plane store is unavailable")
	}
	canonical, err := CanonicalWAFSectionConfig(next)
	if err != nil {
		return WAFDocument{}, fmt.Errorf("validate waf configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadWAF(ctx)
	if err != nil {
		return WAFDocument{}, fmt.Errorf("load current waf configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		expectedRevision = current.Revision
	}
	document, err := store.SaveWAF(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return WAFDocument{}, err
	}
	if err := ApplyWAFControlPlaneDocument(document); err != nil {
		return WAFDocument{}, fmt.Errorf("activate saved waf configuration: %w", err)
	}
	return cloneWAFDocument(document), nil
}

// ApplyWAFControlPlaneDocument validates and activates a committed WAF document.
func ApplyWAFControlPlaneDocument(document WAFDocument) error {
	return applyWAFControlPlaneDocument(document, nil)
}

func applyWAFControlPlaneDocument(document WAFDocument, bootstrap *Config) error {
	if document.Revision < 1 {
		return errors.New("waf configuration revision is invalid")
	}
	canonical, err := CanonicalWAFSectionConfig(document.Config)
	if err != nil {
		return err
	}

	wafPlaneMu.Lock()
	defer wafPlaneMu.Unlock()

	if wafActivator != nil {
		if err := wafActivator(canonical); err != nil {
			return fmt.Errorf("activate waf runtime: %w", err)
		}
	}

	wafPlaneManaged = true
	wafLatestDocument = cloneWAFDocument(document)
	activateWAFConfig(bootstrap, canonical)
	return nil
}

func activateWAFConfig(bootstrap *Config, canonical sections.SectionConfig) {
	configMu.Lock()
	defer configMu.Unlock()

	apply := func(target *Config) {
		if target == nil {
			return
		}
		target.Sections.WAFCore.Enabled = canonical.Enabled
		target.Sections.WAFCore.ProtectionLevel = canonical.ProtectionLevel
	}

	apply(GlobalConfig)
	apply(bootstrap)
}

func preserveManagedWAF(cfg *Config) {
	wafPlaneMu.Lock()
	managed := wafPlaneManaged
	latest := cloneWAFDocument(wafLatestDocument)
	wafPlaneMu.Unlock()

	if !managed || cfg == nil || latest.Revision < 1 {
		return
	}
	cfg.Sections.WAFCore.Enabled = latest.Config.Enabled
	cfg.Sections.WAFCore.ProtectionLevel = latest.Config.ProtectionLevel
}

func cloneWAFDocument(doc WAFDocument) WAFDocument {
	clonedSettings := make(map[string]interface{}, len(doc.Config.Settings))
	for k, v := range doc.Config.Settings {
		clonedSettings[k] = v
	}
	return WAFDocument{
		Config: sections.SectionConfig{
			Enabled:         doc.Config.Enabled,
			ProtectionLevel: doc.Config.ProtectionLevel,
			Settings:        clonedSettings,
		},
		Revision: doc.Revision,
	}
}
