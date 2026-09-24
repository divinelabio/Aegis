package config

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/divinelab-io/aegis/internal/sections"
)

const (
	// APISecurityConfigurationScope is the persistence scope for API Security in PostgreSQL.
	APISecurityConfigurationScope         = "sections.api_security"
	APISecurityConfigurationSchemaVersion = 1
)

var ErrAPISecurityRevisionConflict = errors.New("api security configuration revision conflict")

// APISecurityRevisionConflictError reports a stale document write.
type APISecurityRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *APISecurityRevisionConflictError) Error() string {
	if e == nil {
		return ErrAPISecurityRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrAPISecurityRevisionConflict, e.Expected, e.Actual)
}

func (e *APISecurityRevisionConflictError) Unwrap() error {
	return ErrAPISecurityRevisionConflict
}

// APISecurityDocument represents the durable API Security document in PostgreSQL.
type APISecurityDocument struct {
	Config   sections.SectionConfig `json:"config"`
	Revision int64                  `json:"revision"`
}

// APISecurityStore defines the PostgreSQL persistence boundary for API Security.
type APISecurityStore interface {
	LoadAPISecurity(context.Context) (APISecurityDocument, bool, error)
	SaveAPISecurity(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (APISecurityDocument, error)
}

// APISecurityRuntimeActivator updates the in-memory API Security engine when a document is activated.
type APISecurityRuntimeActivator func(sections.SectionConfig) error

var (
	apiSecurityPlaneManaged   bool
	apiSecurityPlaneMu        sync.Mutex
	apiSecurityActivator      APISecurityRuntimeActivator
	apiSecurityLatestDocument APISecurityDocument
)

// SetAPISecurityRuntimeActivator registers the runtime update callback for API Security.
func SetAPISecurityRuntimeActivator(activator APISecurityRuntimeActivator) {
	apiSecurityPlaneMu.Lock()
	defer apiSecurityPlaneMu.Unlock()
	apiSecurityActivator = activator
}

// CanonicalAPISecuritySectionConfig normalizes and validates API Security configuration.
func CanonicalAPISecuritySectionConfig(input sections.SectionConfig) (sections.SectionConfig, error) {
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

// InitializeAPISecurityControlPlane loads the authoritative API Security document from PostgreSQL
// or imports bootstrap YAML on first boot.
func InitializeAPISecurityControlPlane(ctx context.Context, store APISecurityStore, cfg *Config) (APISecurityDocument, bool, error) {
	if store == nil {
		return APISecurityDocument{}, false, errors.New("api security control-plane store is unavailable")
	}
	if cfg == nil {
		return APISecurityDocument{}, false, errors.New("api security bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadAPISecurity(ctx)
	if err != nil {
		return APISecurityDocument{}, false, fmt.Errorf("load api security control-plane document: %w", err)
	}

	imported := false
	if !found {
		bootstrapMap := cfg.GetSectionsConfigMap()
		apiSection, exists := bootstrapMap["api_security"]
		if !exists {
			apiSection = sections.SectionConfig{
				Enabled:         true,
				ProtectionLevel: 3,
				Settings:        cfg.Sections.APISecurity,
			}
		}
		canonical, err := CanonicalAPISecuritySectionConfig(apiSection)
		if err != nil {
			return APISecurityDocument{}, false, fmt.Errorf("validate api security bootstrap configuration: %w", err)
		}
		document, err = store.SaveAPISecurity(ctx, 0, canonical, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrAPISecurityRevisionConflict) {
				document, found, err = store.LoadAPISecurity(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("api security document disappeared after revision conflict")
				}
			}
			if err != nil {
				return APISecurityDocument{}, false, fmt.Errorf("import api security YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}

	if err := applyAPISecurityControlPlaneDocument(document, cfg); err != nil {
		return APISecurityDocument{}, false, err
	}
	return cloneAPISecurityDocument(document), imported, nil
}

// SaveAPISecurityControlPlane commits a validated API Security document to PostgreSQL with CAS revision locking.
func SaveAPISecurityControlPlane(ctx context.Context, store APISecurityStore, next sections.SectionConfig, actor, reason string) (APISecurityDocument, error) {
	if store == nil {
		return APISecurityDocument{}, errors.New("api security control-plane store is unavailable")
	}
	canonical, err := CanonicalAPISecuritySectionConfig(next)
	if err != nil {
		return APISecurityDocument{}, fmt.Errorf("validate api security configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadAPISecurity(ctx)
	if err != nil {
		return APISecurityDocument{}, fmt.Errorf("load current api security configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		expectedRevision = current.Revision
	}
	document, err := store.SaveAPISecurity(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return APISecurityDocument{}, err
	}
	if err := ApplyAPISecurityControlPlaneDocument(document); err != nil {
		return APISecurityDocument{}, fmt.Errorf("activate saved api security configuration: %w", err)
	}
	return cloneAPISecurityDocument(document), nil
}

// ApplyAPISecurityControlPlaneDocument validates and activates a committed API Security document.
func ApplyAPISecurityControlPlaneDocument(document APISecurityDocument) error {
	return applyAPISecurityControlPlaneDocument(document, nil)
}

func applyAPISecurityControlPlaneDocument(document APISecurityDocument, bootstrap *Config) error {
	if document.Revision < 1 {
		return errors.New("api security configuration revision is invalid")
	}
	canonical, err := CanonicalAPISecuritySectionConfig(document.Config)
	if err != nil {
		return err
	}

	apiSecurityPlaneMu.Lock()
	defer apiSecurityPlaneMu.Unlock()

	if apiSecurityActivator != nil {
		if err := apiSecurityActivator(canonical); err != nil {
			return fmt.Errorf("activate api security runtime: %w", err)
		}
	}

	apiSecurityPlaneManaged = true
	apiSecurityLatestDocument = cloneAPISecurityDocument(document)
	activateAPISecurityConfig(bootstrap, canonical)
	return nil
}

func activateAPISecurityConfig(bootstrap *Config, canonical sections.SectionConfig) {
	configMu.Lock()
	defer configMu.Unlock()

	apply := func(target *Config) {
		if target == nil {
			return
		}
		if target.Sections.APISecurity == nil {
			target.Sections.APISecurity = make(map[string]interface{})
		}
		for k, v := range canonical.Settings {
			target.Sections.APISecurity[k] = v
		}
		target.Sections.APISecurity["enabled"] = canonical.Enabled
		target.Sections.APISecurity["protection_level"] = canonical.ProtectionLevel
	}

	apply(GlobalConfig)
	apply(bootstrap)
}

func preserveManagedAPISecurity(cfg *Config) {
	apiSecurityPlaneMu.Lock()
	managed := apiSecurityPlaneManaged
	latest := cloneAPISecurityDocument(apiSecurityLatestDocument)
	apiSecurityPlaneMu.Unlock()

	if !managed || cfg == nil || latest.Revision < 1 {
		return
	}
	if cfg.Sections.APISecurity == nil {
		cfg.Sections.APISecurity = make(map[string]interface{})
	}
	for k, v := range latest.Config.Settings {
		cfg.Sections.APISecurity[k] = v
	}
	cfg.Sections.APISecurity["enabled"] = latest.Config.Enabled
	cfg.Sections.APISecurity["protection_level"] = latest.Config.ProtectionLevel
}

func cloneAPISecurityDocument(doc APISecurityDocument) APISecurityDocument {
	clonedSettings := make(map[string]interface{}, len(doc.Config.Settings))
	for k, v := range doc.Config.Settings {
		clonedSettings[k] = v
	}
	return APISecurityDocument{
		Config: sections.SectionConfig{
			Enabled:         doc.Config.Enabled,
			ProtectionLevel: doc.Config.ProtectionLevel,
			Settings:        clonedSettings,
		},
		Revision: doc.Revision,
	}
}
