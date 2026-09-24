package config

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/divinelab-io/aegis/internal/sections"
)

const (
	// AccessControlConfigurationScope is the persistence scope for Access Control in PostgreSQL.
	AccessControlConfigurationScope         = "sections.access_control"
	AccessControlConfigurationSchemaVersion = 1
)

var ErrAccessControlRevisionConflict = errors.New("access control configuration revision conflict")

// AccessControlRevisionConflictError reports a stale document write.
type AccessControlRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *AccessControlRevisionConflictError) Error() string {
	if e == nil {
		return ErrAccessControlRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrAccessControlRevisionConflict, e.Expected, e.Actual)
}

func (e *AccessControlRevisionConflictError) Unwrap() error {
	return ErrAccessControlRevisionConflict
}

// AccessControlDocument represents the durable Access Control document in PostgreSQL.
type AccessControlDocument struct {
	Config   sections.SectionConfig `json:"config"`
	Revision int64                  `json:"revision"`
}

// AccessControlStore defines the PostgreSQL persistence boundary for Access Control.
type AccessControlStore interface {
	LoadAccessControl(context.Context) (AccessControlDocument, bool, error)
	SaveAccessControl(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (AccessControlDocument, error)
}

// AccessControlRuntimeActivator updates the in-memory Access Control engine when a document is activated.
type AccessControlRuntimeActivator func(sections.SectionConfig) error

var (
	accessControlPlaneManaged   bool
	accessControlPlaneMu        sync.Mutex
	accessControlActivator      AccessControlRuntimeActivator
	accessControlLatestDocument AccessControlDocument
)

// SetAccessControlRuntimeActivator registers the runtime update callback for Access Control.
func SetAccessControlRuntimeActivator(activator AccessControlRuntimeActivator) {
	accessControlPlaneMu.Lock()
	defer accessControlPlaneMu.Unlock()
	accessControlActivator = activator
}

// CanonicalAccessControlSectionConfig normalizes and validates Access Control configuration.
func CanonicalAccessControlSectionConfig(input sections.SectionConfig) (sections.SectionConfig, error) {
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

// InitializeAccessControlPlane loads the authoritative Access Control document from PostgreSQL
// or imports bootstrap YAML on first boot.
func InitializeAccessControlPlane(ctx context.Context, store AccessControlStore, cfg *Config) (AccessControlDocument, bool, error) {
	if store == nil {
		return AccessControlDocument{}, false, errors.New("access control control-plane store is unavailable")
	}
	if cfg == nil {
		return AccessControlDocument{}, false, errors.New("access control bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadAccessControl(ctx)
	if err != nil {
		return AccessControlDocument{}, false, fmt.Errorf("load access control control-plane document: %w", err)
	}

	imported := false
	if !found {
		bootstrapMap := cfg.GetSectionsConfigMap()
		accessSection, exists := bootstrapMap["access_control"]
		if !exists {
			accessSection = sections.SectionConfig{
				Enabled:         true,
				ProtectionLevel: 3,
				Settings:        cfg.Sections.AccessControl,
			}
		}
		canonical, err := CanonicalAccessControlSectionConfig(accessSection)
		if err != nil {
			return AccessControlDocument{}, false, fmt.Errorf("validate access control bootstrap configuration: %w", err)
		}
		document, err = store.SaveAccessControl(ctx, 0, canonical, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrAccessControlRevisionConflict) {
				document, found, err = store.LoadAccessControl(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("access control document disappeared after revision conflict")
				}
			}
			if err != nil {
				return AccessControlDocument{}, false, fmt.Errorf("import access control YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}

	if err := applyAccessControlPlaneDocument(document, cfg); err != nil {
		return AccessControlDocument{}, false, err
	}
	return cloneAccessControlDocument(document), imported, nil
}

// SaveAccessControlControlPlane commits a validated Access Control document to PostgreSQL with CAS revision locking.
func SaveAccessControlControlPlane(ctx context.Context, store AccessControlStore, next sections.SectionConfig, actor, reason string) (AccessControlDocument, error) {
	if store == nil {
		return AccessControlDocument{}, errors.New("access control control-plane store is unavailable")
	}
	canonical, err := CanonicalAccessControlSectionConfig(next)
	if err != nil {
		return AccessControlDocument{}, fmt.Errorf("validate access control configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadAccessControl(ctx)
	if err != nil {
		return AccessControlDocument{}, fmt.Errorf("load current access control configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		expectedRevision = current.Revision
	}
	document, err := store.SaveAccessControl(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return AccessControlDocument{}, err
	}
	if err := ApplyAccessControlPlaneDocument(document); err != nil {
		return AccessControlDocument{}, fmt.Errorf("activate saved access control configuration: %w", err)
	}
	return cloneAccessControlDocument(document), nil
}

// ApplyAccessControlPlaneDocument validates and activates a committed Access Control document.
func ApplyAccessControlPlaneDocument(document AccessControlDocument) error {
	return applyAccessControlPlaneDocument(document, nil)
}

func applyAccessControlPlaneDocument(document AccessControlDocument, bootstrap *Config) error {
	if document.Revision < 1 {
		return errors.New("access control configuration revision is invalid")
	}
	canonical, err := CanonicalAccessControlSectionConfig(document.Config)
	if err != nil {
		return err
	}

	accessControlPlaneMu.Lock()
	defer accessControlPlaneMu.Unlock()

	if accessControlActivator != nil {
		if err := accessControlActivator(canonical); err != nil {
			return fmt.Errorf("activate access control runtime: %w", err)
		}
	}

	accessControlPlaneManaged = true
	accessControlLatestDocument = cloneAccessControlDocument(document)
	activateAccessControlConfig(bootstrap, canonical)
	return nil
}

func activateAccessControlConfig(bootstrap *Config, canonical sections.SectionConfig) {
	configMu.Lock()
	defer configMu.Unlock()

	apply := func(target *Config) {
		if target == nil {
			return
		}
		if target.Sections.AccessControl == nil {
			target.Sections.AccessControl = make(map[string]interface{})
		}
		for k, v := range canonical.Settings {
			target.Sections.AccessControl[k] = v
		}
		target.Sections.AccessControl["enabled"] = canonical.Enabled
		target.Sections.AccessControl["protection_level"] = canonical.ProtectionLevel
	}

	apply(GlobalConfig)
	apply(bootstrap)
}

func preserveManagedAccessControl(cfg *Config) {
	accessControlPlaneMu.Lock()
	managed := accessControlPlaneManaged
	latest := cloneAccessControlDocument(accessControlLatestDocument)
	accessControlPlaneMu.Unlock()

	if !managed || cfg == nil || latest.Revision < 1 {
		return
	}
	if cfg.Sections.AccessControl == nil {
		cfg.Sections.AccessControl = make(map[string]interface{})
	}
	for k, v := range latest.Config.Settings {
		cfg.Sections.AccessControl[k] = v
	}
	cfg.Sections.AccessControl["enabled"] = latest.Config.Enabled
	cfg.Sections.AccessControl["protection_level"] = latest.Config.ProtectionLevel
}

func cloneAccessControlDocument(doc AccessControlDocument) AccessControlDocument {
	clonedSettings := make(map[string]interface{}, len(doc.Config.Settings))
	for k, v := range doc.Config.Settings {
		clonedSettings[k] = v
	}
	return AccessControlDocument{
		Config: sections.SectionConfig{
			Enabled:         doc.Config.Enabled,
			ProtectionLevel: doc.Config.ProtectionLevel,
			Settings:        clonedSettings,
		},
		Revision: doc.Revision,
	}
}
