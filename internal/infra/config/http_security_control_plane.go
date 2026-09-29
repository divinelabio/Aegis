package config

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/divinelab-io/aegis/internal/sections"
)

const (
	// HTTPSecurityConfigurationScope is the persistence scope for HTTP Security in PostgreSQL.
	HTTPSecurityConfigurationScope         = "sections.http_security"
	HTTPSecurityConfigurationSchemaVersion = 1
)

var ErrHTTPSecurityRevisionConflict = errors.New("http security configuration revision conflict")

// HTTPSecurityRevisionConflictError reports a stale document write.
type HTTPSecurityRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *HTTPSecurityRevisionConflictError) Error() string {
	if e == nil {
		return ErrHTTPSecurityRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrHTTPSecurityRevisionConflict, e.Expected, e.Actual)
}

func (e *HTTPSecurityRevisionConflictError) Unwrap() error {
	return ErrHTTPSecurityRevisionConflict
}

// HTTPSecurityDocument represents the durable HTTP Security document in PostgreSQL.
type HTTPSecurityDocument struct {
	Config   sections.SectionConfig `json:"config"`
	Revision int64                  `json:"revision"`
}

// HTTPSecurityStore defines the PostgreSQL persistence boundary for HTTP Security.
type HTTPSecurityStore interface {
	LoadHTTPSecurity(context.Context) (HTTPSecurityDocument, bool, error)
	SaveHTTPSecurity(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (HTTPSecurityDocument, error)
}

// HTTPSecurityRuntimeActivator updates the in-memory HTTP Security engine when a document is activated.
type HTTPSecurityRuntimeActivator func(sections.SectionConfig) error

var (
	httpSecurityPlaneManaged   bool
	httpSecurityPlaneMu        sync.Mutex
	httpSecurityActivator      HTTPSecurityRuntimeActivator
	httpSecurityLatestDocument HTTPSecurityDocument
)

// SetHTTPSecurityRuntimeActivator registers the runtime update callback for HTTP Security.
func SetHTTPSecurityRuntimeActivator(activator HTTPSecurityRuntimeActivator) {
	httpSecurityPlaneMu.Lock()
	defer httpSecurityPlaneMu.Unlock()
	httpSecurityActivator = activator
}

// CanonicalHTTPSecuritySectionConfig normalizes and validates HTTP Security configuration.
func CanonicalHTTPSecuritySectionConfig(input sections.SectionConfig) (sections.SectionConfig, error) {
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

// InitializeHTTPSecurityControlPlane loads the authoritative HTTP Security document from PostgreSQL
// or imports bootstrap YAML on first boot.
func InitializeHTTPSecurityControlPlane(ctx context.Context, store HTTPSecurityStore, cfg *Config) (HTTPSecurityDocument, bool, error) {
	if store == nil {
		return HTTPSecurityDocument{}, false, errors.New("http security control-plane store is unavailable")
	}
	if cfg == nil {
		return HTTPSecurityDocument{}, false, errors.New("http security bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadHTTPSecurity(ctx)
	if err != nil {
		return HTTPSecurityDocument{}, false, fmt.Errorf("load http security control-plane document: %w", err)
	}

	imported := false
	if !found {
		bootstrapMap := cfg.GetSectionsConfigMap()
		httpSection, exists := bootstrapMap["http_security"]
		if !exists {
			httpSection = sections.SectionConfig{
				Enabled:         true,
				ProtectionLevel: 3,
				Settings:        cfg.Sections.HTTPSecurity,
			}
		}
		canonical, err := CanonicalHTTPSecuritySectionConfig(httpSection)
		if err != nil {
			return HTTPSecurityDocument{}, false, fmt.Errorf("validate http security bootstrap configuration: %w", err)
		}
		document, err = store.SaveHTTPSecurity(ctx, 0, canonical, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrHTTPSecurityRevisionConflict) {
				document, found, err = store.LoadHTTPSecurity(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("http security document disappeared after revision conflict")
				}
			}
			if err != nil {
				return HTTPSecurityDocument{}, false, fmt.Errorf("import http security YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}

	if err := applyHTTPSecurityControlPlaneDocument(document, cfg); err != nil {
		return HTTPSecurityDocument{}, false, err
	}
	return cloneHTTPSecurityDocument(document), imported, nil
}

// SaveHTTPSecurityControlPlane commits a validated HTTP Security document to PostgreSQL with CAS revision locking.
func SaveHTTPSecurityControlPlane(ctx context.Context, store HTTPSecurityStore, next sections.SectionConfig, actor, reason string) (HTTPSecurityDocument, error) {
	if store == nil {
		return HTTPSecurityDocument{}, errors.New("http security control-plane store is unavailable")
	}
	canonical, err := CanonicalHTTPSecuritySectionConfig(next)
	if err != nil {
		return HTTPSecurityDocument{}, fmt.Errorf("validate http security configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadHTTPSecurity(ctx)
	if err != nil {
		return HTTPSecurityDocument{}, fmt.Errorf("load current http security configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		expectedRevision = current.Revision
	}
	document, err := store.SaveHTTPSecurity(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return HTTPSecurityDocument{}, err
	}
	if err := ApplyHTTPSecurityControlPlaneDocument(document); err != nil {
		return HTTPSecurityDocument{}, fmt.Errorf("activate saved http security configuration: %w", err)
	}
	return cloneHTTPSecurityDocument(document), nil
}

// ApplyHTTPSecurityControlPlaneDocument validates and activates a committed HTTP Security document.
func ApplyHTTPSecurityControlPlaneDocument(document HTTPSecurityDocument) error {
	return applyHTTPSecurityControlPlaneDocument(document, nil)
}

func applyHTTPSecurityControlPlaneDocument(document HTTPSecurityDocument, bootstrap *Config) error {
	if document.Revision < 1 {
		return errors.New("http security configuration revision is invalid")
	}
	canonical, err := CanonicalHTTPSecuritySectionConfig(document.Config)
	if err != nil {
		return err
	}

	httpSecurityPlaneMu.Lock()
	defer httpSecurityPlaneMu.Unlock()

	if httpSecurityActivator != nil {
		if err := httpSecurityActivator(canonical); err != nil {
			return fmt.Errorf("activate http security runtime: %w", err)
		}
	}

	httpSecurityPlaneManaged = true
	httpSecurityLatestDocument = cloneHTTPSecurityDocument(document)
	activateHTTPSecurityConfig(bootstrap, canonical)
	return nil
}

func activateHTTPSecurityConfig(bootstrap *Config, canonical sections.SectionConfig) {
	configMu.Lock()
	defer configMu.Unlock()

	apply := func(target *Config) {
		if target == nil {
			return
		}
		if target.Sections.HTTPSecurity == nil {
			target.Sections.HTTPSecurity = make(map[string]interface{})
		}
		for k, v := range canonical.Settings {
			target.Sections.HTTPSecurity[k] = v
		}
		target.Sections.HTTPSecurity["enabled"] = canonical.Enabled
		target.Sections.HTTPSecurity["protection_level"] = canonical.ProtectionLevel
	}

	apply(GlobalConfig)
	apply(bootstrap)
}

func preserveManagedHTTPSecurity(cfg *Config) {
	httpSecurityPlaneMu.Lock()
	managed := httpSecurityPlaneManaged
	latest := cloneHTTPSecurityDocument(httpSecurityLatestDocument)
	httpSecurityPlaneMu.Unlock()

	if !managed || cfg == nil || latest.Revision < 1 {
		return
	}
	if cfg.Sections.HTTPSecurity == nil {
		cfg.Sections.HTTPSecurity = make(map[string]interface{})
	}
	for k, v := range latest.Config.Settings {
		cfg.Sections.HTTPSecurity[k] = v
	}
	cfg.Sections.HTTPSecurity["enabled"] = latest.Config.Enabled
	cfg.Sections.HTTPSecurity["protection_level"] = latest.Config.ProtectionLevel
}

func cloneHTTPSecurityDocument(doc HTTPSecurityDocument) HTTPSecurityDocument {
	clonedSettings := make(map[string]interface{}, len(doc.Config.Settings))
	for k, v := range doc.Config.Settings {
		clonedSettings[k] = v
	}
	return HTTPSecurityDocument{
		Config: sections.SectionConfig{
			Enabled:         doc.Config.Enabled,
			ProtectionLevel: doc.Config.ProtectionLevel,
			Settings:        clonedSettings,
		},
		Revision: doc.Revision,
	}
}
