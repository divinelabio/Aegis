package config

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/divinelab-io/aegis/internal/sections"
)

const (
	// TrafficControlConfigurationScope is the unique persistence scope for
	// the Traffic Control security section document in PostgreSQL.
	TrafficControlConfigurationScope         = "sections.traffic_control"
	TrafficControlConfigurationSchemaVersion = 1
)

var ErrTrafficControlRevisionConflict = errors.New("traffic control configuration revision conflict")

// TrafficControlRevisionConflictError reports a stale document write.
type TrafficControlRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *TrafficControlRevisionConflictError) Error() string {
	if e == nil {
		return ErrTrafficControlRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrTrafficControlRevisionConflict, e.Expected, e.Actual)
}

func (e *TrafficControlRevisionConflictError) Unwrap() error {
	return ErrTrafficControlRevisionConflict
}

// TrafficControlDocument is the durable section document persisted to PostgreSQL.
type TrafficControlDocument struct {
	Config   sections.SectionConfig `json:"config"`
	Revision int64                  `json:"revision"`
}

// TrafficControlStore defines the PostgreSQL persistence boundary for Traffic Control.
type TrafficControlStore interface {
	LoadTrafficControl(context.Context) (TrafficControlDocument, bool, error)
	SaveTrafficControl(ctx context.Context, expectedRevision int64, next sections.SectionConfig, actor, reason string) (TrafficControlDocument, error)
}

// TrafficControlRuntimeActivator updates the in-memory Traffic Control engine
// when a new document is activated or received via pg_notify.
type TrafficControlRuntimeActivator func(sections.SectionConfig) error

var (
	trafficControlPlaneManaged bool
	trafficControlPlaneMu      sync.Mutex
	trafficControlActivator    TrafficControlRuntimeActivator
	trafficControlLatestDoc    TrafficControlDocument
)

// SetTrafficControlRuntimeActivator registers the runtime update callback.
func SetTrafficControlRuntimeActivator(activator TrafficControlRuntimeActivator) {
	trafficControlPlaneMu.Lock()
	defer trafficControlPlaneMu.Unlock()
	trafficControlActivator = activator
}

// CanonicalTrafficControlSectionConfig normalizes and validates a Traffic Control section configuration.
func CanonicalTrafficControlSectionConfig(input sections.SectionConfig) (sections.SectionConfig, error) {
	canonicalSettings := canonicalTrafficControlSettings(input.Settings)
	if canonicalSettings == nil {
		canonicalSettings = make(map[string]interface{})
	}
	protectionLevel := input.ProtectionLevel
	if protectionLevel < 1 || protectionLevel > 5 {
		protectionLevel = 3
	}
	canonicalSettings["enabled"] = input.Enabled
	canonicalSettings["protection_level"] = protectionLevel

	return sections.SectionConfig{
		Enabled:         input.Enabled,
		ProtectionLevel: protectionLevel,
		Settings:        canonicalSettings,
	}, nil
}

// InitializeTrafficControlPlane loads the authoritative Traffic Control document
// from PostgreSQL or imports bootstrap YAML on first boot.
func InitializeTrafficControlPlane(ctx context.Context, store TrafficControlStore, cfg *Config) (TrafficControlDocument, bool, error) {
	if store == nil {
		return TrafficControlDocument{}, false, errors.New("traffic control control-plane store is unavailable")
	}
	if cfg == nil {
		return TrafficControlDocument{}, false, errors.New("traffic control bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadTrafficControl(ctx)
	if err != nil {
		return TrafficControlDocument{}, false, fmt.Errorf("load traffic control control-plane document: %w", err)
	}

	imported := false
	if !found {
		bootstrapMap := cfg.GetSectionsConfigMap()
		trafficSection, exists := bootstrapMap["traffic_control"]
		if !exists {
			trafficSection = sections.SectionConfig{
				Enabled:         true,
				ProtectionLevel: 3,
				Settings:        cfg.Sections.TrafficControl,
			}
		}
		canonical, err := CanonicalTrafficControlSectionConfig(trafficSection)
		if err != nil {
			return TrafficControlDocument{}, false, fmt.Errorf("validate traffic control bootstrap configuration: %w", err)
		}
		document, err = store.SaveTrafficControl(ctx, 0, canonical, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrTrafficControlRevisionConflict) {
				document, found, err = store.LoadTrafficControl(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("traffic control document disappeared after revision conflict")
				}
			}
			if err != nil {
				return TrafficControlDocument{}, false, fmt.Errorf("import traffic control YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}

	if err := applyTrafficControlPlaneDocument(document, cfg); err != nil {
		return TrafficControlDocument{}, false, err
	}
	return cloneTrafficControlDocument(document), imported, nil
}

// SaveTrafficControlControlPlane persists a validated Traffic Control document
// to PostgreSQL with compare-and-swap concurrency control.
func SaveTrafficControlControlPlane(ctx context.Context, store TrafficControlStore, next sections.SectionConfig, actor, reason string) (TrafficControlDocument, error) {
	if store == nil {
		return TrafficControlDocument{}, errors.New("traffic control control-plane store is unavailable")
	}
	canonical, err := CanonicalTrafficControlSectionConfig(next)
	if err != nil {
		return TrafficControlDocument{}, fmt.Errorf("validate traffic control configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadTrafficControl(ctx)
	if err != nil {
		return TrafficControlDocument{}, fmt.Errorf("load current traffic control configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		expectedRevision = current.Revision
	}
	document, err := store.SaveTrafficControl(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return TrafficControlDocument{}, err
	}
	if err := ApplyTrafficControlPlaneDocument(document); err != nil {
		return TrafficControlDocument{}, fmt.Errorf("activate saved traffic control configuration: %w", err)
	}
	return cloneTrafficControlDocument(document), nil
}

// ApplyTrafficControlPlaneDocument validates and activates a committed PostgreSQL document in memory.
func ApplyTrafficControlPlaneDocument(document TrafficControlDocument) error {
	return applyTrafficControlPlaneDocument(document, nil)
}

func applyTrafficControlPlaneDocument(document TrafficControlDocument, bootstrap *Config) error {
	if document.Revision < 1 {
		return errors.New("traffic control configuration revision is invalid")
	}
	canonical, err := CanonicalTrafficControlSectionConfig(document.Config)
	if err != nil {
		return err
	}

	trafficControlPlaneMu.Lock()
	defer trafficControlPlaneMu.Unlock()

	if trafficControlActivator != nil {
		if err := trafficControlActivator(canonical); err != nil {
			return fmt.Errorf("activate traffic control runtime: %w", err)
		}
	}

	trafficControlPlaneManaged = true
	trafficControlLatestDoc = cloneTrafficControlDocument(document)
	activateTrafficControlConfig(bootstrap, canonical)
	return nil
}

func activateTrafficControlConfig(bootstrap *Config, canonical sections.SectionConfig) {
	configMu.Lock()
	defer configMu.Unlock()

	apply := func(target *Config) {
		if target == nil {
			return
		}
		if target.Sections.TrafficControl == nil {
			target.Sections.TrafficControl = make(map[string]interface{})
		}
		for k, v := range canonical.Settings {
			target.Sections.TrafficControl[k] = v
		}
		target.Sections.TrafficControl["enabled"] = canonical.Enabled
		target.Sections.TrafficControl["protection_level"] = canonical.ProtectionLevel
	}

	apply(GlobalConfig)
	apply(bootstrap)
}

func preserveManagedTrafficControl(cfg *Config) {
	trafficControlPlaneMu.Lock()
	managed := trafficControlPlaneManaged
	latest := cloneTrafficControlDocument(trafficControlLatestDoc)
	trafficControlPlaneMu.Unlock()

	if !managed || cfg == nil || latest.Revision < 1 {
		return
	}
	if cfg.Sections.TrafficControl == nil {
		cfg.Sections.TrafficControl = make(map[string]interface{})
	}
	for k, v := range latest.Config.Settings {
		cfg.Sections.TrafficControl[k] = v
	}
	cfg.Sections.TrafficControl["enabled"] = latest.Config.Enabled
	cfg.Sections.TrafficControl["protection_level"] = latest.Config.ProtectionLevel
}

func cloneTrafficControlDocument(doc TrafficControlDocument) TrafficControlDocument {
	clonedSettings := make(map[string]interface{}, len(doc.Config.Settings))
	for k, v := range doc.Config.Settings {
		clonedSettings[k] = v
	}
	return TrafficControlDocument{
		Config: sections.SectionConfig{
			Enabled:         doc.Config.Enabled,
			ProtectionLevel: doc.Config.ProtectionLevel,
			Settings:        clonedSettings,
		},
		Revision: doc.Revision,
	}
}
