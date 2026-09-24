package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	ErrorPagesConfigurationScope         = "modules.errorpages"
	ErrorPagesConfigurationSchemaVersion = 1
)

var ErrErrorPagesRevisionConflict = errors.New("Error Pages configuration revision conflict")

// ErrorPagesRevisionConflictError is returned when another control-plane
// writer committed an Error Pages document between a caller's read and save.
// Callers use errors.Is(err, ErrErrorPagesRevisionConflict) to return HTTP 409.
type ErrorPagesRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *ErrorPagesRevisionConflictError) Error() string {
	if e == nil {
		return ErrErrorPagesRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrErrorPagesRevisionConflict, e.Expected, e.Actual)
}

func (e *ErrorPagesRevisionConflictError) Unwrap() error { return ErrErrorPagesRevisionConflict }

// ErrorPagesDocument is the typed form of the complete Error Pages
// control-plane document. Revision is assigned by the durable store.
type ErrorPagesDocument struct {
	Config   ErrorPagesConfig
	Revision int64
}

// ErrorPagesStore keeps the Error Pages configuration package independent from
// the PostgreSQL implementation. This boundary keeps domain validation and
// activation testable without a database and prevents the config package from
// importing its persistence adapter.
type ErrorPagesStore interface {
	LoadErrorPages(context.Context) (ErrorPagesDocument, bool, error)
	SaveErrorPages(ctx context.Context, expectedRevision int64, next ErrorPagesConfig, actor, reason string) (ErrorPagesDocument, error)
}

// errorPagesControlPlaneManaged is protected by configMu. It is set only after
// the PostgreSQL document has been loaded or imported successfully. From that
// point generic YAML saves and SIGHUP parsing preserve the active document
// rather than allowing an old YAML copy to replace the runtime state.
var errorPagesControlPlaneManaged bool

// InitializeErrorPagesControlPlane loads the active PostgreSQL document. A
// deployment with no document yet receives one guarded, durable import from
// the already-validated YAML bootstrap configuration. YAML is not changed and
// never wins over a document after the import.
func InitializeErrorPagesControlPlane(ctx context.Context, store ErrorPagesStore, cfg *Config) (ErrorPagesDocument, bool, error) {
	if store == nil {
		return ErrorPagesDocument{}, false, errors.New("Error Pages control-plane store is unavailable")
	}
	if cfg == nil {
		return ErrorPagesDocument{}, false, errors.New("Error Pages bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadErrorPages(ctx)
	if err != nil {
		return ErrorPagesDocument{}, false, fmt.Errorf("load Error Pages control-plane document: %w", err)
	}
	imported := false
	if !found {
		bootstrap := cloneErrorPagesConfig(cfg.Modules.ErrorPages)
		if err := bootstrap.Validate(); err != nil {
			return ErrorPagesDocument{}, false, fmt.Errorf("validate Error Pages bootstrap configuration: %w", err)
		}
		document, err = store.SaveErrorPages(ctx, 0, bootstrap, "system:migration", "yaml_import")
		if err != nil {
			// Concurrent initializers are expected during a rolling deployment.
			// If another process won the create race, it is now authoritative.
			if errors.Is(err, ErrErrorPagesRevisionConflict) {
				document, found, err = store.LoadErrorPages(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("Error Pages document disappeared after a revision conflict")
				}
			}
			if err != nil {
				return ErrorPagesDocument{}, false, fmt.Errorf("import Error Pages YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}
	if err := document.Config.Validate(); err != nil {
		return ErrorPagesDocument{}, false, fmt.Errorf("validate stored Error Pages configuration: %w", err)
	}
	if document.Revision < 1 {
		return ErrorPagesDocument{}, false, errors.New("stored Error Pages configuration revision is invalid")
	}
	activateErrorPagesControlPlaneConfig(cfg, document.Config)
	return cloneErrorPagesDocument(document), imported, nil
}

// SaveErrorPagesControlPlane validates a full candidate, commits it with an
// optimistic revision check, and only then swaps the active runtime snapshot.
// A failed database write therefore leaves the last-known-good error pages in
// use for public error responses.
func SaveErrorPagesControlPlane(ctx context.Context, store ErrorPagesStore, next ErrorPagesConfig, actor, reason string) (ErrorPagesDocument, error) {
	if store == nil {
		return ErrorPagesDocument{}, errors.New("Error Pages control-plane store is unavailable")
	}
	if err := next.Validate(); err != nil {
		return ErrorPagesDocument{}, fmt.Errorf("validate Error Pages configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadErrorPages(ctx)
	if err != nil {
		return ErrorPagesDocument{}, fmt.Errorf("load current Error Pages configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		if err := current.Config.Validate(); err != nil {
			return ErrorPagesDocument{}, fmt.Errorf("validate current Error Pages configuration: %w", err)
		}
		if current.Revision < 1 {
			return ErrorPagesDocument{}, errors.New("current Error Pages configuration revision is invalid")
		}
		expectedRevision = current.Revision
	}
	document, err := store.SaveErrorPages(ctx, expectedRevision, cloneErrorPagesConfig(next), actor, reason)
	if err != nil {
		return ErrorPagesDocument{}, err
	}
	if err := ApplyErrorPagesControlPlaneDocument(document); err != nil {
		return ErrorPagesDocument{}, fmt.Errorf("activate saved Error Pages configuration: %w", err)
	}
	return cloneErrorPagesDocument(document), nil
}

// ApplyErrorPagesControlPlaneDocument validates and atomically activates a
// committed Error Pages document. It is used by the PostgreSQL listener on
// every process; an invalid or incomplete document therefore cannot displace
// the last-known-good public error response.
func ApplyErrorPagesControlPlaneDocument(document ErrorPagesDocument) error {
	if document.Revision < 1 {
		return errors.New("Error Pages configuration revision is invalid")
	}
	if err := document.Config.Validate(); err != nil {
		return fmt.Errorf("validate Error Pages configuration: %w", err)
	}
	activateErrorPagesControlPlaneConfig(nil, document.Config)
	return nil
}

// ContainsErrorPagesUpdate reports whether a generic settings request attempts
// to mutate any Error Pages field. Such requests must be routed through the
// complete-document control-plane handler, never into Viper's partial YAML
// merger.
func ContainsErrorPagesUpdate(updates map[string]interface{}) bool {
	for key := range updates {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), ErrorPagesConfigurationScope+".") {
			return true
		}
	}
	return false
}

var errorPagesUpdateKeys = []string{
	"modules.errorpages.enabled",
	"modules.errorpages.theme",
	"modules.errorpages.page_403",
	"modules.errorpages.page_404",
	"modules.errorpages.page_503",
	"modules.errorpages.templates",
	"modules.errorpages.active_template_id",
}

// ErrorPagesConfigFromUpdates accepts exactly the full document emitted by the
// existing Error Pages form. Partial or mixed updates are rejected because a
// document replacement is the atomic control-plane boundary.
func ErrorPagesConfigFromUpdates(updates map[string]interface{}) (ErrorPagesConfig, error) {
	if !ContainsErrorPagesUpdate(updates) {
		return ErrorPagesConfig{}, errors.New("Error Pages configuration update is required")
	}
	if len(updates) != len(errorPagesUpdateKeys) {
		return ErrorPagesConfig{}, errors.New("Error Pages updates must replace the complete document without unrelated settings")
	}
	for _, key := range errorPagesUpdateKeys {
		if _, ok := updates[key]; !ok {
			return ErrorPagesConfig{}, fmt.Errorf("Error Pages update is missing %s", key)
		}
	}

	enabled, ok := updates["modules.errorpages.enabled"].(bool)
	if !ok {
		return ErrorPagesConfig{}, errors.New("modules.errorpages.enabled must be a boolean")
	}
	config := ErrorPagesConfig{Enabled: enabled}
	for _, field := range []struct {
		key string
		set func(string)
	}{
		{"modules.errorpages.theme", func(value string) { config.Theme = value }},
		{"modules.errorpages.page_403", func(value string) { config.Page403 = value }},
		{"modules.errorpages.page_404", func(value string) { config.Page404 = value }},
		{"modules.errorpages.page_503", func(value string) { config.Page503 = value }},
		{"modules.errorpages.active_template_id", func(value string) { config.ActiveTemplateID = value }},
	} {
		value, ok := updates[field.key].(string)
		if !ok {
			return ErrorPagesConfig{}, fmt.Errorf("%s must be a string", field.key)
		}
		field.set(value)
	}
	templatesJSON, err := json.Marshal(updates["modules.errorpages.templates"])
	if err != nil {
		return ErrorPagesConfig{}, fmt.Errorf("encode modules.errorpages.templates: %w", err)
	}
	if err := json.Unmarshal(templatesJSON, &config.Templates); err != nil {
		return ErrorPagesConfig{}, fmt.Errorf("decode modules.errorpages.templates: %w", err)
	}
	if err := config.Validate(); err != nil {
		return ErrorPagesConfig{}, err
	}
	return cloneErrorPagesConfig(config), nil
}

func activateErrorPagesControlPlaneConfig(bootstrap *Config, pages ErrorPagesConfig) {
	pages = cloneErrorPagesConfig(pages)
	configMu.Lock()
	if GlobalConfig != nil {
		activated := *GlobalConfig
		activated.Modules.ErrorPages = pages
		GlobalConfig = &activated
	} else if bootstrap != nil {
		activated := *bootstrap
		activated.Modules.ErrorPages = pages
		GlobalConfig = &activated
	}
	errorPagesControlPlaneManaged = true
	configMu.Unlock()
	if bootstrap != nil {
		bootstrap.Modules.ErrorPages = cloneErrorPagesConfig(pages)
	}
}

// preserveManagedErrorPages overlays the active PostgreSQL document into a
// fresh YAML-derived Config. It is used by generic settings writes and SIGHUP
// reloads so those unrelated flows cannot regress a migrated document.
func preserveManagedErrorPages(cfg *Config) {
	if cfg == nil {
		return
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if !errorPagesControlPlaneManaged || GlobalConfig == nil {
		return
	}
	cfg.Modules.ErrorPages = cloneErrorPagesConfig(GlobalConfig.Modules.ErrorPages)
}

func cloneErrorPagesConfig(input ErrorPagesConfig) ErrorPagesConfig {
	clone := input
	clone.Templates = append([]ErrorPageTemplate(nil), input.Templates...)
	return clone
}

func cloneErrorPagesDocument(input ErrorPagesDocument) ErrorPagesDocument {
	clone := input
	clone.Config = cloneErrorPagesConfig(input.Config)
	return clone
}
