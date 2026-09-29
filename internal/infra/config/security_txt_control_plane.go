package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const (
	SecurityTXTConfigurationScope         = "security_txt"
	SecurityTXTConfigurationSchemaVersion = 1
)

var ErrSecurityTXTRevisionConflict = errors.New("Security.txt configuration revision conflict")

// SecurityTXTRevisionConflictError reports a concurrent durable update.
type SecurityTXTRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *SecurityTXTRevisionConflictError) Error() string {
	if e == nil {
		return ErrSecurityTXTRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrSecurityTXTRevisionConflict, e.Expected, e.Actual)
}

func (e *SecurityTXTRevisionConflictError) Unwrap() error { return ErrSecurityTXTRevisionConflict }

// SecurityTXTDocument is the typed, complete public disclosure document.
type SecurityTXTDocument struct {
	Config   SecurityTXTConfig
	Revision int64
}

// SecurityTXTStore keeps the config domain independent from PostgreSQL.
type SecurityTXTStore interface {
	LoadSecurityTXT(context.Context) (SecurityTXTDocument, bool, error)
	SaveSecurityTXT(ctx context.Context, expectedRevision int64, next SecurityTXTConfig, actor, reason string) (SecurityTXTDocument, error)
}

// securityTXTControlPlaneManaged is protected by configMu. Once true, YAML
// reloads and unrelated generic saves cannot replace the committed document.
var securityTXTControlPlaneManaged bool

// CanonicalSecurityTXTConfig validates the public contact and stores emails as
// mailto URIs so all processes converge on one representation.
func CanonicalSecurityTXTConfig(next SecurityTXTConfig) (SecurityTXTConfig, error) {
	contact, err := NormalizeSecurityTXTContact(next.Contact)
	if err != nil {
		return SecurityTXTConfig{}, err
	}
	return SecurityTXTConfig{Contact: contact}, nil
}

// InitializeSecurityTXTControlPlane imports the validated YAML value only when
// no durable document exists; after that PostgreSQL is authoritative.
func InitializeSecurityTXTControlPlane(ctx context.Context, store SecurityTXTStore, cfg *Config) (SecurityTXTDocument, bool, error) {
	if store == nil {
		return SecurityTXTDocument{}, false, errors.New("Security.txt control-plane store is unavailable")
	}
	if cfg == nil {
		return SecurityTXTDocument{}, false, errors.New("Security.txt bootstrap configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadSecurityTXT(ctx)
	if err != nil {
		return SecurityTXTDocument{}, false, fmt.Errorf("load Security.txt control-plane document: %w", err)
	}
	imported := false
	if !found {
		bootstrap, err := CanonicalSecurityTXTConfig(cfg.SecurityTXT)
		if err != nil {
			return SecurityTXTDocument{}, false, fmt.Errorf("validate Security.txt bootstrap configuration: %w", err)
		}
		document, err = store.SaveSecurityTXT(ctx, 0, bootstrap, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrSecurityTXTRevisionConflict) {
				document, found, err = store.LoadSecurityTXT(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("Security.txt document disappeared after a revision conflict")
				}
			}
			if err != nil {
				return SecurityTXTDocument{}, false, fmt.Errorf("import Security.txt YAML configuration: %w", err)
			}
		} else {
			imported = true
		}
	}
	if err := validateSecurityTXTDocument(document); err != nil {
		return SecurityTXTDocument{}, false, fmt.Errorf("validate stored Security.txt configuration: %w", err)
	}
	activateSecurityTXTControlPlaneConfig(cfg, document.Config)
	return document, imported, nil
}

// SaveSecurityTXTControlPlane commits a complete public contact before it is
// activated. Failed writes leave the last-known-good disclosure document live.
func SaveSecurityTXTControlPlane(ctx context.Context, store SecurityTXTStore, next SecurityTXTConfig, actor, reason string) (SecurityTXTDocument, error) {
	if store == nil {
		return SecurityTXTDocument{}, errors.New("Security.txt control-plane store is unavailable")
	}
	next, err := CanonicalSecurityTXTConfig(next)
	if err != nil {
		return SecurityTXTDocument{}, fmt.Errorf("validate Security.txt configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadSecurityTXT(ctx)
	if err != nil {
		return SecurityTXTDocument{}, fmt.Errorf("load current Security.txt configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		if err := validateSecurityTXTDocument(current); err != nil {
			return SecurityTXTDocument{}, fmt.Errorf("validate current Security.txt configuration: %w", err)
		}
		expectedRevision = current.Revision
	}
	document, err := store.SaveSecurityTXT(ctx, expectedRevision, next, actor, reason)
	if err != nil {
		return SecurityTXTDocument{}, err
	}
	if err := ApplySecurityTXTControlPlaneDocument(document); err != nil {
		return SecurityTXTDocument{}, fmt.Errorf("activate saved Security.txt configuration: %w", err)
	}
	return document, nil
}

// ApplySecurityTXTControlPlaneDocument activates only a valid canonical,
// committed document. It is used by PostgreSQL listener callbacks.
func ApplySecurityTXTControlPlaneDocument(document SecurityTXTDocument) error {
	if err := validateSecurityTXTDocument(document); err != nil {
		return err
	}
	activateSecurityTXTControlPlaneConfig(nil, document.Config)
	return nil
}

func validateSecurityTXTDocument(document SecurityTXTDocument) error {
	if document.Revision < 1 {
		return errors.New("Security.txt configuration revision is invalid")
	}
	canonical, err := CanonicalSecurityTXTConfig(document.Config)
	if err != nil {
		return fmt.Errorf("validate Security.txt contact: %w", err)
	}
	if canonical != document.Config {
		return errors.New("Security.txt configuration is not canonical")
	}
	return nil
}

// ContainsSecurityTXTUpdate identifies mutations that must bypass generic YAML
// persistence and be saved as the complete Security.txt document.
func ContainsSecurityTXTUpdate(updates map[string]interface{}) bool {
	for key := range updates {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), SecurityTXTConfigurationScope+".") {
			return true
		}
	}
	return false
}

// SecurityTXTConfigFromUpdates accepts exactly the one-field document emitted
// by the existing App Security console.
func SecurityTXTConfigFromUpdates(updates map[string]interface{}) (SecurityTXTConfig, error) {
	if !ContainsSecurityTXTUpdate(updates) {
		return SecurityTXTConfig{}, errors.New("Security.txt configuration update is required")
	}
	if len(updates) != 1 {
		return SecurityTXTConfig{}, errors.New("Security.txt updates must replace the complete document without unrelated settings")
	}
	value, ok := updates["security_txt.contact"].(string)
	if !ok {
		return SecurityTXTConfig{}, errors.New("security_txt.contact must be a string")
	}
	canonical, err := CanonicalSecurityTXTConfig(SecurityTXTConfig{Contact: value})
	if err != nil {
		return SecurityTXTConfig{}, err
	}
	return canonical, nil
}

func activateSecurityTXTControlPlaneConfig(bootstrap *Config, next SecurityTXTConfig) {
	configMu.Lock()
	if GlobalConfig != nil {
		activated := *GlobalConfig
		activated.SecurityTXT = next
		GlobalConfig = &activated
	} else if bootstrap != nil {
		activated := *bootstrap
		activated.SecurityTXT = next
		GlobalConfig = &activated
	}
	securityTXTControlPlaneManaged = true
	configMu.Unlock()
	if bootstrap != nil {
		bootstrap.SecurityTXT = next
	}
}

func preserveManagedSecurityTXT(cfg *Config) {
	if cfg == nil {
		return
	}
	configMu.RLock()
	defer configMu.RUnlock()
	if !securityTXTControlPlaneManaged || GlobalConfig == nil {
		return
	}
	cfg.SecurityTXT = GlobalConfig.SecurityTXT
}
