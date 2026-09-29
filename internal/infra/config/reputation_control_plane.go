package config

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

const (
	// ReputationConfigurationScope is the persistence scope for Threat Intelligence & Reputation in PostgreSQL.
	ReputationConfigurationScope         = "modules.reputation"
	ReputationConfigurationSchemaVersion = 1
)

var ErrReputationRevisionConflict = errors.New("reputation configuration revision conflict")

// ReputationRevisionConflictError reports a stale document write.
type ReputationRevisionConflictError struct {
	Expected int64
	Actual   int64
}

func (e *ReputationRevisionConflictError) Error() string {
	if e == nil {
		return ErrReputationRevisionConflict.Error()
	}
	return fmt.Sprintf("%s: expected revision %d, current revision %d", ErrReputationRevisionConflict, e.Expected, e.Actual)
}

func (e *ReputationRevisionConflictError) Unwrap() error {
	return ErrReputationRevisionConflict
}

// CTIConfig holds settings for DivineLab CTI integration.
type CTIConfig struct {
	Enabled  bool   `json:"enabled" mapstructure:"enabled"`
	URL      string `json:"url" mapstructure:"url"`
	APIKey   string `json:"api_key" mapstructure:"api_key"`
	MinScore int    `json:"min_score" mapstructure:"min_score"`
}

// ReputationConfig defines the full IP reputation and threat intelligence settings.
type ReputationConfig struct {
	Enabled         bool      `json:"enabled" mapstructure:"enabled"`
	Action          string    `json:"action" mapstructure:"action"`
	BlockTor        bool      `json:"block_tor" mapstructure:"block_tor"`
	BlockDatacenter bool      `json:"block_datacenter" mapstructure:"block_datacenter"`
	CacheTTL        string    `json:"cache_ttl" mapstructure:"cache_ttl"`
	Sensitivity     int       `json:"sensitivity" mapstructure:"sensitivity"`
	AllowedIPs      []string  `json:"allowed_ips" mapstructure:"allowed_ips"`
	BlockedIPs      []string  `json:"blocked_ips" mapstructure:"blocked_ips"`
	CTI             CTIConfig `json:"cti" mapstructure:"cti"`
}

// DefaultReputationConfig returns production defaults for Reputation.
func DefaultReputationConfig() ReputationConfig {
	return ReputationConfig{
		Enabled:         true,
		Action:          "block",
		BlockTor:        false,
		BlockDatacenter: false,
		CacheTTL:        "1h",
		Sensitivity:     80,
		AllowedIPs:      []string{},
		BlockedIPs:      []string{},
		CTI: CTIConfig{
			Enabled:  true,
			URL:      "http://localhost:8090",
			MinScore: 60,
		},
	}
}

// ReputationDocument represents the durable document in PostgreSQL.
type ReputationDocument struct {
	Config   ReputationConfig `json:"config"`
	Revision int64            `json:"revision"`
}

// ReputationStore defines the PostgreSQL persistence boundary for Reputation.
type ReputationStore interface {
	LoadReputation(context.Context) (ReputationDocument, bool, error)
	SaveReputation(ctx context.Context, expectedRevision int64, next ReputationConfig, actor, reason string) (ReputationDocument, error)
}

// ReputationRuntimeActivator updates the in-memory reputation engine when a new document is activated.
type ReputationRuntimeActivator func(ReputationConfig) error

var (
	reputationPlaneManaged   bool
	reputationPlaneMu        sync.Mutex
	reputationActivator      ReputationRuntimeActivator
	reputationLatestDocument ReputationDocument
)

// SetReputationRuntimeActivator registers the runtime update callback for Reputation.
func SetReputationRuntimeActivator(activator ReputationRuntimeActivator) {
	reputationPlaneMu.Lock()
	defer reputationPlaneMu.Unlock()
	reputationActivator = activator
}

// CanonicalReputationConfig normalizes and validates Reputation configuration.
func CanonicalReputationConfig(input ReputationConfig) (ReputationConfig, error) {
	if input.Action == "" {
		input.Action = "block"
	}
	if input.CacheTTL == "" {
		input.CacheTTL = "1h"
	}
	if input.Sensitivity < 0 || input.Sensitivity > 100 {
		input.Sensitivity = 80
	}
	if input.AllowedIPs == nil {
		input.AllowedIPs = []string{}
	}
	if input.BlockedIPs == nil {
		input.BlockedIPs = []string{}
	}
	return input, nil
}

// InitializeReputationControlPlane loads the authoritative Reputation document from PostgreSQL
// or imports default configuration on first boot.
func InitializeReputationControlPlane(ctx context.Context, store ReputationStore, cfg *Config) (ReputationDocument, bool, error) {
	if store == nil {
		return ReputationDocument{}, false, errors.New("reputation control-plane store is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	document, found, err := store.LoadReputation(ctx)
	if err != nil {
		return ReputationDocument{}, false, fmt.Errorf("load reputation control-plane document: %w", err)
	}

	imported := false
	if !found {
		initialConfig := DefaultReputationConfig()
		canonical, err := CanonicalReputationConfig(initialConfig)
		if err != nil {
			return ReputationDocument{}, false, fmt.Errorf("validate reputation default configuration: %w", err)
		}
		document, err = store.SaveReputation(ctx, 0, canonical, "system:migration", "yaml_import")
		if err != nil {
			if errors.Is(err, ErrReputationRevisionConflict) {
				document, found, err = store.LoadReputation(ctx)
				if err == nil && found {
					imported = false
				} else if err == nil {
					err = errors.New("reputation document disappeared after revision conflict")
				}
			}
			if err != nil {
				return ReputationDocument{}, false, fmt.Errorf("import reputation configuration: %w", err)
			}
		} else {
			imported = true
		}
	}

	if err := applyReputationControlPlaneDocument(document, cfg); err != nil {
		return ReputationDocument{}, false, err
	}
	return cloneReputationDocument(document), imported, nil
}

// SaveReputationControlPlane commits a validated Reputation document to PostgreSQL with CAS revision locking.
func SaveReputationControlPlane(ctx context.Context, store ReputationStore, next ReputationConfig, actor, reason string) (ReputationDocument, error) {
	if store == nil {
		return ReputationDocument{}, errors.New("reputation control-plane store is unavailable")
	}
	canonical, err := CanonicalReputationConfig(next)
	if err != nil {
		return ReputationDocument{}, fmt.Errorf("validate reputation configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, found, err := store.LoadReputation(ctx)
	if err != nil {
		return ReputationDocument{}, fmt.Errorf("load current reputation configuration: %w", err)
	}
	expectedRevision := int64(0)
	if found {
		expectedRevision = current.Revision
	}
	document, err := store.SaveReputation(ctx, expectedRevision, canonical, actor, reason)
	if err != nil {
		return ReputationDocument{}, err
	}
	if err := ApplyReputationControlPlaneDocument(document); err != nil {
		return ReputationDocument{}, fmt.Errorf("activate saved reputation configuration: %w", err)
	}
	return cloneReputationDocument(document), nil
}

// ApplyReputationControlPlaneDocument validates and activates a committed Reputation document.
func ApplyReputationControlPlaneDocument(document ReputationDocument) error {
	return applyReputationControlPlaneDocument(document, nil)
}

func applyReputationControlPlaneDocument(document ReputationDocument, bootstrap *Config) error {
	if document.Revision < 1 {
		return errors.New("reputation configuration revision is invalid")
	}
	canonical, err := CanonicalReputationConfig(document.Config)
	if err != nil {
		return err
	}

	reputationPlaneMu.Lock()
	defer reputationPlaneMu.Unlock()

	if reputationActivator != nil {
		if err := reputationActivator(canonical); err != nil {
			return fmt.Errorf("activate reputation runtime: %w", err)
		}
	}

	reputationPlaneManaged = true
	reputationLatestDocument = cloneReputationDocument(document)
	return nil
}

func preserveManagedReputation(cfg *Config) {
	reputationPlaneMu.Lock()
	managed := reputationPlaneManaged
	latest := cloneReputationDocument(reputationLatestDocument)
	reputationPlaneMu.Unlock()

	if !managed || cfg == nil || latest.Revision < 1 {
		return
	}
}

func cloneReputationDocument(doc ReputationDocument) ReputationDocument {
	allowed := make([]string, len(doc.Config.AllowedIPs))
	copy(allowed, doc.Config.AllowedIPs)
	blocked := make([]string, len(doc.Config.BlockedIPs))
	copy(blocked, doc.Config.BlockedIPs)

	return ReputationDocument{
		Config: ReputationConfig{
			Enabled:         doc.Config.Enabled,
			Action:          doc.Config.Action,
			BlockTor:        doc.Config.BlockTor,
			BlockDatacenter: doc.Config.BlockDatacenter,
			CacheTTL:        doc.Config.CacheTTL,
			Sensitivity:     doc.Config.Sensitivity,
			AllowedIPs:      allowed,
			BlockedIPs:      blocked,
			CTI:             doc.Config.CTI,
		},
		Revision: doc.Revision,
	}
}
