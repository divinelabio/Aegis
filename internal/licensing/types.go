// Package licensing implements Aegis installation licensing and entitlements.
package licensing

import (
	"context"
	"time"

	"github.com/divinelab-io/aegis/internal/edition"
)

type Status string

const (
	StatusCommunity           Status = "community"
	StatusActivating          Status = "activating"
	StatusUpgradeRequired     Status = "upgrade_required"
	StatusActive              Status = "active"
	StatusGrace               Status = "grace"
	StatusPastDue             Status = "past_due"
	StatusExpired             Status = "expired"
	StatusSuspended           Status = "suspended"
	StatusRevoked             Status = "revoked"
	StatusOverLimit           Status = "over_limit"
	StatusInvalid             Status = "invalid"
	StatusUpgradeFailed       Status = "upgrade_failed"
	StatusDeactivationPending Status = "deactivation_pending"
)

func (s Status) validEntitlementStatus() bool {
	switch s {
	case "", StatusActive, StatusGrace, StatusPastDue, StatusExpired, StatusSuspended, StatusRevoked:
		return true
	default:
		return false
	}
}

type UpgradeInfo struct {
	Required      bool              `json:"required"`
	State         string            `json:"state,omitempty"`
	TargetTier    edition.BuildTier `json:"target_tier,omitempty"`
	TargetVersion string            `json:"target_version,omitempty"`
	Manifest      string            `json:"-"`
	Credential    string            `json:"-"`
}

type Snapshot struct {
	BuildTier       edition.BuildTier   `json:"build_tier"`
	LicensedTier    edition.BuildTier   `json:"licensed_tier"`
	EffectiveTier   edition.BuildTier   `json:"effective_tier"`
	Status          Status              `json:"status"`
	Features        []edition.FeatureID `json:"features"`
	ActivationID    string              `json:"activation_id,omitempty"`
	ExpiresAt       time.Time           `json:"expires_at,omitempty"`
	OfflineUntil    time.Time           `json:"offline_until,omitempty"`
	SubscriptionEnd time.Time           `json:"subscription_end,omitempty"`
	LastRefresh     time.Time           `json:"last_refresh,omitempty"`
	LastError       string              `json:"last_error,omitempty"`
	Upgrade         UpgradeInfo         `json:"upgrade"`

	effective edition.FeatureSet
}

func (s Snapshot) Has(feature edition.FeatureID) bool { return s.effective.Has(feature) }

type ActivationResult struct {
	Snapshot Snapshot    `json:"license"`
	Upgrade  UpgradeInfo `json:"upgrade"`
}

type Manager interface {
	Snapshot() Snapshot
	Has(edition.FeatureID) bool
	Activate(context.Context, string) (ActivationResult, error)
	Refresh(context.Context) error
	Deactivate(context.Context) error
	Subscribe() <-chan Snapshot
}
