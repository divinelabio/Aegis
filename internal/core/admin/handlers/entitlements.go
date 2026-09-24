package handlers

import (
	"github.com/divinelab-io/aegis/internal/edition"
	"github.com/divinelab-io/aegis/internal/licensing"
)

// currentLicenseSnapshot is the sole admin-side source for plan data. It
// intentionally reports the manager's effective capabilities, not the
// compiled build tier or an unverified licence label.
func (h *Handler) currentLicenseSnapshot() licensing.Snapshot {
	community := licensing.Snapshot{
		BuildTier:     edition.CommunityTier,
		LicensedTier:  edition.CommunityTier,
		EffectiveTier: edition.CommunityTier,
		Status:        licensing.StatusCommunity,
		Features:      edition.FeaturesForTier(edition.CommunityTier).Sorted(),
	}
	if h == nil || h.License == nil {
		return community
	}

	snapshot := h.License.Snapshot()
	if !snapshot.EffectiveTier.Valid() {
		return community
	}
	// Feature order is part of the admin API contract; canonicalise it while
	// preserving only explicitly active capabilities.
	snapshot.Features = edition.NewFeatureSet(snapshot.Features...).Sorted()
	return snapshot
}
