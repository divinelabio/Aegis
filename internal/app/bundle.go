// Package app provides edition-neutral bundle wiring and the Community bundle.
package app

import (
	"github.com/divinelab-io/aegis/internal/analytics"
	"github.com/divinelab-io/aegis/internal/edition"
	"github.com/divinelab-io/aegis/internal/infra/geoip"
	"github.com/divinelab-io/aegis/internal/infra/metrics"
	"github.com/divinelab-io/aegis/internal/infra/transport"
	"github.com/divinelab-io/aegis/internal/licensing"
	"github.com/divinelab-io/aegis/internal/rules"
	"github.com/divinelab-io/aegis/internal/sections"
	"github.com/divinelab-io/aegis/internal/sections/httpbasic"
	"github.com/divinelab-io/aegis/internal/sections/trafficbasic"
	"github.com/divinelab-io/aegis/internal/sections/wafbasic"
	"go.uber.org/zap"
)

// BundleDependencies carries runtime services into the section bundle.
// Commercial overlays populate License through DepsHook.
type BundleDependencies struct {
	Logger               *zap.Logger
	Metrics              *metrics.UnifiedCollector
	Geo                  *geoip.Service
	License              licensing.Manager
	RuleStore            *rules.Store
	AnalyticsStore       *analytics.Store
	Router               *transport.Router
	PersistSectionConfig sections.SectionConfigPersister
}

// DepsHook lets commercial builds inject their licence manager.
var DepsHook func(*BundleDependencies)

// EditionBundle registers all security sections for a given edition.
type EditionBundle interface {
	CompiledTier() edition.BuildTier
	CompiledFeatures() edition.FeatureSet
	RegisterSections(*sections.Registry, BundleDependencies) error
}

// BundleFactory returns the active EditionBundle.
// Tier-specific overlay files override this for commercial builds.
var BundleFactory = func() EditionBundle { return CommunityBundle{} }

// DefaultBundle returns the active edition bundle.
func DefaultBundle() EditionBundle { return BundleFactory() }

// ─── Community Bundle ────────────────────────────────────────────────────────

// CommunityBundle registers the community-tier security sections.
type CommunityBundle struct{}

func (CommunityBundle) CompiledTier() edition.BuildTier { return edition.CommunityTier }
func (CommunityBundle) CompiledFeatures() edition.FeatureSet {
	return edition.FeaturesForTier(edition.CommunityTier)
}
func (CommunityBundle) RegisterSections(registry *sections.Registry, deps BundleDependencies) error {
	reg := func(id string) {
		if deps.Metrics != nil {
			deps.Metrics.RegisterSection(id)
		}
	}
	registry.Register(trafficbasic.New(deps.Logger, deps.Geo, deps.PersistSectionConfig))
	reg(trafficbasic.SectionID)
	registry.Register(wafbasic.New(deps.Logger, deps.PersistSectionConfig))
	reg(wafbasic.SectionID)
	registry.Register(httpbasic.New(deps.Logger, deps.PersistSectionConfig))
	reg(httpbasic.SectionID)
	return nil
}
