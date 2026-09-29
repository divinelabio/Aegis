// Package app provides application-level setup and wiring.
//
// Community edition — BSL-1.1.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"go.uber.org/zap"

	"github.com/divinelab-io/aegis/internal/infra/health"
	"github.com/divinelab-io/aegis/internal/infra/metrics"
	"github.com/divinelab-io/aegis/internal/sections"
)

// SectionManager manages all active security sections.
type SectionManager struct {
	registry       *sections.Registry
	logger         *zap.Logger
	UnifiedMetrics *metrics.UnifiedCollector
}

type publicRouteRegistrar interface {
	RegisterPublicRoutes(mux *http.ServeMux, prefix string)
}

// NewSectionManager creates the section manager using the active bundle.
func NewSectionManager(bundle EditionBundle, logger *zap.Logger, unifiedMetrics *metrics.UnifiedCollector, deps BundleDependencies) (*SectionManager, error) {
	if bundle == nil {
		bundle = DefaultBundle()
	}
	registry := sections.NewRegistry(logger)
	// Allow enterprise overlay to inject License, RuleStore, etc. without
	// requiring main.go to know about enterprise-specific dependencies.
	if DepsHook != nil {
		DepsHook(&deps)
	}
	if err := bundle.RegisterSections(registry, deps); err != nil {
		return nil, fmt.Errorf("register sections: %w", err)
	}
	return &SectionManager{
		registry:       registry,
		logger:         logger,
		UnifiedMetrics: unifiedMetrics,
	}, nil
}

// Init initializes all sections with configs.
func (m *SectionManager) Init(configs map[string]sections.SectionConfig) error {
	if configs == nil {
		configs = DefaultSectionConfigs()
	}
	return m.registry.InitAll(configs)
}

// Start starts all enabled sections.
func (m *SectionManager) Start(ctx context.Context) error {
	return m.registry.StartAll(ctx)
}

// Stop stops all sections.
func (m *SectionManager) Stop(ctx context.Context) error {
	return m.registry.StopAll(ctx)
}

// BuildMiddlewareChain returns the HTTP middleware chain.
func (m *SectionManager) BuildMiddlewareChain() []func(http.Handler) http.Handler {
	return m.registry.BuildMiddlewareChain()
}

// RegisterRoutes registers admin API routes for all sections.
func (m *SectionManager) RegisterRoutes(mux *http.ServeMux) {
	for _, s := range m.registry.List() {
		prefix := fmt.Sprintf("/api/sections/%s", s.ID())
		s.RegisterRoutes(mux, prefix)
	}

	mux.HandleFunc("/api/sections/all/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := m.GetStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})
}

// RegisterPublicRoutes exposes section-owned browser/runtime endpoints on the
// proxy listener without exposing the admin-only section API surface.
func (m *SectionManager) RegisterPublicRoutes(mux *http.ServeMux) {
	for _, s := range m.registry.List() {
		registrar, ok := s.(publicRouteRegistrar)
		if !ok {
			continue
		}
		prefix := fmt.Sprintf("/api/sections/%s", s.ID())
		registrar.RegisterPublicRoutes(mux, prefix)
	}
}

// GetStats returns stats for all sections.
func (m *SectionManager) GetStats() map[string]sections.SectionStats {
	return m.registry.GetAllStats()
}

// GetHealth returns health for all sections.
func (m *SectionManager) GetHealth() map[string]sections.HealthStatus {
	return m.registry.GetAllHealth()
}

// GlobalHealth aggregates health into a single check.
func (m *SectionManager) GlobalHealth() health.Check {
	return summarizeGlobalHealth(m.GetHealth(), m.GetStats())
}

// summarizeGlobalHealth reports only actionable section health. A disabled
// protection is an explicit operator choice, so it must not degrade the
// installation's overall health while it is disabled.
func summarizeGlobalHealth(allHealth map[string]sections.HealthStatus, allStats map[string]sections.SectionStats) health.Check {
	unhealthy, degraded := 0, 0
	enabledSections := 0
	for sectionID, h := range allHealth {
		if stats, known := allStats[sectionID]; known && !stats.Enabled {
			continue
		}
		enabledSections++
		switch h.Status {
		case sections.HealthStateUnhealthy:
			unhealthy++
		case sections.HealthStateDegraded:
			degraded++
		}
	}
	status := health.StatusHealthy
	message := fmt.Sprintf("All %d enabled %s healthy", enabledSections, sectionCountLabel(enabledSections))
	if unhealthy > 0 {
		status = health.StatusUnhealthy
		message = fmt.Sprintf("%d enabled %s unhealthy", unhealthy, sectionCountLabel(unhealthy))
	} else if degraded > 0 {
		status = health.StatusDegraded
		message = fmt.Sprintf("%d enabled %s degraded", degraded, sectionCountLabel(degraded))
	}
	return health.Check{
		Name:    "Security Engines",
		Status:  status,
		Message: message,
	}
}

func sectionCountLabel(count int) string {
	if count == 1 {
		return "section"
	}
	return "sections"
}

// ListSections returns info about all sections.
func (m *SectionManager) ListSections() []sections.SectionInfo {
	return m.registry.ListInfo()
}

// GetSection returns a section by ID.
func (m *SectionManager) GetSection(id string) (sections.Section, bool) {
	return m.registry.Get(id)
}

// DefaultSectionConfigs returns default section configs.
func DefaultSectionConfigs() map[string]sections.SectionConfig {
	return map[string]sections.SectionConfig{}
}
