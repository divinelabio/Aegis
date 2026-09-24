package sections

import (
	"context"
	"net/http"
	"sync"

	"go.uber.org/zap"
)

// =============================================================================
// SECTION REGISTRY
// =============================================================================

// Registry manages all sections
type Registry struct {
	mu       sync.RWMutex
	sections map[string]Section
	order    []string
	logger   *zap.Logger
}

// NewRegistry creates a new section registry
func NewRegistry(logger *zap.Logger) *Registry {
	return &Registry{
		sections: make(map[string]Section),
		order:    make([]string, 0),
		logger:   logger,
	}
}

// Register registers a section
func (r *Registry) Register(s Section) {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := s.ID()
	r.sections[id] = s
	r.order = append(r.order, id)

	r.logger.Info("Section registered",
		zap.String("id", id),
		zap.String("name", s.Name()),
	)
}

// List returns all registered sections
func (r *Registry) List() []Section {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Section, 0, len(r.order))
	for _, id := range r.order {
		if s, ok := r.sections[id]; ok {
			result = append(result, s)
		}
	}
	return result
}

// Get returns a registered section by ID.
func (r *Registry) Get(id string) (Section, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sections[id]
	return s, ok
}

// InitAll initializes all sections
func (r *Registry) InitAll(configs map[string]SectionConfig) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for id, s := range r.sections {
		cfg := SectionConfig{Enabled: true, ProtectionLevel: 3}
		if c, ok := configs[id]; ok {
			cfg = c
		}
		if err := s.Init(cfg); err != nil {
			r.logger.Error("Failed to initialize section",
				zap.String("id", id),
				zap.Error(err),
			)
			return err
		}
	}
	return nil
}

// StartAll starts all sections
func (r *Registry) StartAll(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, id := range r.order {
		s := r.sections[id]
		alwaysInstalled, _ := s.(interface{ AlwaysInstallMiddleware() bool })
		if s.Enabled() || (alwaysInstalled != nil && alwaysInstalled.AlwaysInstallMiddleware()) {
			if err := s.Start(ctx); err != nil {
				r.logger.Error("Failed to start section",
					zap.String("id", id),
					zap.Error(err),
				)
				return err
			}
		}
	}
	return nil
}

// StopAll stops all sections
func (r *Registry) StopAll(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Stop in reverse order
	for i := len(r.order) - 1; i >= 0; i-- {
		id := r.order[i]
		s := r.sections[id]
		if err := s.Stop(ctx); err != nil {
			r.logger.Warn("Error stopping section",
				zap.String("id", id),
				zap.Error(err),
			)
		}
	}
	return nil
}

// BuildMiddlewareChain builds the middleware chain from all enabled sections
func (r *Registry) BuildMiddlewareChain() []func(http.Handler) http.Handler {
	r.mu.RLock()
	defer r.mu.RUnlock()

	middlewares := make([]func(http.Handler) http.Handler, 0, len(r.order))

	for _, id := range r.order {
		s := r.sections[id]
		alwaysInstalled, _ := s.(interface{ AlwaysInstallMiddleware() bool })
		if s.Enabled() || (alwaysInstalled != nil && alwaysInstalled.AlwaysInstallMiddleware()) {
			middlewares = append(middlewares, s.Middleware)
		}
	}

	return middlewares
}

// GetAllStats returns stats for all sections
func (r *Registry) GetAllStats() map[string]SectionStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make(map[string]SectionStats)
	for id, s := range r.sections {
		stats[id] = s.Stats()
	}
	return stats
}

// GetAllHealth returns health status for all sections
func (r *Registry) GetAllHealth() map[string]HealthStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	health := make(map[string]HealthStatus)
	for id, s := range r.sections {
		health[id] = s.Health()
	}
	return health
}

// ListInfo returns info about all sections
func (r *Registry) ListInfo() []SectionInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	infos := make([]SectionInfo, 0, len(r.order))
	for _, id := range r.order {
		s := r.sections[id]
		infos = append(infos, SectionInfo{
			ID:          s.ID(),
			Name:        s.Name(),
			Description: s.Description(),
			Icon:        s.Icon(),
			Enabled:     s.Enabled(),
			Functions:   len(s.ListFunctions()),
		})
	}
	return infos
}

// SectionInfo provides basic info about a section
type SectionInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Enabled     bool   `json:"enabled"`
	Functions   int    `json:"functions"`
}
