// Package health provides a health check endpoint for the Aegis WAF.
package health

import (
	"encoding/json"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// Status represents the health status
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
)

// Check represents a single health check
type Check struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message,omitempty"`
}

// Response is the health check response
type Response struct {
	Status    Status                 `json:"status"`
	Timestamp string                 `json:"timestamp"`
	Uptime    string                 `json:"uptime"`
	Version   string                 `json:"version,omitempty"`
	Checks    []Check                `json:"checks,omitempty"`
	System    map[string]interface{} `json:"system,omitempty"`
}

// Handler provides health check endpoints
type Handler struct {
	startTime time.Time
	version   string
	checks    []func() Check
	ready     atomic.Bool
}

// NewHandler creates a new health check handler
func NewHandler(version string) *Handler {
	h := &Handler{
		startTime: time.Now(),
		version:   version,
		checks:    make([]func() Check, 0),
	}
	h.ready.Store(true)
	return h
}

// RegisterCheck adds a health check function
func (h *Handler) RegisterCheck(check func() Check) {
	h.checks = append(h.checks, check)
}

// LivenessHandler handles /health/live - is the process running?
func (h *Handler) LivenessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "alive",
	})
}

// ReadinessHandler handles /health/ready - can we accept traffic?
func (h *Handler) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if !h.ready.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "not_ready",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ready",
	})
}

// HealthHandler handles /health - full health check
func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Run all checks
	checks := make([]Check, 0, len(h.checks))
	overallStatus := StatusHealthy

	for _, check := range h.checks {
		result := check()
		checks = append(checks, result)

		if result.Status == StatusUnhealthy {
			overallStatus = StatusUnhealthy
		} else if result.Status == StatusDegraded && overallStatus == StatusHealthy {
			overallStatus = StatusDegraded
		}
	}

	// Build response
	resp := Response{
		Status:    overallStatus,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Uptime:    time.Since(h.startTime).Round(time.Second).String(),
		Version:   h.version,
		Checks:    checks,
		System: map[string]interface{}{
			"go_version": runtime.Version(),
			"goroutines": runtime.NumGoroutine(),
			"cpu_cores":  runtime.NumCPU(),
			"os":         runtime.GOOS,
			"arch":       runtime.GOARCH,
		},
	}

	// Set status code based on health
	if overallStatus == StatusUnhealthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	json.NewEncoder(w).Encode(resp)
}

// RegisterRoutes registers health check routes on a mux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.HealthHandler)
	mux.HandleFunc("/health/live", h.LivenessHandler)
	mux.HandleFunc("/health/ready", h.ReadinessHandler)
}
