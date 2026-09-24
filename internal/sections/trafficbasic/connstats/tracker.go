package connstats

import (
	"sync"
	"time"
)

// Config holds connection stats configuration
type Config struct {
	Enabled bool
}

// Tracker tracks active connections details
type Tracker struct {
	config Config
	mu     sync.RWMutex

	// Active connections metadata
	// Map of remoteAddr -> start time
	activeConns map[string]time.Time
}

// New creates a new connection tracker
func New(cfg Config) *Tracker {
	return &Tracker{
		config:      cfg,
		activeConns: make(map[string]time.Time),
	}
}

func (t *Tracker) UpdateConfig(cfg Config) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.config = cfg
	if !cfg.Enabled {
		t.activeConns = make(map[string]time.Time)
	}
}

// TrackConnection starts tracking a connection
func (t *Tracker) TrackConnection(remoteAddr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.config.Enabled {
		return
	}
	t.activeConns[remoteAddr] = time.Now()
}

// ReleaseConnection stops tracking and returns duration
func (t *Tracker) ReleaseConnection(remoteAddr string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	start, exists := t.activeConns[remoteAddr]
	if !exists {
		return 0
	}

	delete(t.activeConns, remoteAddr)
	return time.Since(start)
}

// GetActiveCount returns number of active tracked connections
func (t *Tracker) GetActiveCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.activeConns)
}
