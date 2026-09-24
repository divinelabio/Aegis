package geoip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/requestctx"
	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
)

const (
	DefaultCacheTTL  = 24 * time.Hour
	DefaultCacheSize = 100000
	DefaultPoll      = 30 * time.Second
)

type snapshot struct {
	data       []byte
	reader     *geoip2.Reader
	generation string
	dbType     string
	loadedAt   time.Time
}

type cacheEntry struct {
	result    requestctx.GeoResult
	expiresAt time.Time
}

type Status struct {
	Path          string    `json:"path"`
	Loaded        bool      `json:"loaded"`
	Generation    string    `json:"generation,omitempty"`
	DatabaseType  string    `json:"database_type,omitempty"`
	LoadedAt      time.Time `json:"loaded_at,omitempty"`
	LastCheckedAt time.Time `json:"last_checked_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	CacheEntries  int       `json:"cache_entries"`
	CacheHits     uint64    `json:"cache_hits"`
	CacheMisses   uint64    `json:"cache_misses"`
	Unknown       uint64    `json:"unknown"`
}

type Service struct {
	path         string
	cacheTTL     time.Duration
	cacheSize    int
	pollInterval time.Duration
	logger       *zap.Logger
	snapshot     atomic.Pointer[snapshot]
	cacheMu      sync.Mutex
	cache        map[string]cacheEntry
	statusMu     sync.RWMutex
	lastChecked  time.Time
	lastError    string
	cacheHits    atomic.Uint64
	cacheMisses  atomic.Uint64
	unknown      atomic.Uint64
}

func New(path string, cacheTTL time.Duration, cacheSize int, logger *zap.Logger) *Service {
	if cacheTTL <= 0 {
		cacheTTL = DefaultCacheTTL
	}
	if cacheSize <= 0 {
		cacheSize = DefaultCacheSize
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	s := &Service{path: strings.TrimSpace(path), cacheTTL: cacheTTL, cacheSize: cacheSize, pollInterval: DefaultPoll, logger: logger, cache: make(map[string]cacheEntry)}
	if err := s.Reload(); err != nil {
		logger.Warn("GeoIP database unavailable; country checks will fail open", zap.Error(err))
	}
	return s
}

func (s *Service) Start(ctx context.Context) {
	if s == nil || s.path == "" {
		return
	}
	go func() {
		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if changed, err := s.changedOnDisk(); err != nil {
					s.setError(err)
				} else if changed {
					if err := s.Reload(); err != nil {
						s.logger.Error("GeoIP database reload rejected; keeping last known good snapshot", zap.Error(err))
					}
				}
			}
		}
	}()
}

func (s *Service) changedOnDisk() (bool, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(data)
	current := s.snapshot.Load()
	return current == nil || current.generation != hex.EncodeToString(sum[:]), nil
}

func (s *Service) Reload() error {
	if s == nil || s.path == "" {
		return fmt.Errorf("geoip database path is empty")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		s.setError(err)
		return err
	}
	reader, err := geoip2.FromBytes(data)
	if err != nil {
		s.setError(err)
		return fmt.Errorf("invalid country mmdb: %w", err)
	}
	dbType := reader.Metadata().DatabaseType
	if !isCountryDatabase(dbType) {
		err = fmt.Errorf("unsupported country mmdb type %q", dbType)
		s.setError(err)
		return err
	}
	if _, err = reader.Country(net.ParseIP("8.8.8.8")); err != nil {
		s.setError(err)
		return fmt.Errorf("country mmdb test lookup failed: %w", err)
	}
	sum := sha256.Sum256(data)
	next := &snapshot{data: data, reader: reader, generation: hex.EncodeToString(sum[:]), dbType: dbType, loadedAt: time.Now().UTC()}
	s.snapshot.Store(next)
	s.cacheMu.Lock()
	clear(s.cache)
	s.cacheMu.Unlock()
	s.statusMu.Lock()
	s.lastChecked = time.Now().UTC()
	s.lastError = ""
	s.statusMu.Unlock()
	s.logger.Info("GeoIP database activated", zap.String("path", s.path), zap.String("generation", next.generation), zap.String("database_type", dbType))
	return nil
}

func isCountryDatabase(dbType string) bool {
	lower := strings.ToLower(dbType)
	return strings.Contains(lower, "country") || strings.Contains(lower, "city") || strings.Contains(lower, "location") || strings.Contains(lower, "enterprise")
}

func (s *Service) Lookup(ipText string) requestctx.GeoResult {
	ip := net.ParseIP(strings.TrimSpace(ipText))
	if ip == nil {
		return requestctx.GeoResult{State: requestctx.GeoError, Error: "invalid IP address"}
	}
	if !IsPublicIP(ip) {
		return requestctx.GeoResult{State: requestctx.GeoPrivate}
	}
	current := s.snapshot.Load()
	if current == nil {
		s.unknown.Add(1)
		return requestctx.GeoResult{State: requestctx.GeoError, Error: "country database is not loaded"}
	}
	key, now := current.generation+":"+ip.String(), time.Now()
	s.cacheMu.Lock()
	if entry, ok := s.cache[key]; ok && now.Before(entry.expiresAt) {
		s.cacheMu.Unlock()
		s.cacheHits.Add(1)
		return entry.result
	}
	s.cacheMu.Unlock()
	s.cacheMisses.Add(1)
	record, err := current.reader.Country(ip)
	result := requestctx.GeoResult{Generation: current.generation}
	if err != nil {
		result.State, result.Error = requestctx.GeoError, err.Error()
		s.unknown.Add(1)
	} else if code := strings.ToUpper(strings.TrimSpace(record.Country.IsoCode)); code != "" {
		result.State, result.Country = requestctx.GeoKnown, code
	} else {
		result.State = requestctx.GeoNotFound
		s.unknown.Add(1)
	}
	s.cacheMu.Lock()
	if len(s.cache) >= s.cacheSize {
		for oldKey := range s.cache {
			delete(s.cache, oldKey)
			break
		}
	}
	s.cache[key] = cacheEntry{result: result, expiresAt: now.Add(s.cacheTTL)}
	s.cacheMu.Unlock()
	return result
}

func (s *Service) Status() Status {
	status := Status{Path: s.path, CacheHits: s.cacheHits.Load(), CacheMisses: s.cacheMisses.Load(), Unknown: s.unknown.Load()}
	if current := s.snapshot.Load(); current != nil {
		status.Loaded, status.Generation, status.DatabaseType, status.LoadedAt = true, current.generation, current.dbType, current.loadedAt
	}
	s.statusMu.RLock()
	status.LastCheckedAt, status.LastError = s.lastChecked, s.lastError
	s.statusMu.RUnlock()
	s.cacheMu.Lock()
	status.CacheEntries = len(s.cache)
	s.cacheMu.Unlock()
	return status
}

func (s *Service) setError(err error) {
	s.statusMu.Lock()
	s.lastChecked, s.lastError = time.Now().UTC(), err.Error()
	s.statusMu.Unlock()
}

var nonPublicNetworks = mustNetworks([]string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "2001:db8::/32", "ff00::/8",
})

func mustNetworks(values []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		out = append(out, network)
	}
	return out
}
func IsPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() {
		return false
	}
	for _, network := range nonPublicNetworks {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}
