// Package trafficbasic is the Community Traffic Control implementation.
package trafficbasic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	infraConfig "github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/geoip"
	"github.com/divinelab-io/aegis/internal/infra/requestctx"
	"github.com/divinelab-io/aegis/internal/infra/storage"
	"github.com/divinelab-io/aegis/internal/infra/transport"
	"github.com/google/uuid"
	"github.com/divinelab-io/aegis/internal/sections"
	"github.com/divinelab-io/aegis/internal/sections/trafficbasic/blacklist"
	"github.com/divinelab-io/aegis/internal/sections/trafficbasic/connstats"
	"github.com/divinelab-io/aegis/internal/sections/trafficbasic/ratelimit"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
)

const (
	SectionID   = "traffic_control"
	SectionName = "Traffic Control"
)

var paidKeys = []string{"application_flood", "ddos", "trusted_exceptions", "challenge", "reputation"}

func toInterfaceSlice(val interface{}) []interface{} {
	if val == nil {
		return nil
	}
	switch s := val.(type) {
	case []interface{}:
		return s
	case []map[string]interface{}:
		out := make([]interface{}, len(s))
		for i, item := range s {
			out[i] = item
		}
		return out
	case []BlockEntryConfig:
		out := make([]interface{}, len(s))
		for i, item := range s {
			out[i] = item
		}
		return out
	default:
		rv := reflect.ValueOf(val)
		if rv.Kind() == reflect.Slice {
			out := make([]interface{}, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				out[i] = rv.Index(i).Interface()
			}
			return out
		}
		return nil
	}
}

func extractExceptionIDs(list []interface{}) map[string]bool {
	ids := make(map[string]bool)
	for _, item := range list {
		if m, ok := item.(map[string]interface{}); ok {
			if id, ok := m["id"].(string); ok && id != "" {
				ids[id] = true
			}
		}
	}
	return ids
}

func isPaidFeatureActivated(key string, requested, currentVal interface{}) bool {
	if requested == nil {
		return false
	}
	switch key {
	case "application_flood", "ddos", "challenge", "reputation":
		if m, ok := requested.(map[string]interface{}); ok {
			if enabled, ok := m["enabled"].(bool); ok && enabled {
				return true
			}
			if s, ok := m["enabled"].(string); ok && strings.EqualFold(s, "true") {
				return true
			}
		}
		return false
	case "trusted_exceptions":
		reqList := toInterfaceSlice(requested)
		if len(reqList) == 0 {
			return false
		}
		curList := toInterfaceSlice(currentVal)
		if len(reqList) > len(curList) {
			return true
		}
		currentIDs := extractExceptionIDs(curList)
		for _, item := range reqList {
			if m, ok := item.(map[string]interface{}); ok {
				if id, ok := m["id"].(string); ok && id != "" && !currentIDs[id] {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

type Config struct {
	Geo       infraConfig.GeoConfig `json:"geo" mapstructure:"geo"`
	Blacklist struct {
		Enabled bool               `json:"enabled" mapstructure:"enabled"`
		IPs     []string           `json:"ips" mapstructure:"ips"`
		CIDRs   []string           `json:"cidrs" mapstructure:"cidrs"`
		Entries []BlockEntryConfig `json:"entries" mapstructure:"entries"`
	} `json:"blacklist" mapstructure:"blacklist"`
	RateLimit struct {
		Enabled         bool                       `json:"enabled" mapstructure:"enabled"`
		DefaultRate     int                        `json:"default_rate" mapstructure:"default_rate"`
		DefaultBurst    int                        `json:"default_burst" mapstructure:"default_burst"`
		Window          string                     `json:"window" mapstructure:"window"`
		Algorithm       string                     `json:"algorithm" mapstructure:"algorithm"`
		KeyBy           string                     `json:"key_by" mapstructure:"key_by"`
		Action          string                     `json:"action" mapstructure:"action"`
		BypassStatic    bool                       `json:"bypass_static" mapstructure:"bypass_static"`
		BypassKnownBots bool                       `json:"bypass_known_bots" mapstructure:"bypass_known_bots"`
		CookieName      string                     `json:"cookie_name" mapstructure:"cookie_name"`
		HeaderName      string                     `json:"header_name" mapstructure:"header_name"`
		PathRules       []ratelimit.PathRuleConfig `json:"path_rules" mapstructure:"path_rules"`
		PathOverrides   []ratelimit.PathRuleConfig `json:"path_overrides" mapstructure:"path_overrides"`
	} `json:"ratelimit" mapstructure:"ratelimit"`
	Connections struct {
		Enabled bool `json:"enabled" mapstructure:"enabled"`
	} `json:"conn_stats" mapstructure:"conn_stats"`
}

// BlockEntryConfig gives Community the same explicit expiry semantics used by
// the Traffic Control UI. A capability must either enforce a saved entry or be
// hidden; it must never be a persistence-only affordance.
type BlockEntryConfig struct {
	Target    string    `json:"target" yaml:"target" mapstructure:"target"`
	ExpiresAt time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty" mapstructure:"expires_at"`
	Note      string    `json:"note,omitempty" yaml:"note,omitempty" mapstructure:"note"`
}

type Section struct {
	logger           *zap.Logger
	mu               sync.RWMutex
	enabled          bool
	protection       int
	settings         map[string]interface{}
	config           Config
	blacklist        *blacklist.Blacklist
	limiter          *ratelimit.Limiter
	connections      *connstats.Tracker
	geoService       *geoip.Service
	geoBlocker       *geoip.Blocker
	total            atomic.Int64
	blocked          atomic.Int64
	allowed          atomic.Int64
	blacklistBlocked atomic.Int64
	geoBlocked       atomic.Int64
	rateLimited      atomic.Int64
	started          atomic.Bool
	stopChan         chan struct{}
	stopOnce         sync.Once
	persist          sections.SectionConfigPersister
}

func (*Section) AlwaysInstallMiddleware() bool { return true }

func New(logger *zap.Logger, geoService *geoip.Service, persisters ...sections.SectionConfigPersister) *Section {
	if logger == nil {
		logger = zap.NewNop()
	}
	section := &Section{logger: logger, enabled: true, protection: 3, blacklist: blacklist.New(), geoService: geoService}
	section.apply(defaultConfig(), map[string]interface{}{})
	if len(persisters) > 0 {
		section.persist = persisters[0]
	}
	return section
}

func defaultConfig() Config {
	var config Config
	config.Blacklist.Enabled = true
	config.Geo.DBPath = "./data/dbip-country.mmdb"
	config.Geo.CacheTTL = "24h"
	config.Geo.Mode = "blocklist"
	config.RateLimit.Enabled = true
	config.RateLimit.DefaultRate = 60
	config.RateLimit.DefaultBurst = 10
	config.RateLimit.Window = "1m"
	config.RateLimit.Algorithm = "token_bucket"
	config.RateLimit.KeyBy = "ip"
	config.Connections.Enabled = true
	return config
}

func (s *Section) Name() string { return SectionName }
func (s *Section) ID() string   { return SectionID }
func (s *Section) Description() string {
	return "Geo-blocking, manual blacklist, rate limiting, and connection statistics"
}
func (s *Section) Icon() string { return "shield-check" }

func (s *Section) Init(input sections.SectionConfig) error {
	config := defaultConfig()
	settings := cloneMap(input.Settings)
	if rl, ok := settings["rate_limit"]; ok && settings["ratelimit"] == nil {
		settings["ratelimit"] = rl
	}
	if cs, ok := settings["connections"]; ok && settings["conn_stats"] == nil {
		settings["conn_stats"] = cs
	}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &config,
		TagName: "mapstructure",
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			trafficBasicStringToTimeHook(),
		),
	})
	if err != nil {
		return err
	}
	if err := decoder.Decode(settings); err != nil {
		return err
	}
	if err := validate(config); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled, s.protection = input.Enabled, input.ProtectionLevel
	s.apply(config, cloneMap(input.Settings))
	return nil
}

func trafficBasicStringToTimeHook() mapstructure.DecodeHookFuncType {
	timeType := reflect.TypeOf(time.Time{})
	return func(from reflect.Type, to reflect.Type, value interface{}) (interface{}, error) {
		if from.Kind() != reflect.String || to != timeType {
			return value, nil
		}
		return time.Parse(time.RFC3339, value.(string))
	}
}

func (s *Section) Start(ctx context.Context) error {
	if s.started.Swap(true) {
		return nil
	}
	s.mu.Lock()
	s.stopChan = make(chan struct{})
	s.stopOnce = sync.Once{}
	stopChan := s.stopChan
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.RLock()
				bl := s.blacklist
				rl := s.limiter
				s.mu.RUnlock()
				if bl != nil {
					bl.CleanExpired()
				}
				if rl != nil {
					rl.Cleanup()
				}
			}
		}
	}()

	return nil
}

func (s *Section) Stop(context.Context) error {
	s.started.Store(false)
	s.mu.Lock()
	stopChan := s.stopChan
	s.mu.Unlock()
	if stopChan != nil {
		s.stopOnce.Do(func() {
			close(stopChan)
		})
	}
	return nil
}
func (s *Section) Reload(config sections.SectionConfig) error { return s.Init(config) }

func (s *Section) Enabled() bool         { s.mu.RLock(); defer s.mu.RUnlock(); return s.enabled }
func (s *Section) SetEnabled(value bool) { s.mu.Lock(); s.enabled = value; s.mu.Unlock() }

func (s *Section) GetConfig() sections.SectionConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sections.SectionConfig{Enabled: s.enabled, ProtectionLevel: s.protection, Settings: cloneMap(s.settings)}
}

func (s *Section) UpdateConfig(input sections.SectionConfig) error {
	s.mu.RLock()
	current := cloneMap(s.settings)
	s.mu.RUnlock()
	for _, key := range paidKeys {
		requested, exists := input.Settings[key]
		if !exists {
			continue
		}
		currentVal := current[key]
		if currentVal == nil && key == "application_flood" {
			currentVal = current["ddos"]
		} else if currentVal == nil && key == "ddos" {
			currentVal = current["application_flood"]
		}

		if isPaidFeatureActivated(key, requested, currentVal) {
			return sections.ErrFeatureNotEntitled
		}

		if currentVal != nil {
			input.Settings[key] = currentVal
		}
	}
	if s.persist != nil {
		if err := s.persist(SectionID, input); err != nil {
			return err
		}
	}
	return s.Init(input)
}

func (s *Section) apply(config Config, settings map[string]interface{}) {
	s.config = config
	s.settings = settings
	s.blacklist = blacklist.New()
	s.blacklist.SetEnabled(config.Blacklist.Enabled)
	for _, value := range config.Blacklist.IPs {
		_ = s.blacklist.AddIP(value, "manual", 0)
	}
	for _, value := range config.Blacklist.CIDRs {
		_ = s.blacklist.AddCIDR(value, "manual", 0)
	}
	for _, entry := range config.Blacklist.Entries {
		remaining := time.Until(entry.ExpiresAt)
		if entry.ExpiresAt.IsZero() {
			remaining = 0
		} else if remaining <= 0 {
			continue
		}
		reason := strings.TrimSpace(entry.Note)
		if reason == "" {
			reason = "manual"
		}
		if strings.Contains(entry.Target, "/") {
			_ = s.blacklist.AddCIDR(entry.Target, reason, remaining)
		} else {
			_ = s.blacklist.AddIP(entry.Target, reason, remaining)
		}
	}
	pathRules := append([]ratelimit.PathRuleConfig(nil), config.RateLimit.PathRules...)
	if len(pathRules) == 0 && len(config.RateLimit.PathOverrides) > 0 {
		pathRules = append(pathRules, config.RateLimit.PathOverrides...)
	}
	s.limiter = ratelimit.New(ratelimit.Config{
		Enabled:         config.RateLimit.Enabled,
		DefaultRate:     config.RateLimit.DefaultRate,
		DefaultBurst:    config.RateLimit.DefaultBurst,
		Window:          config.RateLimit.Window,
		Algorithm:       config.RateLimit.Algorithm,
		KeyBy:           config.RateLimit.KeyBy,
		Action:          config.RateLimit.Action,
		BypassStatic:    config.RateLimit.BypassStatic,
		BypassKnownBots: config.RateLimit.BypassKnownBots,
		CookieName:      config.RateLimit.CookieName,
		HeaderName:      config.RateLimit.HeaderName,
		PathRules:       pathRules,
	})
	s.connections = connstats.New(connstats.Config{Enabled: config.Connections.Enabled})
	s.geoBlocker = geoip.NewBlocker(policyConfig(config.Geo))
}

func validate(config Config) error {
	if config.RateLimit.DefaultRate < 0 || config.RateLimit.DefaultBurst < 0 {
		return errors.New("rate limit and burst must be non-negative")
	}
	if config.RateLimit.Window != "" {
		if _, err := time.ParseDuration(config.RateLimit.Window); err != nil {
			return errors.New("rate-limit window is invalid")
		}
	}
	for _, value := range config.Blacklist.IPs {
		if net.ParseIP(value) == nil {
			return errors.New("blacklist contains an invalid IP")
		}
	}
	for _, value := range config.Blacklist.CIDRs {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return errors.New("blacklist contains an invalid CIDR")
		}
	}
	for _, entry := range config.Blacklist.Entries {
		if net.ParseIP(entry.Target) == nil {
			if _, _, err := net.ParseCIDR(entry.Target); err != nil {
				return errors.New("blacklist contains an invalid entry target")
			}
		}
	}
	policy := &infraConfig.RouteCountryPolicy{Enabled: config.Geo.Enabled, AllowCountries: config.Geo.AllowCountries, BlockCountries: config.Geo.BlockCountries, Groups: append(append([]string{}, config.Geo.Groups...), config.Geo.Regions...), Exceptions: config.Geo.Exceptions}
	if err := infraConfig.ValidateRouteCountryPolicy(policy); err != nil {
		return fmt.Errorf("geo: %w", err)
	}
	if config.Geo.CacheTTL != "" {
		if _, err := time.ParseDuration(config.Geo.CacheTTL); err != nil {
			return fmt.Errorf("geo cache_ttl: %w", err)
		}
	}
	return nil
}

func (s *Section) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Enabled() {
			next.ServeHTTP(w, r)
			return
		}
		if !transport.RouteAllowsSection(r, SectionID) {
			next.ServeHTTP(w, r)
			return
		}
		s.total.Add(1)
		clientIP := requestctx.ClientIP(r)
		if clientIP == "" {
			clientIP = remoteHost(r.RemoteAddr)
		}
		s.mu.RLock()
		list, limiter, tracker, geoBlocker := s.blacklist, s.limiter, s.connections, s.geoBlocker
		s.mu.RUnlock()
		tracker.TrackConnection(r.RemoteAddr)
		defer tracker.ReleaseConnection(r.RemoteAddr)

		if blocked, _ := list.IsBlocked(clientIP); blocked {
			s.blocked.Add(1)
			s.blacklistBlocked.Add(1)
			w.Header().Set("X-Aegis-Traffic", "blacklisted")
			reqID := r.Header.Get("X-Request-Id")
			if reqID == "" {
				reqID = uuid.NewString()
			}
			storage.LogSectionEvent(storage.SectionEventLog{
				ID:         uuid.NewString(),
				Timestamp:  time.Now().Unix(),
				Section:    "traffic_control",
				EventType:  "blacklist",
				Action:     "block",
				ClientIP:   clientIP,
				Method:     r.Method,
				Path:       r.URL.Path,
				StatusCode: http.StatusForbidden,
				RuleName:   "Manual Blacklist",
				RequestID:  reqID,
				UserAgent:  r.UserAgent(),
			})
			if !transport.WriteConfiguredErrorPage(w, r, http.StatusForbidden) {
				http.Error(w, "Access denied", http.StatusForbidden)
			}
			return
		}

		if geoBlocker != nil {
			identity, _ := requestctx.FromRequest(r)
			geoData := identity.Geo
			if geoData.State != requestctx.GeoKnown && s.geoService != nil {
				geoData = s.geoService.Lookup(clientIP)
			}
			if blocked, _, _ := geoBlocker.IsBlocked(clientIP, geoData, routeCountryPolicy(r)); blocked {
				s.blocked.Add(1)
				s.geoBlocked.Add(1)
				w.Header().Set("X-Aegis-Traffic", "geo-blocked")
				reqID := r.Header.Get("X-Request-Id")
				if reqID == "" {
					reqID = uuid.NewString()
				}
				storage.LogSectionEvent(storage.SectionEventLog{
					ID:         uuid.NewString(),
					Timestamp:  time.Now().Unix(),
					Section:    "traffic_control",
					EventType:  "geo_block",
					Action:     "block",
					ClientIP:   clientIP,
					Country:    geoData.Country,
					Method:     r.Method,
					Path:       r.URL.Path,
					StatusCode: http.StatusForbidden,
					RuleName:   "Country Policy",
					RequestID:  reqID,
					UserAgent:  r.UserAgent(),
				})
				if !transport.WriteConfiguredErrorPage(w, r, http.StatusForbidden) {
					http.Error(w, "Access denied by country policy", http.StatusForbidden)
				}
				return
			}
		}

		if limiter != nil {
			allowed, remaining, matchedRule := limiter.IsAllowed(r)
			effectiveRate := s.config.RateLimit.DefaultRate
			effectiveWindow := limiter.Window()
			action := s.config.RateLimit.Action
			if matchedRule != nil {
				effectiveRate = matchedRule.Rate
				effectiveWindow = matchedRule.Window
				if matchedRule.Action != "" {
					action = matchedRule.Action
				}
			}
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(effectiveRate))
			if remaining >= 0 {
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			} else {
				w.Header().Set("X-RateLimit-Remaining", "0")
			}
			resetSecs := int(effectiveWindow.Seconds())
			if resetSecs <= 0 {
				resetSecs = 1
			}
			w.Header().Set("X-RateLimit-Reset", strconv.Itoa(resetSecs))

			if !allowed {
				if strings.EqualFold(action, "dry_run") {
					// Dry run mode: observe and report without blocking
				} else {
					s.blocked.Add(1)
					s.rateLimited.Add(1)
					w.Header().Set("X-Aegis-Traffic", "rate-limited")
					w.Header().Set("Retry-After", strconv.Itoa(resetSecs))
					reqID := r.Header.Get("X-Request-Id")
					if reqID == "" {
						reqID = uuid.NewString()
					}
					storage.LogSectionEvent(storage.SectionEventLog{
						ID:         uuid.NewString(),
						Timestamp:  time.Now().Unix(),
						Section:    "traffic_control",
						EventType:  "rate_limit",
						Action:     "ratelimit",
						ClientIP:   clientIP,
						Method:     r.Method,
						Path:       r.URL.Path,
						StatusCode: http.StatusTooManyRequests,
						RuleName:   "Rate Limit Exceeded",
						RequestID:  reqID,
						UserAgent:  r.UserAgent(),
					})
					if !transport.WriteConfiguredErrorPage(w, r, http.StatusTooManyRequests) {
						http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
					}
					return
				}
			}
		}

		s.allowed.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (s *Section) Stats() sections.SectionStats {
	s.mu.RLock()
	connections := s.connections.GetActiveCount()
	s.mu.RUnlock()
	return sections.SectionStats{
		Name:            SectionName,
		Enabled:         s.Enabled(),
		TotalRequests:   s.total.Load(),
		BlockedRequests: s.blocked.Load(),
		AllowedRequests: s.allowed.Load(),
		UpdatedAt:       time.Now().UTC(),
		Custom: map[string]interface{}{
			"active_connections": connections,
			"rate_limited":       s.rateLimited.Load(),
			"blacklist_blocked":  s.blacklistBlocked.Load(),
			"geo_blocked":        s.geoBlocked.Load(),
		},
	}
}

func (s *Section) Health() sections.HealthStatus {
	state := sections.HealthStateHealthy
	message := "Community traffic controls are operational"
	if s.Enabled() && !s.started.Load() {
		state, message = sections.HealthStateUnhealthy, "section is not started"
	} else if s.config.Geo.Enabled && (s.geoService == nil || !s.geoService.Status().Loaded) {
		state, message = sections.HealthStateDegraded, "GeoIP database unavailable; country policy is fail-open"
	}
	return sections.HealthStatus{Status: state, Message: message, CheckedAt: time.Now().UTC()}
}

func (s *Section) GetConfigSchema() sections.ConfigSchema {
	return sections.ConfigSchema{Groups: []sections.ConfigGroup{
		{ID: "geo", Name: "Geo-blocking", Fields: []sections.ConfigField{{ID: "geo_enabled", Key: "geo.enabled", Label: "Enable Geo-blocking", Type: sections.ConfigTypeToggle, Default: false}, {ID: "allow_countries", Key: "geo.allow_countries", Label: "Allowed countries", Type: sections.ConfigTypeTags, Default: []string{}}, {ID: "block_countries", Key: "geo.block_countries", Label: "Blocked countries", Type: sections.ConfigTypeTags, Default: []string{}}}},
		{ID: "blacklist", Name: "Manual blacklist", Fields: []sections.ConfigField{{ID: "blacklist_enabled", Key: "blacklist.enabled", Label: "Enable blacklist", Type: sections.ConfigTypeToggle, Default: true}, {ID: "blacklist_ips", Key: "blacklist.ips", Label: "Blocked IPs", Type: sections.ConfigTypeIPList, Default: []string{}}}},
		{ID: "ratelimit", Name: "Rate limiting", Fields: []sections.ConfigField{{ID: "ratelimit_enabled", Key: "ratelimit.enabled", Label: "Enable rate limiting", Type: sections.ConfigTypeToggle, Default: true}, {ID: "default_rate", Key: "ratelimit.default_rate", Label: "Requests per window", Type: sections.ConfigTypeNumber, Default: 60, Min: 1}, {ID: "window", Key: "ratelimit.window", Label: "Window", Type: sections.ConfigTypeDuration, Default: "1s"}}},
	}}
}

func (s *Section) RegisterRoutes(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(prefix+"/stats", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Stats()) })
	mux.HandleFunc(prefix+"/dashboard", s.handleDashboard)
	mux.HandleFunc(prefix+"/dashboard/", s.handleDashboard)
	mux.HandleFunc(prefix+"/geo/status", s.handleGeoStatus)
	mux.HandleFunc(prefix+"/config", s.handleConfig)
	mux.HandleFunc(prefix+"/capabilities", s.handleCapabilities)
	mux.HandleFunc(prefix+"/operations", s.handleOperations)
	mux.HandleFunc(prefix+"/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Health()) })
	mux.HandleFunc(prefix+"/blacklist", s.handleBlacklist)
	mux.HandleFunc(prefix+"/blocked", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		bl := s.blacklist
		s.mu.RUnlock()
		var ips []*blacklist.BlockEntry
		var cidrs []*blacklist.CIDREntry
		if bl != nil {
			ips = bl.ListIPs()
			cidrs = bl.ListCIDRs()
		}
		writeJSON(w, map[string]interface{}{
			"blocked": ips,
			"cidrs":   cidrs,
			"count":   len(ips) + len(cidrs),
		})
	})
	mux.HandleFunc(prefix+"/top-ips", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"ips": []interface{}{}})
	})
	mux.HandleFunc(prefix+"/countries", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		blocker := s.geoBlocker
		geoCfg := s.config.Geo
		s.mu.RUnlock()
		var status geoip.PolicyStatus
		if blocker != nil {
			status = blocker.Status()
		}
		writeJSON(w, map[string]interface{}{
			"mode":            geoCfg.Mode,
			"block_countries": status.BlockCountries,
			"allow_countries": status.AllowCountries,
			"groups":          status.Groups,
		})
	})
	mux.HandleFunc(prefix+"/reputation/feed", s.handleUnifiedThreatFeed)
	mux.HandleFunc(prefix+"/reputation/feed/refresh", s.handleUnifiedThreatFeedRefresh)
	mux.HandleFunc(prefix+"/reputation/cti", s.handleCTIFeed)
	mux.HandleFunc(prefix+"/reputation/cti/refresh", s.handleCTIFeedRefresh)
}

func (s *Section) handleOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	c := s.config
	connections := s.connections.GetActiveCount()
	s.mu.RUnlock()

	checkedAt := time.Now().UTC()
	var blacklistIPs, blacklistCIDRs int
	if s.blacklist != nil {
		blacklistIPs, blacklistCIDRs = s.blacklist.Count()
	}
	var rateStats map[string]interface{}
	if s.limiter != nil {
		rateStats = s.limiter.GetStats()
	}

	geoStatus := map[string]interface{}{
		"enabled":     c.Geo.Enabled,
		"db_loaded":   false,
		"lookup_mode": "none",
	}
	if s.geoService != nil {
		st := s.geoService.Status()
		geoStatus["db_loaded"] = st.Loaded
		geoStatus["path"] = st.Path
		geoStatus["last_loaded_at"] = st.LoadedAt
		geoStatus["last_error"] = st.LastError
	}

	health := s.Health()

	response := map[string]interface{}{
		"health": health,
		"revision": map[string]interface{}{
			"active":     "community",
			"updated_at": checkedAt.Format(time.RFC3339),
		},
		"persistence": map[string]interface{}{
			"configured": s.persist != nil,
		},
		"modules": map[string]interface{}{
			"blacklist": map[string]interface{}{
				"enabled":       c.Blacklist.Enabled,
				"exact_entries": blacklistIPs,
				"cidr_entries":  blacklistCIDRs,
			},
			"ratelimit": rateStats,
			"geo":       geoStatus,
		},
		"state": map[string]interface{}{
			"ratelimit_entries":  0,
			"ratelimit_capacity": 10000,
			"active_connections": connections,
		},
		"telemetry": map[string]interface{}{
			"storage_available": true,
			"freshness":         "live",
		},
		"freshness": map[string]interface{}{
			"geo_database_age_seconds": 0,
		},
		"module_readiness": map[string]string{
			"blacklist": "ready",
			"ratelimit": "ready",
			"geo":       "ready",
		},
		"latency": map[string]interface{}{
			"samples":    0,
			"average_ms": 0.0,
			"p50_ms":     0.0,
			"p95_ms":     0.0,
			"p99_ms":     0.0,
		},
	}
	if rateStats != nil {
		if entries, ok := rateStats["active_buckets"]; ok {
			response["state"].(map[string]interface{})["ratelimit_entries"] = entries
		}
		if cap, ok := rateStats["max_states"]; ok {
			response["state"].(map[string]interface{})["ratelimit_capacity"] = cap
		}
	}
	writeJSON(w, response)
}

func (s *Section) handleUnifiedThreatFeed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	writeJSON(w, map[string]interface{}{
		"status":      "error",
		"error":       "IP Reputation & DivineLab CTI threat feeds require an active Professional or Enterprise license",
		"tier":        "professional",
		"upgrade_url": "/admin/licensing",
	})
}

func (s *Section) handleUnifiedThreatFeedRefresh(w http.ResponseWriter, r *http.Request) {
	s.handleUnifiedThreatFeed(w, r)
}

func (s *Section) handleCTIFeed(w http.ResponseWriter, r *http.Request) {
	s.handleUnifiedThreatFeed(w, r)
}

func (s *Section) handleCTIFeedRefresh(w http.ResponseWriter, r *http.Request) {
	s.handleUnifiedThreatFeed(w, r)
}


func (s *Section) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{
		"schema_version": 1,
		"edition":        "community",
		"features": map[string]map[string]interface{}{
			"blacklist":          {"available": true, "configurable": true, "tier": "community"},
			"geo":                {"available": true, "configurable": true, "tier": "community"},
			"ratelimit":          {"available": true, "configurable": true, "tier": "community"},
			"conn_stats":         {"available": true, "configurable": true, "tier": "community"},
			"reputation":         {"available": false, "configurable": false, "tier": "professional"},
			"application_flood":  {"available": false, "configurable": false, "tier": "professional", "layer": "http"},
			"network_layer":      {"available": false, "configurable": false, "tier": "external_integration_required", "reason": "Network and L4 mitigation must be supplied by an upstream edge provider."},
			"upstream_health":    {"available": false, "configurable": false, "tier": "future", "reason": "Adaptive upstream-health hardening is not implemented."},
			"trusted_exceptions": {"available": false, "configurable": false, "tier": "professional"},
			"challenge":          {"available": false, "configurable": false, "tier": "professional"},
		},
	})
}

func (s *Section) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config := s.GetConfig()
		response := cloneMap(config.Settings)
		response["enabled"] = config.Enabled
		response["protection_level"] = config.ProtectionLevel
		if rl, ok := response["ratelimit"]; ok && response["rate_limit"] == nil {
			response["rate_limit"] = rl
		}
		if flood, ok := response["ddos"]; ok && response["application_flood"] == nil {
			response["application_flood"] = flood
		}
		if reputationConfig, ok := response["reputation"].(map[string]interface{}); ok {
			if cti, ok := reputationConfig["cti"].(map[string]interface{}); ok {
				apiKey, _ := cti["api_key"].(string)
				delete(cti, "api_key")
				delete(cti, "clear_api_key")
				cti["api_key_configured"] = apiKey != ""
			}
		}
		delete(response, "priority")
		writeJSON(w, response)
	case http.MethodPut:
		var incoming map[string]interface{}
		bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		bodyBytes = bytes.TrimPrefix(bodyBytes, []byte("\xef\xbb\xbf"))
		decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
		if err := decoder.Decode(&incoming); err != nil {
			http.Error(w, "invalid configuration: "+err.Error(), http.StatusBadRequest)
			return
		}
		var trailing interface{}
		if err := decoder.Decode(&trailing); err != io.EOF {
			http.Error(w, "invalid configuration: trailing characters", http.StatusBadRequest)
			return
		}
		allowed := map[string]bool{
			"enabled": true, "protection_level": true, "blacklist": true, "geo": true,
			"ratelimit": true, "rate_limit": true, "conn_stats": true, "connections": true,
			"control": true, "priority": true, "ddos": true,
			// Preserve the explicit entitlement error for known paid-only keys.
			"reputation": true, "application_flood": true, "trusted_exceptions": true, "challenge": true,
		}
		for key := range incoming {
			if !allowed[key] {
				http.Error(w, "invalid configuration field", http.StatusBadRequest)
				return
			}
		}
		current := s.GetConfig()
		input := sections.SectionConfig{Enabled: current.Enabled, ProtectionLevel: current.ProtectionLevel, Settings: cloneMap(current.Settings)}
		if enabled, ok := incoming["enabled"].(bool); ok {
			input.Enabled = enabled
			delete(incoming, "enabled")
		}
		if level, ok := numericInt(incoming["protection_level"]); ok {
			input.ProtectionLevel = level
			delete(incoming, "protection_level")
		}
		if rl, ok := incoming["rate_limit"]; ok {
			if _, exists := incoming["ratelimit"]; !exists {
				incoming["ratelimit"] = rl
			}
		}
		if cs, ok := incoming["connections"]; ok {
			if _, exists := incoming["conn_stats"]; !exists {
				incoming["conn_stats"] = cs
			}
		}
		if flood, ok := incoming["application_flood"]; ok {
			if _, exists := incoming["ddos"]; !exists {
				incoming["ddos"] = flood
			}
		}
		for key, value := range incoming {
			input.Settings[key] = value
		}
		if err := s.UpdateConfig(input); err != nil {
			if errors.Is(err, sections.ErrFeatureNotEntitled) {
				writeFeatureError(w)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := map[string]interface{}{"success": true, "status": "ok"}
		if ctrl, ok := s.GetConfig().Settings["control"].(map[string]interface{}); ok {
			if rev, ok := ctrl["revision"].(string); ok {
				resp["revision"] = rev
				w.Header().Set("X-Aegis-Config-Revision", rev)
			}
			if cs, ok := ctrl["checksum"].(string); ok {
				resp["checksum"] = cs
			}
		}
		writeJSON(w, resp)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Section) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	stats := s.Stats()
	if strings.Contains(r.URL.Path, "/events") {
		writeJSON(w, map[string]interface{}{"events": []interface{}{}, "total": 0})
		return
	}

	reasons := []map[string]interface{}{}
	blCount := s.blacklistBlocked.Load()
	if blCount > 0 {
		reasons = append(reasons, map[string]interface{}{"key": "blacklist", "label": "IP Blacklist", "count": blCount})
	}
	geoCount := s.geoBlocked.Load()
	if geoCount > 0 {
		reasons = append(reasons, map[string]interface{}{"key": "geo", "label": "Geo-Blocking", "count": geoCount})
	}
	rlCount := s.rateLimited.Load()
	if rlCount > 0 {
		reasons = append(reasons, map[string]interface{}{"key": "ratelimit", "label": "Rate Limiting", "count": rlCount})
	}

	actions := []map[string]interface{}{}
	if stats.BlockedRequests > 0 {
		actions = append(actions, map[string]interface{}{"key": "block", "label": "Blocked", "count": stats.BlockedRequests})
	}
	if stats.AllowedRequests > 0 {
		actions = append(actions, map[string]interface{}{"key": "allow", "label": "Allowed", "count": stats.AllowedRequests})
	}

	topReason := "none"
	if rlCount >= blCount && rlCount >= geoCount && rlCount > 0 {
		topReason = "ratelimit"
	} else if blCount >= geoCount && blCount > 0 {
		topReason = "blacklist"
	} else if geoCount > 0 {
		topReason = "geo"
	}

	summary := map[string]interface{}{
		"total_requests":      stats.TotalRequests,
		"blocked_requests":    stats.BlockedRequests,
		"allowed_requests":    stats.AllowedRequests,
		"rate_limited":        rlCount,
		"challenged_requests": 0,
		"active_connections":  stats.Custom["active_connections"],
		"unique_source_ips":   0,
		"unique_countries":    0,
		"top_reason":          topReason,
		"window":              "24h",
	}

	writeJSON(w, map[string]interface{}{
		"dashboard": map[string]interface{}{
			"summary":            summary,
			"total_requests":     stats.TotalRequests,
			"blocked_requests":   stats.BlockedRequests,
			"allowed_requests":   stats.AllowedRequests,
			"active_connections": stats.Custom["active_connections"],
			"history":            []interface{}{},
			"events":             map[string]interface{}{"events": []interface{}{}},
			"breakdowns": map[string]interface{}{
				"reasons":       reasons,
				"actions":       actions,
				"paths":         []interface{}{},
				"ips":           []interface{}{},
				"geo_countries": []interface{}{},
			},
			"health": map[string]interface{}{
				"db_available":     true,
				"freshness_status": "live",
				"message":          "Community traffic metrics operational",
			},
		},
	})
}

func (s *Section) handleGeoStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	blocker := s.geoBlocker
	service := s.geoService
	s.mu.RUnlock()
	response := map[string]interface{}{"available": true, "entitled": true}
	if blocker != nil {
		response["policy"] = blocker.Status()
	}
	if service != nil {
		response["database"] = service.Status()
	}
	writeJSON(w, response)
}

func (s *Section) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	response := map[string]interface{}{"ips": s.blacklist.ListIPs(), "cidrs": s.blacklist.ListCIDRs()}
	s.mu.RUnlock()
	writeJSON(w, response)
}

func (s *Section) GetPolicies() []sections.Policy { return nil }
func (s *Section) SetPolicies([]sections.Policy) error {
	return errors.New("generic Traffic Control policies require Professional")
}
func (s *Section) GetRules() []sections.Rule { return nil }
func (s *Section) SetRules([]sections.Rule) error {
	return errors.New("generic Traffic Control rules require Professional")
}
func (s *Section) ValidateRule(sections.Rule) error {
	return errors.New("custom Traffic Control rules require Professional")
}
func (s *Section) ListFunctions() []sections.FunctionInfo {
	return []sections.FunctionInfo{{ID: "geo", Name: "Geo-blocking", Enabled: s.config.Geo.Enabled, Category: "community"}, {ID: "blacklist", Name: "Manual blacklist", Enabled: true, Category: "community"}, {ID: "ratelimit", Name: "Rate limiting", Enabled: true, Category: "community"}, {ID: "connections", Name: "Connection statistics", Enabled: true, Category: "community"}}
}
func (s *Section) GetFunction(string) sections.Function { return nil }

func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return strings.TrimSpace(address)
}

func cloneMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return map[string]interface{}{}
	}
	encoded, _ := json.Marshal(input)
	var output map[string]interface{}
	_ = json.Unmarshal(encoded, &output)
	return output
}

func writeJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func writeFeatureError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "feature_not_entitled"})
}

func numericInt(value interface{}) (int, bool) {
	switch number := value.(type) {
	case int:
		return number, true
	case float64:
		return int(number), true
	default:
		return 0, false
	}
}

func policyConfig(cfg infraConfig.GeoConfig) geoip.PolicyConfig {
	return geoip.PolicyConfig{Enabled: cfg.Enabled, AllowCountries: cfg.AllowCountries, BlockCountries: cfg.BlockCountries, Groups: cfg.Groups, Exceptions: cfg.Exceptions, Mode: cfg.Mode, Countries: cfg.Countries, Regions: cfg.Regions}
}

func routeCountryPolicy(r *http.Request) *geoip.Policy {
	matched, ok := transport.RouteFromRequest(r)
	if !ok || matched.Rule.Security.Country == nil {
		return nil
	}
	policy := matched.Rule.Security.Country
	return geoip.CompilePolicy(geoip.PolicyConfig{
		Enabled:        policy.Enabled,
		AllowCountries: policy.AllowCountries,
		BlockCountries: policy.BlockCountries,
		Groups:         policy.Groups,
		Exceptions:     policy.Exceptions,
	})
}
