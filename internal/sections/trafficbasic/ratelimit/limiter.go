// Package ratelimit provides request rate limiting with multiple algorithms and strategies
package ratelimit

import (
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/requestctx"
)

// Limiter provides rate limiting functionality
type Limiter struct {
	mu      sync.RWMutex
	enabled bool

	// Configuration
	defaultRate     int           // Requests per window
	defaultBurst    int           // Burst allowance
	window          time.Duration // Time window
	algorithm       string        // "token_bucket", "fixed_window", "sliding_window"
	keyBy           string        // "ip", "ip_ua", "cookie", "token"
	action          string        // "block", "challenge", "drop"
	bypassStatic    bool
	bypassKnownBots bool

	// Advanced Config
	cookieName       string
	headerName       string
	staticExtensions []string

	// Per-path overrides
	pathRules []*PathRule

	// State (Generic buckets for now, assuming TokenBucket struct can handle others or be adapted)
	buckets map[string]*Bucket

	// Cleanup
	lastCleanup time.Time
}

// PathRule defines rate limits for specific paths
type PathRule struct {
	Pattern     string        // Glob pattern (e.g., "/api/auth/*")
	PathPattern string        // Alternative pattern field
	Rate        int           // Requests per window
	Burst       int           // Burst allowance
	Window      time.Duration // Time window
	Methods     []string      // Filter HTTP methods (GET, POST, etc.)
	Action      string        // "block", "dry_run", etc.
	KeyBy       string        // "ip", "ip_ua", "cookie", "token"
	Algorithm   string        // "token_bucket", "fixed_window", "sliding_window"
}

// Bucket holds state for all rate limiting algorithms
type Bucket struct {
	mu sync.Mutex
	// Token Bucket
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time

	// Fixed/Sliding Window
	count       int       // Current window count
	prevCount   int       // Previous window count (for sliding window)
	windowStart time.Time // Start of current window
}

// Config holds rate limiter configuration matched to UI
type Config struct {
	Enabled          bool
	DefaultRate      int
	DefaultBurst     int
	Window           string // e.g. "1m", "1h"
	Algorithm        string // "token_bucket", "fixed_window", "sliding_window"
	KeyBy            string // "ip", "ip_ua", "cookie", "token"
	Action           string // "block", "challenge"
	BypassStatic     bool
	BypassKnownBots  bool
	CookieName       string   // Default: session_id
	HeaderName       string   // Default: Authorization
	StaticExtensions []string // Default: .css, .js...
	PathRules        []PathRuleConfig
}

// PathRuleConfig is the config version of PathRule
type PathRuleConfig struct {
	Pattern     string   `json:"pattern" mapstructure:"pattern"`
	PathPattern string   `json:"path_pattern,omitempty" mapstructure:"path_pattern"`
	Rate        int      `json:"rate" mapstructure:"rate"`
	Burst       int      `json:"burst" mapstructure:"burst"`
	Window      string   `json:"window" mapstructure:"window"`
	Methods     []string `json:"methods,omitempty" mapstructure:"methods"`
	Action      string   `json:"action,omitempty" mapstructure:"action"`
	KeyBy       string   `json:"key_by,omitempty" mapstructure:"key_by"`
	Algorithm   string   `json:"algorithm,omitempty" mapstructure:"algorithm"`
}

func convertPathRule(rule PathRuleConfig, defaultRate, defaultBurst int, defaultWindow time.Duration) *PathRule {
	pattern := strings.TrimSpace(rule.Pattern)
	if pattern == "" {
		pattern = strings.TrimSpace(rule.PathPattern)
	}
	rate := rule.Rate
	if rate <= 0 {
		rate = defaultRate
	}
	burst := rule.Burst
	if burst <= 0 {
		burst = rate
		if burst <= 0 {
			burst = defaultBurst
		}
	}
	window := parseWindow(rule.Window)
	if window <= 0 {
		window = defaultWindow
	}
	return &PathRule{
		Pattern:     pattern,
		PathPattern: rule.PathPattern,
		Rate:        rate,
		Burst:       burst,
		Window:      window,
		Methods:     rule.Methods,
		Action:      rule.Action,
		KeyBy:       rule.KeyBy,
		Algorithm:   rule.Algorithm,
	}
}

// New creates a new rate limiter
func New(cfg Config) *Limiter {
	l := &Limiter{
		enabled:          cfg.Enabled,
		defaultRate:      cfg.DefaultRate,
		defaultBurst:     cfg.DefaultBurst,
		window:           parseWindow(cfg.Window),
		algorithm:        cfg.Algorithm,
		keyBy:            cfg.KeyBy,
		action:           cfg.Action,
		bypassStatic:     cfg.BypassStatic,
		bypassKnownBots:  cfg.BypassKnownBots,
		cookieName:       cfg.CookieName,
		headerName:       cfg.HeaderName,
		staticExtensions: cfg.StaticExtensions,
		buckets:          make(map[string]*Bucket),
		pathRules:        make([]*PathRule, 0, len(cfg.PathRules)),
		lastCleanup:      time.Now(),
	}

	// Set defaults
	if l.defaultRate <= 0 {
		l.defaultRate = 60
	}
	if l.defaultBurst <= 0 {
		l.defaultBurst = 10
	}
	if l.window <= 0 {
		l.window = time.Second
	}
	if l.algorithm == "" {
		l.algorithm = "token_bucket"
	}
	if l.keyBy == "" {
		l.keyBy = "ip"
	}
	if l.cookieName == "" {
		l.cookieName = "session_id"
	}
	if l.headerName == "" {
		l.headerName = "Authorization"
	}
	if len(l.staticExtensions) == 0 {
		l.staticExtensions = []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"}
	}

	// Convert path rules
	for _, rule := range cfg.PathRules {
		l.pathRules = append(l.pathRules, convertPathRule(rule, l.defaultRate, l.defaultBurst, l.window))
	}

	return l
}

func parseWindow(s string) time.Duration {
	if s == "" {
		return time.Minute
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	// Fallback for simple "1s", "1m", "1h" if ParseDuration fails
	switch s {
	case "1s":
		return time.Second
	case "1h":
		return time.Hour
	default:
		return time.Minute
	}
}

// SetEnabled enables or disables the limiter
func (l *Limiter) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}

// IsAllowed checks if a request should be allowed based on config
func (l *Limiter) IsAllowed(r *http.Request) (allowed bool, remaining int, rule *PathRule) {
	// Opportunistic periodic cleanup
	l.mu.RLock()
	needCleanup := time.Since(l.lastCleanup) >= time.Minute
	l.mu.RUnlock()
	if needCleanup {
		l.Cleanup()
	}

	l.mu.RLock()
	if !l.enabled {
		l.mu.RUnlock()
		return true, -1, nil
	}
	// Check bypasses
	if l.bypassStatic && l.isStaticResource(r.URL.Path) {
		l.mu.RUnlock()
		return true, -1, nil
	}
	if l.bypassKnownBots && isKnownBot(r.UserAgent()) {
		l.mu.RUnlock()
		return true, -1, nil
	}
	l.mu.RUnlock()

	// 1. Determine Rate/Burst/Window and Rule for this path & method
	rate, burst, window, matchedRule := l.getLimitsForPath(r.Method, r.URL.Path)

	// 2. Determine Key
	key := l.extractKey(r, matchedRule)
	if key == "" {
		key = getClientIP(r)
	}

	// Appending path pattern to key
	bucketSuffix := ":global"
	if matchedRule != nil {
		pattern := matchedRule.Pattern
		if pattern == "" {
			pattern = matchedRule.PathPattern
		}
		bucketSuffix = ":" + pattern
	}
	fullKey := key + bucketSuffix

	// 3. Get Bucket
	bucket := l.getOrCreateBucket(fullKey, rate, burst, window)

	// 4. Consume
	l.mu.RLock()
	algo := l.algorithm
	if matchedRule != nil && matchedRule.Algorithm != "" {
		algo = matchedRule.Algorithm
	}
	l.mu.RUnlock()
	allowed, remainingCount := bucket.consume(1, rate, burst, window, algo)

	return allowed, remainingCount, matchedRule
}

// extractKey generates the storage key based on configuration
func (l *Limiter) extractKey(r *http.Request, matchedRule *PathRule) string {
	l.mu.RLock()
	mode := l.keyBy
	if matchedRule != nil && matchedRule.KeyBy != "" {
		mode = matchedRule.KeyBy
	}
	cookieName := l.cookieName
	headerName := l.headerName
	l.mu.RUnlock()

	switch mode {
	case "ip_ua":
		return getClientIP(r) + "|" + r.UserAgent()
	case "cookie":
		if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
			return "cookie:" + c.Value
		}
		return "" // Fallback handled in caller
	case "token":
		auth := r.Header.Get(headerName)
		if strings.HasPrefix(auth, "Bearer ") {
			return "token:" + strings.TrimPrefix(auth, "Bearer ")
		}
		if headerName != "Authorization" && auth != "" {
			return "token:" + auth
		}
		return ""
	case "ip":
		fallthrough
	default:
		return getClientIP(r)
	}
}

func getClientIP(r *http.Request) string {
	if ip := requestctx.ClientIP(r); ip != "" {
		return ip
	}
	remoteIP := hostFromAddr(r.RemoteAddr)
	return remoteIP
}

func hostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return strings.TrimSpace(addr)
}

func (l *Limiter) isStaticResource(p string) bool {
	// Note: Called while holding l.mu.RLock in IsAllowed, so staticExtensions is safe to access
	for _, ext := range l.staticExtensions {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func isKnownBot(ua string) bool {
	ua = strings.ToLower(ua)
	bots := []string{"googlebot", "bingbot", "yandexbot", "duckduckbot", "baiduspider", "facebookexternalhit", "twitterbot"}
	for _, bot := range bots {
		if strings.Contains(ua, bot) {
			return true
		}
	}
	return false
}

// getLimitsForPath returns the rate limit config for a path and method
func (l *Limiter) getLimitsForPath(reqMethod, requestPath string) (rate, burst int, window time.Duration, rule *PathRule) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Check path rules
	for _, r := range l.pathRules {
		if len(r.Methods) > 0 {
			methodMatched := false
			for _, m := range r.Methods {
				if strings.EqualFold(m, reqMethod) {
					methodMatched = true
					break
				}
			}
			if !methodMatched {
				continue
			}
		}

		pattern := r.Pattern
		if pattern == "" {
			pattern = r.PathPattern
		}
		if matched, _ := path.Match(pattern, requestPath); matched {
			return r.Rate, r.Burst, r.Window, r
		}
		// Glob suffix check
		if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
			prefix := pattern[:len(pattern)-1]
			if len(requestPath) >= len(prefix) && requestPath[:len(prefix)] == prefix {
				return r.Rate, r.Burst, r.Window, r
			}
		}
	}

	return l.defaultRate, l.defaultBurst, l.window, nil
}

// getOrCreateBucket gets or creates a bucket
func (l *Limiter) getOrCreateBucket(key string, rate, burst int, window time.Duration) *Bucket {
	l.mu.RLock()
	bucket, exists := l.buckets[key]
	l.mu.RUnlock()

	if exists {
		return bucket
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if bucket, exists = l.buckets[key]; exists {
		return bucket
	}

	refillRate := float64(rate) / window.Seconds()

	bucket = &Bucket{
		tokens:      float64(burst),
		maxTokens:   float64(burst),
		refillRate:  refillRate,
		lastRefill:  time.Now(),
		windowStart: time.Now(),
		count:       0,
		prevCount:   0,
	}
	l.buckets[key] = bucket
	return bucket
}

// consume tries to consume tokens/allow request based on algorithm
func (b *Bucket) consume(cost int, rate, burst int, window time.Duration, algo string) (allowed bool, remaining int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	switch algo {
	case "fixed_window":
		// Reset if window passed
		if now.Sub(b.windowStart) >= window {
			b.windowStart = now
			b.count = 0
		}
		b.lastRefill = now
		if b.count+cost <= rate {
			b.count += cost
			return true, rate - b.count
		}
		return false, 0

	case "sliding_window":
		// Fixed Window Counter + Previous Window weight approximation
		elapsed := now.Sub(b.windowStart)
		if elapsed >= window {
			if elapsed >= 2*window {
				b.prevCount = 0
			} else {
				b.prevCount = b.count
			}
			b.count = 0
			b.windowStart = now
			elapsed = 0
		}
		b.lastRefill = now

		weight := float64(window-elapsed) / float64(window)
		estimatedCount := int(float64(b.prevCount)*weight) + b.count + cost

		if estimatedCount <= rate {
			b.count += cost
			return true, rate - estimatedCount
		}
		return false, 0

	case "token_bucket":
		fallthrough
	default:
		// Refill
		elapsedSec := now.Sub(b.lastRefill).Seconds()
		b.tokens += elapsedSec * b.refillRate
		if b.tokens > float64(burst) {
			b.tokens = float64(burst)
		}
		b.lastRefill = now

		if b.tokens >= float64(cost) {
			b.tokens -= float64(cost)
			return true, int(b.tokens)
		}
		return false, int(b.tokens)
	}
}

// AddPathRule adds a path-specific rate limit rule
func (l *Limiter) AddPathRule(pattern string, rate, burst int, window time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if rate <= 0 {
		rate = l.defaultRate
	}
	if burst <= 0 {
		burst = rate
		if burst <= 0 {
			burst = l.defaultBurst
		}
	}
	if window <= 0 {
		window = l.window
	}

	l.pathRules = append(l.pathRules, &PathRule{
		Pattern: pattern,
		Rate:    rate,
		Burst:   burst,
		Window:  window,
	})
}

// RemovePathRule removes a path rule
func (l *Limiter) RemovePathRule(pattern string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	for i, rule := range l.pathRules {
		if rule.Pattern == pattern {
			l.pathRules = append(l.pathRules[:i], l.pathRules[i+1:]...)
			return true
		}
	}
	return false
}

// Window returns the configured default rate limit window
func (l *Limiter) Window() time.Duration {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.window
}

// DefaultRate returns the configured default rate
func (l *Limiter) DefaultRate() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.defaultRate
}

// DefaultBurst returns the configured default burst
func (l *Limiter) DefaultBurst() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.defaultBurst
}

// GetStats returns rate limiter statistics
func (l *Limiter) GetStats() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return map[string]interface{}{
		"enabled":        l.enabled,
		"default_rate":   l.defaultRate,
		"default_burst":  l.defaultBurst,
		"path_rules":     len(l.pathRules),
		"active_buckets": len(l.buckets),
		"max_states":     10000,
	}
}

// Cleanup cleans up old buckets periodically
func (l *Limiter) Cleanup() {
	l.mu.RLock()
	if time.Since(l.lastCleanup) < time.Minute {
		l.mu.RUnlock()
		return
	}
	l.mu.RUnlock()

	// Update lastCleanup timestamp
	l.mu.Lock()
	l.lastCleanup = time.Now()
	l.mu.Unlock()

	// Optimization: Use RLock to identify expired keys first (Scan Phase)
	expiredKeys := make([]string, 0)
	threshold := time.Now().Add(-5 * time.Minute)

	l.mu.RLock()
	for key, bucket := range l.buckets {
		bucket.mu.Lock()
		if bucket.lastRefill.Before(threshold) {
			expiredKeys = append(expiredKeys, key)
		}
		bucket.mu.Unlock()
	}
	l.mu.RUnlock()

	if len(expiredKeys) == 0 {
		return
	}

	// Delete Phase (Write Lock)
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, key := range expiredKeys {
		delete(l.buckets, key)
	}
}

// UpdateConfig updates the limiter configuration
func (l *Limiter) UpdateConfig(cfg Config) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.enabled = cfg.Enabled
	l.defaultRate = cfg.DefaultRate
	l.defaultBurst = cfg.DefaultBurst
	l.window = parseWindow(cfg.Window)
	l.algorithm = cfg.Algorithm
	l.keyBy = cfg.KeyBy
	l.action = cfg.Action
	l.bypassStatic = cfg.BypassStatic
	l.bypassKnownBots = cfg.BypassKnownBots

	l.cookieName = cfg.CookieName
	l.headerName = cfg.HeaderName
	l.staticExtensions = cfg.StaticExtensions

	// Rebuild Path Rules
	l.pathRules = make([]*PathRule, 0, len(cfg.PathRules))
	for _, rule := range cfg.PathRules {
		l.pathRules = append(l.pathRules, convertPathRule(rule, l.defaultRate, l.defaultBurst, l.window))
	}

	// Set defaults if zero/invalid
	if l.defaultRate <= 0 {
		l.defaultRate = 60
	}
	if l.defaultBurst <= 0 {
		l.defaultBurst = 10
	}
	if l.window <= 0 {
		l.window = time.Second
	}
	if l.algorithm == "" {
		l.algorithm = "token_bucket"
	}
	if l.keyBy == "" {
		l.keyBy = "ip"
	}
	if l.cookieName == "" {
		l.cookieName = "session_id"
	}
	if l.headerName == "" {
		l.headerName = "Authorization"
	}
	if len(l.staticExtensions) == 0 {
		l.staticExtensions = []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"}
	}

	// Clear old buckets so new limits apply immediately
	l.buckets = make(map[string]*Bucket)
}
