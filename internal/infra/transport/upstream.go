package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"go.uber.org/zap"
)

// UpstreamManager manages upstream groups and load balancing
type UpstreamManager struct {
	Groups map[string]*UpstreamGroup
	mu     sync.RWMutex
	logger *zap.Logger

	lifecycleMu sync.Mutex
	stopHealth  context.CancelFunc
	healthCtx   context.Context
	healthHTTP  *http.Client
	healthSem   chan struct{}
	healthWG    sync.WaitGroup
	stickyMgr   *StickySessionManager
}

// UpstreamGroup represents a load balancing pool
type UpstreamGroup struct {
	// Must be at the top for 64-bit alignment on 32-bit architectures
	Next uint64 // For Round Robin

	Name        string
	Strategy    string // round_robin, weighted_rr, least_conn, ip_hash
	Targets     []*Target
	HealthCheck config.HealthCheckConfig
	Sticky      config.StickySessionConfig
}

// Target represents a single backend server
type Target struct {
	// Must be at the top for 64-bit alignment on 32-bit architectures
	ActiveConns         int64
	Fails               int64
	SuccessCount        int64
	lastCheckUnixNano   int64
	lastLatencyMicros   int64
	lastStatusCode      int64
	consecutiveFailures int64
	consecutiveSuccess  int64

	URL     *url.URL
	Weight  int
	healthy atomic.Bool

	lastError atomic.Value
}

// NewUpstreamManager creates a new manager from config
func NewUpstreamManager(cfg config.UpstreamConfig, logger *zap.Logger) (*UpstreamManager, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	groups, err := buildUpstreamGroups(cfg.Groups)
	if err != nil {
		return nil, err
	}
	return &UpstreamManager{
		Groups:     groups,
		logger:     logger,
		stickyMgr:  NewStickySessionManager(cfg.StickySecret),
		healthHTTP: newHealthHTTPClient(cfg.InsecureSkipVerify),
		healthSem:  make(chan struct{}, healthCheckConcurrency(cfg.HealthConcurrency)),
	}, nil
}

func buildUpstreamGroups(groups []config.UpstreamGroup) (map[string]*UpstreamGroup, error) {
	built := make(map[string]*UpstreamGroup, len(groups))
	for _, configured := range groups {
		name := strings.TrimSpace(configured.Name)
		if name == "" {
			return nil, fmt.Errorf("upstream group name is required")
		}
		if _, exists := built[name]; exists {
			return nil, fmt.Errorf("duplicate upstream group %q", name)
		}
		strategy := strings.ToLower(strings.TrimSpace(configured.Strategy))
		if strategy == "" {
			strategy = "round_robin"
		}
		switch strategy {
		case "round_robin", "weighted_rr", "least_conn", "ip_hash":
		default:
			return nil, fmt.Errorf("unsupported strategy %q in upstream group %q", strategy, name)
		}
		if len(configured.Targets) > config.MaxRouteBackends {
			return nil, fmt.Errorf("upstream group %q has %d targets; maximum is %d", name, len(configured.Targets), config.MaxRouteBackends)
		}
		group := &UpstreamGroup{
			Name:        name,
			Strategy:    strategy,
			HealthCheck: configured.HealthCheck,
			Sticky:      configured.Sticky,
		}
		for _, configuredTarget := range configured.Targets {
			targetURL, err := parseUpstreamTargetURL(configuredTarget.URL)
			if err != nil {
				return nil, fmt.Errorf("invalid target URL in upstream group %q: %w", name, err)
			}
			weight := configuredTarget.Weight
			if weight <= 0 {
				weight = 1
			}
			if weight > config.MaxUpstreamTargetWeight {
				return nil, fmt.Errorf("target weight %d in upstream group %q exceeds maximum %d", weight, name, config.MaxUpstreamTargetWeight)
			}
			target := &Target{URL: targetURL, Weight: weight}
			target.healthy.Store(true)
			target.lastError.Store("")
			group.Targets = append(group.Targets, target)
		}
		built[name] = group
	}
	return built, nil
}

func parseUpstreamTargetURL(raw string) (*url.URL, error) {
	targetURL, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if targetURL.Scheme != "http" && targetURL.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be HTTP or HTTPS")
	}
	if targetURL.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if targetURL.User != nil {
		return nil, fmt.Errorf("embedded credentials are not allowed")
	}
	if targetURL.Fragment != "" {
		return nil, fmt.Errorf("fragments are not allowed")
	}
	return targetURL, nil
}

// SelectTarget chooses a backend based on the configured strategy
func (g *UpstreamGroup) SelectTarget(req *http.Request) *Target {
	return g.SelectTargetExcluding(req, nil)
}

// SelectTargetExcluding chooses a healthy backend while avoiding targets that
// already failed during the current proxy attempt sequence.
func (g *UpstreamGroup) SelectTargetExcluding(req *http.Request, excluded map[string]struct{}) *Target {
	if len(g.Targets) == 0 {
		return nil
	}

	switch g.Strategy {
	case "weighted_rr":
		return g.selectWeighted(excluded)
	case "least_conn":
		return g.selectLeastConn(excluded)
	case "ip_hash":
		return g.selectIPHash(req, excluded)
	default: // "round_robin" or empty
		return g.selectRoundRobin(excluded)
	}
}

// selectRoundRobin distributes requests evenly across healthy targets
func (g *UpstreamGroup) selectRoundRobin(excluded map[string]struct{}) *Target {
	start := atomic.AddUint64(&g.Next, 1) - 1
	for offset := 0; offset < len(g.Targets); offset++ {
		target := g.Targets[(int(start)+offset)%len(g.Targets)]
		if target.healthy.Load() && !upstreamTargetExcluded(target, excluded) {
			return target
		}
	}
	return nil
}

// selectWeighted distributes requests proportionally without expanding weights
// into a potentially large allocation.
func (g *UpstreamGroup) selectWeighted(excluded map[string]struct{}) *Target {
	totalWeight := uint64(0)
	for _, target := range g.Targets {
		if target.healthy.Load() && !upstreamTargetExcluded(target, excluded) {
			totalWeight += uint64(target.Weight)
		}
	}
	if totalWeight == 0 {
		return nil
	}
	selectedWeight := (atomic.AddUint64(&g.Next, 1) - 1) % totalWeight
	for _, target := range g.Targets {
		if !target.healthy.Load() || upstreamTargetExcluded(target, excluded) {
			continue
		}
		weight := uint64(target.Weight)
		if selectedWeight < weight {
			return target
		}
		selectedWeight -= weight
	}
	return nil
}

// selectLeastConn picks the healthy target with the fewest active connections
func (g *UpstreamGroup) selectLeastConn(excluded map[string]struct{}) *Target {
	var selected *Target
	var minConns int64 = 1<<63 - 1 // Max int64

	for _, t := range g.Targets {
		if !t.healthy.Load() || upstreamTargetExcluded(t, excluded) {
			continue
		}
		conns := atomic.LoadInt64(&t.ActiveConns)
		if conns < minConns {
			minConns = conns
			selected = t
		}
	}

	if selected != nil {
		atomic.AddInt64(&selected.ActiveConns, 1)
	}

	return selected
}

// selectIPHash consistently routes the same client IP to the same backend
func (g *UpstreamGroup) selectIPHash(req *http.Request, excluded map[string]struct{}) *Target {
	ip := ""
	if req != nil {
		ip = req.Header.Get("X-Aegis-Client-IP")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(req.RemoteAddr)
			if ip == "" {
				ip = req.RemoteAddr
			}
		}
	}

	h := fnv.New32a()
	h.Write([]byte(ip))
	hash := h.Sum32()

	healthyCount := 0
	for _, target := range g.Targets {
		if target.healthy.Load() && !upstreamTargetExcluded(target, excluded) {
			healthyCount++
		}
	}
	if healthyCount == 0 {
		return nil
	}
	wanted := int(hash % uint32(healthyCount))
	for _, target := range g.Targets {
		if !target.healthy.Load() || upstreamTargetExcluded(target, excluded) {
			continue
		}
		if wanted == 0 {
			return target
		}
		wanted--
	}
	return nil
}

// DecrementConn decrements active connection count for a target (call on response/error)
func (g *UpstreamGroup) DecrementConn(targetURL string) {
	for _, t := range g.Targets {
		if t.URL.String() == targetURL {
			for {
				current := atomic.LoadInt64(&t.ActiveConns)
				if current <= 0 || atomic.CompareAndSwapInt64(&t.ActiveConns, current, current-1) {
					return
				}
			}
		}
	}
}

func upstreamTargetExcluded(target *Target, excluded map[string]struct{}) bool {
	if target == nil || len(excluded) == 0 {
		return false
	}
	_, blocked := excluded[target.URL.String()]
	return blocked
}

// GetGroup retrieves a group by name
func (m *UpstreamManager) GetGroup(name string) *UpstreamGroup {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Groups[name]
}

// StickyManager returns the current immutable signer under the same lock used
// by Reload, avoiding a pointer race with live proxy requests.
func (m *UpstreamManager) StickyManager() *StickySessionManager {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stickyMgr
}

type UpstreamTargetRuntimeStatus struct {
	URL                 string `json:"url"`
	Healthy             bool   `json:"healthy"`
	HealthCheckEnabled  bool   `json:"health_check_enabled"`
	ActiveConnections   int64  `json:"active_connections"`
	ConsecutiveFailures int64  `json:"consecutive_failures"`
	ConsecutiveSuccess  int64  `json:"consecutive_successes"`
	LastCheck           string `json:"last_check,omitempty"`
	LastLatencyMS       int64  `json:"last_latency_ms,omitempty"`
	LastStatusCode      int    `json:"last_status_code,omitempty"`
	LastError           string `json:"last_error,omitempty"`
}

type UpstreamGroupRuntimeStatus struct {
	Name    string                        `json:"name"`
	Targets []UpstreamTargetRuntimeStatus `json:"targets"`
}

// RuntimeStatus returns a lock-safe operational snapshot for the admin API.
func (m *UpstreamManager) RuntimeStatus() []UpstreamGroupRuntimeStatus {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	groups := make([]*UpstreamGroup, 0, len(m.Groups))
	for _, group := range m.Groups {
		groups = append(groups, group)
	}
	m.mu.RUnlock()
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })

	status := make([]UpstreamGroupRuntimeStatus, 0, len(groups))
	for _, group := range groups {
		groupStatus := UpstreamGroupRuntimeStatus{Name: group.Name, Targets: make([]UpstreamTargetRuntimeStatus, 0, len(group.Targets))}
		for _, target := range group.Targets {
			lastCheckNano := atomic.LoadInt64(&target.lastCheckUnixNano)
			lastCheck := ""
			if lastCheckNano > 0 {
				lastCheck = time.Unix(0, lastCheckNano).UTC().Format(time.RFC3339Nano)
			}
			lastError, _ := target.lastError.Load().(string)
			groupStatus.Targets = append(groupStatus.Targets, UpstreamTargetRuntimeStatus{
				URL:                 target.URL.String(),
				Healthy:             target.healthy.Load(),
				HealthCheckEnabled:  group.HealthCheck.Enabled,
				ActiveConnections:   atomic.LoadInt64(&target.ActiveConns),
				ConsecutiveFailures: atomic.LoadInt64(&target.consecutiveFailures),
				ConsecutiveSuccess:  atomic.LoadInt64(&target.consecutiveSuccess),
				LastCheck:           lastCheck,
				LastLatencyMS:       atomic.LoadInt64(&target.lastLatencyMicros) / 1000,
				LastStatusCode:      int(atomic.LoadInt64(&target.lastStatusCode)),
				LastError:           lastError,
			})
		}
		status = append(status, groupStatus)
	}
	return status
}

// StartHealthChecks starts the bounded background checker pool.
func (m *UpstreamManager) StartHealthChecks(ctx context.Context) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.stopHealthChecksLocked()
	m.startHealthChecksLocked(ctx)
}

// Reload updates the complete Origin snapshot, preserves health state for
// unchanged targets, swaps TLS behavior, and restarts cancellable checkers.
func (m *UpstreamManager) Reload(cfg config.UpstreamConfig) error {
	newGroups, err := buildUpstreamGroups(cfg.Groups)
	if err != nil {
		return err
	}

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.stopHealthChecksLocked()

	m.mu.Lock()
	copyTargetRuntimeState(m.Groups, newGroups)
	oldHTTP := m.healthHTTP
	m.Groups = newGroups
	m.stickyMgr = NewStickySessionManager(cfg.StickySecret)
	m.healthHTTP = newHealthHTTPClient(cfg.InsecureSkipVerify)
	m.healthSem = make(chan struct{}, healthCheckConcurrency(cfg.HealthConcurrency))
	parentCtx := m.healthCtx
	m.mu.Unlock()
	closeHealthIdleConnections(oldHTTP)

	m.startHealthChecksLocked(parentCtx)
	m.logger.Info("Upstream configuration reloaded", zap.Int("groups", len(newGroups)))
	return nil
}

// ReloadStickySecret replaces only the immutable signer used for affinity
// cookies. Origin pools, health checks, transport settings, and their runtime
// state remain intact while a secret reference is rotated.
func (m *UpstreamManager) ReloadStickySecret(secret string) error {
	if m == nil {
		return errors.New("upstream manager is unavailable")
	}
	if len(strings.TrimSpace(secret)) < 32 {
		return errors.New("sticky-session secret must be at least 32 characters")
	}
	m.mu.Lock()
	m.stickyMgr = NewStickySessionManager(secret)
	m.mu.Unlock()
	return nil
}

func (m *UpstreamManager) startHealthChecksLocked(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	m.healthCtx = ctx
	checkerCtx, cancel := context.WithCancel(ctx)
	m.stopHealth = cancel
	groups := make([]*UpstreamGroup, 0, len(m.Groups))
	for _, group := range m.Groups {
		if group.HealthCheck.Enabled {
			groups = append(groups, group)
		}
	}
	for _, group := range groups {
		interval, err := time.ParseDuration(group.HealthCheck.Interval)
		if err != nil || interval <= 0 {
			interval = 10 * time.Second
		}
		m.healthWG.Add(1)
		go func(current *UpstreamGroup, every time.Duration) {
			defer m.healthWG.Done()
			m.runHealthCheck(checkerCtx, current, every)
		}(group, interval)
	}
	m.mu.Unlock()
}

func (m *UpstreamManager) stopHealthChecksLocked() {
	m.mu.Lock()
	cancel := m.stopHealth
	m.stopHealth = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.healthWG.Wait()
}

func (m *UpstreamManager) runHealthCheck(ctx context.Context, group *UpstreamGroup, interval time.Duration) {
	// Spread initial probes across a small, deterministic portion of the
	// interval so a restart does not synchronize every configured Origin.
	jitterLimit := interval / 5
	if jitterLimit > time.Second {
		jitterLimit = time.Second
	}
	if jitterLimit > 0 {
		hash := fnv.New32a()
		_, _ = hash.Write([]byte(group.Name))
		jitter := time.Duration(hash.Sum32() % uint32(jitterLimit))
		timer := time.NewTimer(jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}

	m.checkGroup(ctx, group)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkGroup(ctx, group)
		}
	}
}

func (m *UpstreamManager) checkGroup(ctx context.Context, group *UpstreamGroup) {
	var wait sync.WaitGroup
	for _, target := range group.Targets {
		select {
		case <-ctx.Done():
			wait.Wait()
			return
		case m.healthSem <- struct{}{}:
		}
		wait.Add(1)
		go func(current *Target) {
			defer wait.Done()
			defer func() { <-m.healthSem }()
			healthy, statusCode, latency, probeErr := m.probeTarget(ctx, current, group.HealthCheck)
			m.recordHealthResult(group, current, healthy, statusCode, latency, probeErr)
		}(target)
	}
	wait.Wait()
}

func (m *UpstreamManager) probeTarget(ctx context.Context, target *Target, check config.HealthCheckConfig) (bool, int, time.Duration, error) {
	checkURL := target.URL.ResolveReference(&url.URL{Path: check.Path})
	timeout, err := time.ParseDuration(check.Timeout)
	if err != nil || timeout <= 0 {
		timeout = 3 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	method := check.Method
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(probeCtx, method, checkURL.String(), nil)
	if err != nil {
		return false, 0, 0, err
	}
	for name, value := range check.Headers {
		if strings.EqualFold(name, "Host") {
			request.Host = value
			continue
		}
		request.Header.Set(name, value)
	}

	started := time.Now()
	resp, err := m.healthHTTP.Do(request)
	latency := time.Since(started)
	if err != nil {
		return false, 0, latency, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32<<10))

	healthy := resp.StatusCode >= 200 && resp.StatusCode < 400
	if len(check.ExpectedStatuses) > 0 {
		healthy = false
		for _, expected := range check.ExpectedStatuses {
			if resp.StatusCode == expected {
				healthy = true
				break
			}
		}
	}
	if !healthy {
		return false, resp.StatusCode, latency, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	return true, resp.StatusCode, latency, nil
}

func (m *UpstreamManager) recordHealthResult(group *UpstreamGroup, target *Target, probeHealthy bool, statusCode int, latency time.Duration, probeErr error) {
	atomic.StoreInt64(&target.lastCheckUnixNano, time.Now().UnixNano())
	atomic.StoreInt64(&target.lastLatencyMicros, latency.Microseconds())
	atomic.StoreInt64(&target.lastStatusCode, int64(statusCode))
	lastError := ""
	if probeErr != nil {
		lastError = probeErr.Error()
		if len(lastError) > 256 {
			lastError = lastError[:256]
		}
	}
	target.lastError.Store(lastError)

	previous := target.healthy.Load()
	current := previous
	if probeHealthy {
		successes := atomic.AddInt64(&target.consecutiveSuccess, 1)
		atomic.StoreInt64(&target.consecutiveFailures, 0)
		atomic.StoreInt64(&target.Fails, 0)
		atomic.AddInt64(&target.SuccessCount, 1)
		threshold := group.HealthCheck.HealthyThreshold
		if threshold <= 0 {
			threshold = 2
		}
		if !previous && successes >= int64(threshold) {
			target.healthy.Store(true)
			current = true
		}
	} else {
		failures := atomic.AddInt64(&target.consecutiveFailures, 1)
		atomic.StoreInt64(&target.consecutiveSuccess, 0)
		atomic.StoreInt64(&target.Fails, failures)
		threshold := group.HealthCheck.UnhealthyThreshold
		if threshold <= 0 {
			threshold = 3
		}
		if previous && failures >= int64(threshold) {
			target.healthy.Store(false)
			current = false
		}
	}
	if current != previous {
		status := "UP"
		if !current {
			status = "DOWN"
		}
		m.logger.Info("Upstream target status changed",
			zap.String("group", group.Name),
			zap.String("url", target.URL.String()),
			zap.String("status", status))
	}
}

func copyTargetRuntimeState(previous, next map[string]*UpstreamGroup) {
	for name, nextGroup := range next {
		previousGroup := previous[name]
		if previousGroup == nil {
			continue
		}
		previousTargets := make(map[string]*Target, len(previousGroup.Targets))
		for _, target := range previousGroup.Targets {
			previousTargets[target.URL.String()] = target
		}
		for _, target := range nextGroup.Targets {
			old := previousTargets[target.URL.String()]
			if old == nil {
				continue
			}
			target.healthy.Store(old.healthy.Load())
			atomic.StoreInt64(&target.ActiveConns, atomic.LoadInt64(&old.ActiveConns))
			atomic.StoreInt64(&target.Fails, atomic.LoadInt64(&old.Fails))
			atomic.StoreInt64(&target.SuccessCount, atomic.LoadInt64(&old.SuccessCount))
			atomic.StoreInt64(&target.lastCheckUnixNano, atomic.LoadInt64(&old.lastCheckUnixNano))
			atomic.StoreInt64(&target.lastLatencyMicros, atomic.LoadInt64(&old.lastLatencyMicros))
			atomic.StoreInt64(&target.lastStatusCode, atomic.LoadInt64(&old.lastStatusCode))
			atomic.StoreInt64(&target.consecutiveFailures, atomic.LoadInt64(&old.consecutiveFailures))
			atomic.StoreInt64(&target.consecutiveSuccess, atomic.LoadInt64(&old.consecutiveSuccess))
			if value, ok := old.lastError.Load().(string); ok {
				target.lastError.Store(value)
			}
		}
	}
}

func healthCheckConcurrency(configured int) int {
	if configured <= 0 {
		return 32
	}
	if configured > 256 {
		return 256
	}
	return configured
}

func newHealthHTTPClient(insecureSkipVerify bool) *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     60 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecureSkipVerify},
	}}
}

func closeHealthIdleConnections(client *http.Client) {
	if client == nil {
		return
	}
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}
