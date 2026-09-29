package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/requestctx"
	"github.com/divinelab-io/aegis/internal/infra/telemetry"
	"go.uber.org/zap"
)

var errRouteTargetUnavailable = errors.New("matched route target unavailable")

type routeResolutionErrorKey struct{}
type proxyLogContextKey struct{}
type routeRetryKey struct{}
type routeTimeoutCancelKey struct{}
type routeProxyAttemptKey struct{}
type routeRetryPlanKey struct{}

type proxyLogContext struct {
	start      time.Time
	clientInfo ClientInfo
	routeName  string
	routeID    string
}

type routeProxyAttempt struct {
	targetURL       string
	group           *UpstreamGroup
	inlineSelection *inlineBackendSelection
	released        atomic.Bool
}

func (attempt *routeProxyAttempt) release() {
	if attempt == nil || attempt.released.Swap(true) {
		return
	}
	if attempt.inlineSelection != nil {
		attempt.inlineSelection.release()
	}
	if attempt.group != nil && attempt.group.Strategy == "least_conn" {
		attempt.group.DecrementConn(attempt.targetURL)
	}
}

type routeRetryPlan struct {
	router        *Router
	upstreamMgr   *UpstreamManager
	route         *compiledRoute
	client        ClientInfo
	upstreamName  string
	routedPath    string
	routedRawPath string
	routedQuery   string
	originalHost  string
	preserveHost  bool
	fallbackURL   *url.URL
}

type selectedProxyTarget struct {
	url     *url.URL
	attempt *routeProxyAttempt
}

// Circuit Breaker States
const (
	CBNormal   = 0
	CBOpen     = 1
	CBHalfOpen = 2
)

// CircuitBreaker manages the health of the upstream connection
type CircuitBreaker struct {
	mu          sync.RWMutex
	state       int
	failures    int
	lastFailure time.Time
	threshold   int           // Configurable failure threshold
	timeout     time.Duration // Configurable recovery timeout
	probeActive bool
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == CBOpen {
		if time.Since(cb.lastFailure) <= cb.timeout {
			return false
		}
		cb.state = CBHalfOpen
		cb.probeActive = true
		return true
	}
	if cb.state == CBHalfOpen {
		if cb.probeActive {
			return false
		}
		cb.probeActive = true
	}
	return true
}

func (cb *CircuitBreaker) RecordResult(success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if success {
		cb.state = CBNormal
		cb.failures = 0
		cb.probeActive = false
	} else {
		wasProbe := cb.state == CBHalfOpen
		cb.failures++
		cb.lastFailure = time.Now()
		cb.probeActive = false
		if wasProbe || cb.failures >= cb.threshold {
			cb.state = CBOpen
		}
	}
}

// GetStatus returns the current state and failure count
func (cb *CircuitBreaker) GetStatus() (string, int) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	stateStr := "closed"
	switch cb.state {
	case CBOpen:
		stateStr = "open"
	case CBHalfOpen:
		stateStr = "half-open"
	}

	return stateStr, cb.failures
}

type proxyRuntime struct {
	fallbackURL    atomic.Pointer[url.URL]
	transport      atomic.Pointer[http.Transport]
	routes         atomic.Value // map[string]string, always immutable after Store
	infrastructure atomic.Value // config.InfrastructureConfig, immutable after Store
}

func newProxyRuntime(fallbackTarget string, routes map[string]string, upstream config.UpstreamConfig, responseHeaderTimeout string) (*proxyRuntime, error) {
	runtime := &proxyRuntime{}
	if err := runtime.reload(fallbackTarget, routes, upstream, responseHeaderTimeout); err != nil {
		return nil, err
	}
	return runtime, nil
}

func (r *proxyRuntime) reload(fallbackTarget string, routes map[string]string, upstream config.UpstreamConfig, responseHeaderTimeout string) error {
	var fallback *url.URL
	var err error
	if strings.TrimSpace(fallbackTarget) != "" {
		fallback, err = parseUpstreamTargetURL(fallbackTarget)
		if err != nil {
			return fmt.Errorf("invalid default target: %w", err)
		}
	}
	responseTimeout, err := time.ParseDuration(responseHeaderTimeout)
	if err != nil || responseTimeout <= 0 {
		return fmt.Errorf("invalid upstream response-header timeout %q", responseHeaderTimeout)
	}
	idleTimeout, err := time.ParseDuration(upstream.IdleTimeout)
	if err != nil || idleTimeout <= 0 {
		idleTimeout = 90 * time.Second
	}
	tlsTimeout, err := time.ParseDuration(upstream.TLSHandshake)
	if err != nil || tlsTimeout <= 0 {
		tlsTimeout = 10 * time.Second
	}
	maxIdle := upstream.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 1000
	}
	maxIdlePerHost := upstream.MaxIdlePerHost
	if maxIdlePerHost <= 0 {
		maxIdlePerHost = 20
	}
	maxConnsPerHost := upstream.MaxConnsPerHost
	if maxConnsPerHost <= 0 {
		maxConnsPerHost = 100
	}
	nextTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   maxIdlePerHost,
		MaxConnsPerHost:       maxConnsPerHost,
		IdleConnTimeout:       idleTimeout,
		TLSHandshakeTimeout:   tlsTimeout,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: responseTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: upstream.InsecureSkipVerify},
	}

	routeSnapshot := make(map[string]string, len(routes))
	for host, target := range routes {
		routeSnapshot[host] = target
	}
	previous := r.transport.Swap(nextTransport)
	r.fallbackURL.Store(fallback)
	r.routes.Store(routeSnapshot)
	if previous != nil {
		previous.CloseIdleConnections()
	}
	return nil
}

func (r *proxyRuntime) reloadLegacyRoutes(routes map[string]string) {
	if r == nil {
		return
	}
	routeSnapshot := make(map[string]string, len(routes))
	for host, target := range routes {
		routeSnapshot[host] = target
	}
	r.routes.Store(routeSnapshot)
}

func (r *proxyRuntime) RoundTrip(req *http.Request) (*http.Response, error) {
	current := r.transport.Load()
	if current == nil {
		return nil, errors.New("upstream transport is not initialized")
	}
	return current.RoundTrip(req)
}

func (r *proxyRuntime) fallback() *url.URL {
	if r == nil {
		return nil
	}
	return r.fallbackURL.Load()
}

func (r *proxyRuntime) legacyRoutes() map[string]string {
	if r == nil {
		return nil
	}
	routes, _ := r.routes.Load().(map[string]string)
	return routes
}

func (r *proxyRuntime) reloadInfrastructure(cfg config.InfrastructureConfig) {
	if r == nil {
		return
	}
	r.infrastructure.Store(cfg)
}

func (r *proxyRuntime) infrastructureConfig() config.InfrastructureConfig {
	if r == nil {
		return config.InfrastructureConfig{}
	}
	cfg, _ := r.infrastructure.Load().(config.InfrastructureConfig)
	return cfg
}

// BreakerTransport wraps http.RoundTripper with Circuit Breaker logic
type BreakerTransport struct {
	RoundTripper http.RoundTripper
	runtime      *proxyRuntime
	threshold    int
	timeout      time.Duration
	mu           sync.RWMutex
	breakers     map[string]*CircuitBreaker
}

// ReloadUpstream applies the default Origin, TLS verification, connection-pool
// tuning, legacy host routes, and breaker policy to new requests without a
// process restart.
func (t *BreakerTransport) ReloadUpstream(cfg config.UpstreamConfig, responseHeaderTimeout string) error {
	if t == nil || t.runtime == nil {
		return errors.New("proxy runtime is not available")
	}
	threshold, timeout, err := circuitBreakerRuntimePolicy(cfg.CircuitBreaker)
	if err != nil {
		return err
	}
	if err := t.runtime.reload(cfg.Target, cfg.Routes, cfg, responseHeaderTimeout); err != nil {
		return err
	}
	t.applyCircuitBreakerPolicy(threshold, timeout)
	return nil
}

// ReloadCircuitBreaker applies only a committed breaker policy. It deliberately
// keeps the current transport, keep-alive pool, and route runtime in place.
func (t *BreakerTransport) ReloadCircuitBreaker(policy config.CircuitBreakerConfig) error {
	if t == nil || t.runtime == nil {
		return errors.New("proxy runtime is not available")
	}
	threshold, timeout, err := circuitBreakerRuntimePolicy(policy)
	if err != nil {
		return err
	}
	t.applyCircuitBreakerPolicy(threshold, timeout)
	return nil
}

// ReloadLegacyRoutes swaps only legacy host-to-Origin selection. It leaves the
// outbound transport, pooled connections, and breaker state in place.
func (t *BreakerTransport) ReloadLegacyRoutes(routes map[string]string) error {
	if t == nil || t.runtime == nil {
		return errors.New("proxy runtime is not available")
	}
	t.runtime.reloadLegacyRoutes(routes)
	return nil
}

func circuitBreakerRuntimePolicy(policy config.CircuitBreakerConfig) (int, time.Duration, error) {
	threshold := policy.Threshold
	if threshold <= 0 {
		threshold = 5
	}
	timeout := 30 * time.Second
	if policy.Timeout != "" {
		parsed, err := time.ParseDuration(policy.Timeout)
		if err != nil || parsed <= 0 {
			return 0, 0, fmt.Errorf("invalid circuit-breaker timeout %q", policy.Timeout)
		}
		timeout = parsed
	}
	return threshold, timeout, nil
}

func (t *BreakerTransport) applyCircuitBreakerPolicy(threshold int, timeout time.Duration) {
	t.mu.Lock()
	t.threshold = threshold
	t.timeout = timeout
	t.breakers = make(map[string]*CircuitBreaker)
	t.mu.Unlock()
}

// ReloadInfrastructure updates request metadata that is emitted by the proxy
// without rebuilding the listener or dropping established Origin connections.
func (t *BreakerTransport) ReloadInfrastructure(cfg config.InfrastructureConfig) {
	if t == nil || t.runtime == nil {
		return
	}
	t.runtime.reloadInfrastructure(cfg)
}

// ResetBreakers discards state for removed/reconfigured Origins so a URL that
// is later re-added never inherits stale failure history.
func (t *BreakerTransport) ResetBreakers() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.breakers = make(map[string]*CircuitBreaker)
	t.mu.Unlock()
}

func (t *BreakerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	breaker := t.breakerFor(req)
	if !breaker.Allow() {
		return nil, fmt.Errorf("circuit breaker open")
	}

	resp, err := t.RoundTripper.RoundTrip(req)

	// Record result
	// Network errors or 5xx status codes count as failures
	success := err == nil && resp != nil && resp.StatusCode < 500
	breaker.RecordResult(success)

	return resp, err
}

func (t *BreakerTransport) breakerFor(req *http.Request) *CircuitBreaker {
	key := proxyTargetKey(req)
	t.mu.RLock()
	breaker := t.breakers[key]
	t.mu.RUnlock()
	if breaker != nil {
		return breaker
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.breakers == nil {
		t.breakers = make(map[string]*CircuitBreaker)
	}
	if breaker = t.breakers[key]; breaker == nil {
		threshold := t.threshold
		if threshold <= 0 {
			threshold = 5
		}
		timeout := t.timeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		breaker = &CircuitBreaker{threshold: threshold, timeout: timeout}
		t.breakers[key] = breaker
	}
	return breaker
}

// GetStatus returns an aggregate operational view without coupling the
// availability decision of unrelated targets.
func (t *BreakerTransport) GetStatus() (string, int) {
	if t == nil {
		return "unknown", 0
	}
	t.mu.RLock()
	breakers := make([]*CircuitBreaker, 0, len(t.breakers))
	for _, breaker := range t.breakers {
		breakers = append(breakers, breaker)
	}
	t.mu.RUnlock()
	status := "closed"
	failures := 0
	for _, breaker := range breakers {
		state, count := breaker.GetStatus()
		failures += count
		if state == "open" {
			status = "open"
		} else if state == "half-open" && status == "closed" {
			status = "half-open"
		}
	}
	return status, failures
}

func proxyTargetKey(req *http.Request) string {
	if attempt := proxyAttemptFromRequest(req); attempt != nil && attempt.targetURL != "" {
		return attempt.targetURL
	}
	if req == nil || req.URL == nil {
		return "unknown"
	}
	return req.URL.Scheme + "://" + req.URL.Host
}

type routeRetryTransport struct {
	next http.RoundTripper
}

func (t routeRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	retries, _ := req.Context().Value(routeRetryKey{}).(int)
	if retries <= 0 || !routeRequestRetryable(req) {
		return t.next.RoundTrip(req)
	}
	if retries > config.MaxRouteRetries {
		retries = config.MaxRouteRetries
	}
	excluded := make(map[string]struct{}, retries)
	for attempt := 0; ; attempt++ {
		attemptRequest, err := cloneRouteRetryRequest(req, attempt)
		if err != nil {
			return nil, err
		}
		if attempt > 0 {
			plan, _ := req.Context().Value(routeRetryPlanKey{}).(*routeRetryPlan)
			selected := selectRetryTarget(attemptRequest, plan, excluded)
			if selected == nil && len(excluded) > 0 {
				clear(excluded)
				selected = selectRetryTarget(attemptRequest, plan, excluded)
			}
			if selected == nil {
				return nil, errRouteTargetUnavailable
			}
			applySelectedProxyTarget(attemptRequest, selected, plan)
		}
		response, roundTripErr := t.next.RoundTrip(attemptRequest)
		if attempt >= retries || !routeResponseRetryable(response, roundTripErr) {
			if roundTripErr != nil {
				if current := proxyAttemptFromRequest(attemptRequest); current != nil {
					current.release()
				}
			}
			return response, roundTripErr
		}
		if current := proxyAttemptFromRequest(attemptRequest); current != nil {
			excluded[current.targetURL] = struct{}{}
			current.release()
		}
		if response != nil && response.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
			_ = response.Body.Close()
		}
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
	}
}

func routeRequestRetryable(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return req.Header.Get("Idempotency-Key") != "" && (req.Body == nil || req.GetBody != nil)
}

func routeResponseRetryable(response *http.Response, err error) bool {
	return err != nil || (response != nil && response.StatusCode >= 500)
}

func cloneRouteRetryRequest(req *http.Request, attempt int) (*http.Request, error) {
	if attempt == 0 {
		return req, nil
	}
	cloned := req.Clone(req.Context())
	if req.Body != nil {
		if req.GetBody == nil {
			return nil, errors.New("request body cannot be replayed")
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		cloned.Body = body
	}
	return cloned, nil
}

func cleanupRouteProxyRequest(req *http.Request) {
	if attempt := proxyAttemptFromRequest(req); attempt != nil {
		attempt.release()
	}
	cancelRouteTimeout(req)
}

func proxyAttemptFromRequest(req *http.Request) *routeProxyAttempt {
	if req == nil {
		return nil
	}
	attempt, _ := req.Context().Value(routeProxyAttemptKey{}).(*routeProxyAttempt)
	return attempt
}

func cancelRouteTimeout(req *http.Request) {
	if cancel, ok := req.Context().Value(routeTimeoutCancelKey{}).(context.CancelFunc); ok {
		cancel()
	}
}

func applyRouteRuntimeContext(req *http.Request, rule config.RouteConfig, plan *routeRetryPlan, attempt *routeProxyAttempt) {
	ctx := req.Context()
	if rule.Action.Retries > 0 {
		ctx = context.WithValue(ctx, routeRetryKey{}, rule.Action.Retries)
		ctx = context.WithValue(ctx, routeRetryPlanKey{}, plan)
	}
	if attempt != nil {
		ctx = context.WithValue(ctx, routeProxyAttemptKey{}, attempt)
	}
	if rule.Action.Timeout != "" {
		if timeout, err := time.ParseDuration(rule.Action.Timeout); err == nil && timeout > 0 {
			timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
			ctx = context.WithValue(timeoutCtx, routeTimeoutCancelKey{}, context.CancelFunc(cancel))
		}
	}
	*req = *req.WithContext(ctx)
}

func selectNamedUpstream(req *http.Request, upstreamMgr *UpstreamManager, name string, excluded map[string]struct{}, allowSticky bool) (*Target, *UpstreamGroup) {
	if upstreamMgr == nil || name == "" {
		return nil, nil
	}
	group := upstreamMgr.GetGroup(name)
	if group == nil {
		return nil, nil
	}
	if allowSticky {
		sticky := group.SelectStickyTarget(req, upstreamMgr.StickyManager())
		if sticky != nil && upstreamTargetExcluded(sticky, excluded) {
			sticky = nil
		}
		if sticky != nil {
			if group.Strategy == "least_conn" {
				atomic.AddInt64(&sticky.ActiveConns, 1)
			}
			return sticky, group
		}
	}
	return group.SelectTargetExcluding(req, excluded), group
}

func selectRouteProxyTarget(req *http.Request, plan *routeRetryPlan, excluded map[string]struct{}, allowSticky bool) *selectedProxyTarget {
	if plan == nil {
		return nil
	}
	if plan.upstreamName != "" {
		target, group := selectNamedUpstream(req, plan.upstreamMgr, plan.upstreamName, excluded, allowSticky)
		if target != nil {
			return &selectedProxyTarget{
				url: target.URL,
				attempt: &routeProxyAttempt{
					targetURL: target.URL.String(),
					group:     group,
				},
			}
		}
	}
	if plan.route == nil || plan.router == nil {
		if plan.fallbackURL == nil {
			return nil
		}
		if _, blocked := excluded[plan.fallbackURL.String()]; blocked {
			return nil
		}
		return &selectedProxyTarget{
			url:     plan.fallbackURL,
			attempt: &routeProxyAttempt{targetURL: plan.fallbackURL.String()},
		}
	}
	selection := plan.router.selectInlineBackendExcluding(plan.route, plan.client, excluded)
	if selection == nil {
		if plan.fallbackURL == nil {
			return nil
		}
		if _, blocked := excluded[plan.fallbackURL.String()]; blocked {
			return nil
		}
		return &selectedProxyTarget{
			url:     plan.fallbackURL,
			attempt: &routeProxyAttempt{targetURL: plan.fallbackURL.String()},
		}
	}
	return &selectedProxyTarget{
		url: selection.target.url,
		attempt: &routeProxyAttempt{
			targetURL:       selection.target.url.String(),
			inlineSelection: selection,
		},
	}
}

func selectRetryTarget(req *http.Request, plan *routeRetryPlan, excluded map[string]struct{}) *selectedProxyTarget {
	return selectRouteProxyTarget(req, plan, excluded, false)
}

func applySelectedProxyTarget(req *http.Request, selected *selectedProxyTarget, plan *routeRetryPlan) {
	if req == nil || selected == nil || selected.url == nil || plan == nil {
		return
	}
	ctx := context.WithValue(req.Context(), routeProxyAttemptKey{}, selected.attempt)
	*req = *req.WithContext(ctx)
	applyProxyTarget(req, selected.url, plan.routedPath, plan.routedRawPath, plan.routedQuery, plan.originalHost, plan.preserveHost)
}

func applyProxyTarget(req *http.Request, target *url.URL, routedPath, routedRawPath, routedQuery, originalHost string, preserveHost bool) {
	if req == nil || req.URL == nil || target == nil {
		return
	}
	requestPath := &url.URL{Path: routedPath, RawPath: routedRawPath}
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.URL.Path, req.URL.RawPath = joinProxyURLPath(target, requestPath)
	switch {
	case target.RawQuery == "":
		req.URL.RawQuery = routedQuery
	case routedQuery == "":
		req.URL.RawQuery = target.RawQuery
	default:
		req.URL.RawQuery = target.RawQuery + "&" + routedQuery
	}
	if preserveHost {
		req.Host = originalHost
	} else {
		req.Host = target.Host
	}
}

// joinProxyURLPath mirrors the standard reverse-proxy path joining contract,
// including escaped paths, so Origin base paths are never discarded.
func joinProxyURLPath(target, request *url.URL) (string, string) {
	if target.RawPath == "" && request.RawPath == "" {
		targetSlash := strings.HasSuffix(target.Path, "/")
		requestSlash := strings.HasPrefix(request.Path, "/")
		switch {
		case targetSlash && requestSlash:
			return target.Path + request.Path[1:], ""
		case !targetSlash && !requestSlash:
			return target.Path + "/" + request.Path, ""
		default:
			return target.Path + request.Path, ""
		}
	}
	targetPath := target.EscapedPath()
	requestPath := request.EscapedPath()
	targetSlash := strings.HasSuffix(targetPath, "/")
	requestSlash := strings.HasPrefix(requestPath, "/")
	switch {
	case targetSlash && requestSlash:
		return target.Path + request.Path[1:], targetPath + requestPath[1:]
	case !targetSlash && !requestSlash:
		return target.Path + "/" + request.Path, targetPath + "/" + requestPath
	default:
		return target.Path + request.Path, targetPath + requestPath
	}
}

func stripClientAegisHeaders(headers http.Header) {
	for name := range headers {
		if strings.HasPrefix(strings.ToLower(name), "x-aegis-") {
			headers.Del(name)
		}
	}
}

// NewProxy creates a new Reverse Proxy supported by dynamic routing and load balancing.
func NewProxy(fallbackTarget string, routes map[string]string, rules []config.RouteConfig, upstreamMgr *UpstreamManager, timeoutStr string, insecureSkipVerify bool, cbCfg config.CircuitBreakerConfig, infraCfg config.InfrastructureConfig) (*httputil.ReverseProxy, *Router, error) {
	return NewProxyWithRouter(fallbackTarget, routes, NewRouter(rules), upstreamMgr, timeoutStr, insecureSkipVerify, cbCfg, infraCfg)
}

func NewProxyWithRouter(fallbackTarget string, routes map[string]string, router *Router, upstreamMgr *UpstreamManager, timeoutStr string, insecureSkipVerify bool, cbCfg config.CircuitBreakerConfig, infraCfg config.InfrastructureConfig) (*httputil.ReverseProxy, *Router, error) {
	runtimeConfig := config.UpstreamConfig{
		Target:             fallbackTarget,
		Routes:             routes,
		InsecureSkipVerify: insecureSkipVerify,
		CircuitBreaker:     cbCfg,
	}
	proxyRuntime, err := newProxyRuntime(fallbackTarget, routes, runtimeConfig, timeoutStr)
	if err != nil {
		return nil, nil, err
	}
	proxyRuntime.reloadInfrastructure(infraCfg)

	if router == nil {
		router = NewRouter(nil)
	}
	// Create a Director that handles routing
	director := func(req *http.Request) {
		stripClientAegisHeaders(req.Header)
		var targetURL *url.URL
		var selectedRule *config.RouteConfig
		var selectedAttempt *routeProxyAttempt
		var retryPlan *routeRetryPlan
		preserveHost := false
		routeTargetRequired := false
		originalHost := req.Host
		clientInfo := clientInfoFromIdentity(req)
		var resolved routeResolution
		if matched, ok := RouteFromRequest(req); ok {
			clientInfo = matched.ClientInfo
			compiled := matched.compiled
			if compiled == nil {
				compiled = compileRoute(config.NormalizeRouteConfig(matched.Rule))
			}
			resolved = routeResolution{route: compiled}
		} else {
			resolved = router.resolveWithClient(req, clientInfo)
		}
		req.Header.Set("X-Aegis-Client-IP", clientInfo.IP)
		req.Header.Set("X-Aegis-Deployment-Mode", proxyRuntime.infrastructureConfig().Mode)

		// A protected disabled route is terminal and must never fall through to
		// a legacy or global origin.
		if resolved.disabled {
			ctx := context.WithValue(req.Context(), routeResolutionErrorKey{}, "protected route is disabled")
			*req = *req.WithContext(ctx)
			return
		}

		// 0. Apply the route decision already produced by Route Context. Direct
		// proxy users resolve here once as a compatibility fallback.
		if resolved.route != nil {
			rule := &resolved.route.rule
			selectedRule = rule
			req.Header.Set("X-Aegis-Route-ID", rule.ID)
			req.Header.Set("X-Aegis-Route-Name", rule.Name)
			preserveHost = rule.Action.PreserveHost

			// Apply StripPrefix
			if stripPrefix := routeStripPrefix(*rule); stripPrefix != "" {
				if strings.HasPrefix(req.URL.Path, stripPrefix) {
					req.URL.Path = strings.TrimPrefix(req.URL.Path, stripPrefix)
					req.URL.RawPath = ""
					if req.URL.Path == "" {
						req.URL.Path = "/"
					}
				}
			}
			if rule.Action.RewritePath != "" {
				req.URL.Path = rule.Action.RewritePath
				req.URL.RawPath = ""
			}

			// Select a named Origin first, then an explicitly configured inline
			// backend using the route's real strategy and precompiled URLs.
			upstreamName := routeUpstream(*rule)
			backends := routeBackends(*rule)
			routeTargetRequired = upstreamName != "" || len(backends) > 0
			retryPlan = &routeRetryPlan{
				router:        router,
				upstreamMgr:   upstreamMgr,
				route:         resolved.route,
				client:        clientInfo,
				upstreamName:  upstreamName,
				routedPath:    req.URL.Path,
				routedRawPath: req.URL.RawPath,
				routedQuery:   req.URL.RawQuery,
				originalHost:  originalHost,
				preserveHost:  preserveHost,
			}
			if selected := selectRouteProxyTarget(req, retryPlan, nil, true); selected != nil {
				targetURL = selected.url
				selectedAttempt = selected.attempt
			}

			if routeTargetRequired && targetURL == nil {
				ctx := context.WithValue(req.Context(), routeResolutionErrorKey{}, fmt.Sprintf("route %q matched but no target backend was available", rule.ID))
				*req = *req.WithContext(ctx)
				return
			}
		}

		// 1. Check Legacy/Simple Host Routing if no advanced rule matched (or rule had no backends)
		if targetURL == nil && !routeTargetRequired {
			host, _, _ := net.SplitHostPort(req.Host)
			if host == "" {
				host = req.Host // Fallback if no port
			}

			if routeTarget, ok := proxyRuntime.legacyRoutes()[host]; ok {
				if target, group := selectNamedUpstream(req, upstreamMgr, routeTarget, nil, true); target != nil {
					targetURL = target.URL
					selectedAttempt = &routeProxyAttempt{targetURL: target.URL.String(), group: group}
					if retryPlan != nil && !routeTargetRequired {
						retryPlan.upstreamName = routeTarget
					}
				}

				// 2. If not a group, try parsing as URL
				if targetURL == nil {
					if parsed, err := url.Parse(routeTarget); err == nil && parsed.Scheme != "" {
						targetURL = parsed
						if retryPlan != nil && !routeTargetRequired {
							retryPlan.fallbackURL = parsed
						}
					}
				}
			}
		}

		// 3. Fallback to Default Target
		if targetURL == nil {
			targetURL = proxyRuntime.fallback()
			if retryPlan != nil && !routeTargetRequired {
				retryPlan.fallbackURL = targetURL
			}
		}

		// If still nil (no default), we can't proxy.
		if targetURL == nil {
			return
		}

		if selectedAttempt == nil {
			selectedAttempt = &routeProxyAttempt{targetURL: targetURL.String()}
		}
		if retryPlan == nil {
			retryPlan = &routeRetryPlan{
				routedPath:    req.URL.Path,
				routedRawPath: req.URL.RawPath,
				routedQuery:   req.URL.RawQuery,
				originalHost:  originalHost,
				preserveHost:  preserveHost,
				fallbackURL:   targetURL,
			}
		}
		applyProxyTarget(req, targetURL, retryPlan.routedPath, retryPlan.routedRawPath, retryPlan.routedQuery, retryPlan.originalHost, retryPlan.preserveHost)
		if selectedRule != nil {
			applyRouteRuntimeContext(req, *selectedRule, retryPlan, selectedAttempt)
		} else {
			ctx := context.WithValue(req.Context(), routeProxyAttemptKey{}, selectedAttempt)
			*req = *req.WithContext(ctx)
		}

		// Forwarding headers
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}

		// Set Standard Proxy Headers
		req.Header.Del("Forwarded")
		req.Header.Del("X-Forwarded-For")
		if clientIP := clientInfo.IP; clientIP != "" {
			// ReverseProxy appends the immediate TCP peer after Director runs.
			// Seed only the canonical client when it differs from that peer.
			if clientIP != clientInfo.ImmediatePeer {
				req.Header.Set("X-Forwarded-For", clientIP)
			}

			// X-Real-IP is always reconstructed from the canonical identity.
			req.Header.Set("X-Real-IP", clientIP)
		}
		if clientInfo.ForwardedProto != "" {
			req.Header.Set("X-Forwarded-Proto", clientInfo.ForwardedProto)
		} else {
			req.Header.Set("X-Forwarded-Proto", clientInfo.OriginalProto)
		}
		if clientInfo.ForwardedHost != "" {
			req.Header.Set("X-Forwarded-Host", clientInfo.ForwardedHost)
		} else if clientInfo.OriginalHost != "" {
			req.Header.Set("X-Forwarded-Host", clientInfo.OriginalHost)
		}

		routeName := ""
		routeID := ""
		if selectedRule != nil {
			routeName = selectedRule.Name
			routeID = selectedRule.ID
		}
		ctx := context.WithValue(req.Context(), proxyLogContextKey{}, proxyLogContext{
			start:      time.Now(),
			clientInfo: clientInfo,
			routeName:  routeName,
			routeID:    routeID,
		})
		*req = *req.WithContext(ctx)
	}

	proxy := &httputil.ReverseProxy{Director: director}

	// Wrap with Circuit Breaker (configurable)
	cbThreshold := cbCfg.Threshold
	if cbThreshold <= 0 {
		cbThreshold = 5
	}
	cbTimeout := 30 * time.Second
	if cbCfg.Timeout != "" {
		if d, err := time.ParseDuration(cbCfg.Timeout); err == nil {
			cbTimeout = d
		}
	}

	breakerTransport := &BreakerTransport{
		RoundTripper: proxyRuntime,
		runtime:      proxyRuntime,
		threshold:    cbThreshold,
		timeout:      cbTimeout,
		breakers:     make(map[string]*CircuitBreaker),
	}
	proxy.Transport = routeResolutionGuard{next: routeRetryTransport{next: breakerTransport}}

	// Custom Error Handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		cleanupRouteProxyRequest(r)
		if telemetry.Logger != nil {
			telemetry.Logger.Warn("Proxy error",
				zap.Error(err),
				zap.String("path", r.URL.Path),
				zap.String("remote", r.RemoteAddr),
			)
		}
		status := http.StatusBadGateway
		message := "502 Bad Gateway - Aegis"
		if reason, ok := r.Context().Value(routeResolutionErrorKey{}).(string); ok && reason == "protected route is disabled" {
			status = http.StatusServiceUnavailable
			message = "503 Service Unavailable - protected route is disabled"
			w.Header().Set("Retry-After", "60")
		}
		enrichCanonicalRequestEvent(r, "")
		if WriteConfiguredErrorPage(w, r, status) {
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(message))
	}

	// ModifyResponse to set Sticky Cookie and handle connection tracking
	proxy.ModifyResponse = func(resp *http.Response) error {
		attempt := proxyAttemptFromRequest(resp.Request)
		targetURLStr := ""
		if attempt != nil {
			targetURLStr = attempt.targetURL
		}
		enrichCanonicalRequestEvent(resp.Request, targetURLStr)
		if ReplaceConfiguredErrorResponse(resp) {
			cleanupRouteProxyRequest(resp.Request)
			return nil
		}

		// Set/Refresh Sticky Cookie
		if resp.StatusCode < http.StatusInternalServerError && attempt != nil && attempt.targetURL != "" && attempt.group != nil && upstreamMgr != nil {
			group := attempt.group
			if group.Sticky.Enabled {
				stickyManager := upstreamMgr.StickyManager()
				if stickyManager == nil || group.stickyCookieMatches(resp.Request, stickyManager, attempt.targetURL) {
					cleanupRouteProxyRequest(resp.Request)
					return nil
				}
				cookieVal := stickyManager.GenerateCookieForGroup(group.Name, attempt.targetURL)
				cookieName := StickyCookieName(group.Name, group.Sticky.Cookie)

				ttl := 24 * time.Hour
				if group.Sticky.TTL != "" {
					if d, err := time.ParseDuration(group.Sticky.TTL); err == nil {
						ttl = d
					}
				}

				cookie := &http.Cookie{
					Name:     cookieName,
					Value:    cookieVal,
					Path:     "/",
					Expires:  time.Now().Add(ttl),
					HttpOnly: true,
					Secure:   strings.EqualFold(resp.Request.Header.Get("X-Forwarded-Proto"), "https"),
					SameSite: http.SameSiteLaxMode,
				}

				resp.Header.Add("Set-Cookie", cookie.String())
			}
		}

		cleanupRouteProxyRequest(resp.Request)

		return nil
	}

	return proxy, router, nil
}

func BreakerTransportFrom(rt http.RoundTripper) *BreakerTransport {
	switch transport := rt.(type) {
	case *BreakerTransport:
		return transport
	case routeResolutionGuard:
		switch next := transport.next.(type) {
		case *BreakerTransport:
			return next
		case routeRetryTransport:
			if breaker, ok := next.next.(*BreakerTransport); ok {
				return breaker
			}
		}
	case routeRetryTransport:
		if breaker, ok := transport.next.(*BreakerTransport); ok {
			return breaker
		}
	}
	return nil
}

func enrichCanonicalRequestEvent(r *http.Request, upstream string) {
	if r == nil {
		return
	}
	logCtx, _ := r.Context().Value(proxyLogContextKey{}).(proxyLogContext)
	clientInfo := logCtx.clientInfo
	if clientInfo.IP == "" {
		clientInfo = ClientInfo{IP: hostWithoutPort(r.RemoteAddr)}
	}
	telemetry.UpdateRequestLogMetadata(r, telemetry.RequestLogMetadata{
		Host:      firstNonEmptyString(clientInfo.OriginalHost, r.Host),
		RuleID:    logCtx.routeID,
		RuleName:  logCtx.routeName,
		RuleType:  "route",
		Upstream:  upstream,
		RouteName: logCtx.routeName,
	})
}

func clientInfoFromIdentity(r *http.Request) ClientInfo {
	if identity, ok := requestctx.FromRequest(r); ok {
		return ClientInfo{
			IP: identity.ClientIP, Source: identity.Source, TrustedProxy: identity.TrustedProxy,
			ImmediatePeer: identity.ImmediatePeer, OriginalHost: identity.OriginalHost, OriginalProto: identity.OriginalProto,
			ForwardedHost: identity.ForwardedHost, ForwardedProto: identity.ForwardedProto,
			RejectedHeaderHint: identity.RejectedHeaderHint, ProxyChain: identity.ProxyChain,
		}
	}
	peer := hostWithoutPort(r.RemoteAddr)
	return ClientInfo{IP: peer, Source: "remote_addr", ImmediatePeer: peer, OriginalHost: r.Host, OriginalProto: requestProto(r)}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

type routeResolutionGuard struct {
	next http.RoundTripper
}

func (g routeResolutionGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Context().Value(routeResolutionErrorKey{}) != nil {
		return nil, errRouteTargetUnavailable
	}
	return g.next.RoundTrip(req)
}
