package transport

import (
	"hash/fnv"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/divinelab-io/aegis/internal/infra/config"
)

// Router publishes immutable, precompiled route tables. Request matching is
// lock-free; route normalization, URL parsing, and CIDR parsing occur only when
// configuration changes.
type Router struct {
	snapshot atomic.Pointer[routeSnapshot]
}

type routeSnapshot struct {
	rules     []*compiledRoute
	configs   []config.RouteConfig
	hostIndex routeHostIndex
}

type routeHostIndex struct {
	exact    map[string][]*compiledRoute
	wildcard map[string][]*compiledRoute
	fallback []*compiledRoute
}

type compiledRoute struct {
	rule           config.RouteConfig
	hosts          []string
	paths          []string
	methods        []string
	headers        map[string][]string
	query          map[string][]string
	sourceAny      bool
	sourcePrefixes []netip.Prefix
	sourceAddrs    []netip.Addr
	backends       []*compiledBackend
	rank           int
	next           atomic.Uint64
}

type compiledBackend struct {
	target config.UpstreamTarget
	url    *url.URL
	active atomic.Int64
}

type routeResolution struct {
	route    *compiledRoute
	disabled bool
}

type inlineBackendSelection struct {
	target   *compiledBackend
	strategy string
	released atomic.Bool
}

const maxRouteCandidateLists = 16

// routeCandidateCursor merges pre-sorted host buckets without allocating on
// the request path. Hostnames with an unusually deep wildcard hierarchy fall
// back to the complete, already sorted snapshot to preserve exact semantics.
type routeCandidateCursor struct {
	lists     [maxRouteCandidateLists][]*compiledRoute
	positions [maxRouteCandidateLists]int
	count     int
}

// NewRouter creates a router with a fully compiled initial snapshot.
func NewRouter(rules []config.RouteConfig) *Router {
	router := &Router{}
	router.UpdateRules(rules)
	return router
}

// UpdateRules compiles then atomically publishes a new routing table.
func (r *Router) UpdateRules(rules []config.RouteConfig) {
	if r == nil {
		return
	}
	configs := config.CloneRouteConfigs(rules)
	compiled := make([]*compiledRoute, 0, len(configs))
	for index := range configs {
		configs[index] = config.NormalizeRouteConfig(configs[index])
		compiled = append(compiled, compileRoute(configs[index]))
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		return compiled[i].rule.Priority < compiled[j].rule.Priority
	})
	sort.SliceStable(configs, func(i, j int) bool {
		return configs[i].Priority < configs[j].Priority
	})
	for index, route := range compiled {
		route.rank = index
	}
	r.snapshot.Store(&routeSnapshot{
		rules:     compiled,
		configs:   configs,
		hostIndex: buildRouteHostIndex(compiled),
	})
}

func buildRouteHostIndex(routes []*compiledRoute) routeHostIndex {
	index := routeHostIndex{
		exact:    make(map[string][]*compiledRoute),
		wildcard: make(map[string][]*compiledRoute),
	}
	for _, route := range routes {
		if len(route.hosts) == 0 {
			index.fallback = append(index.fallback, route)
			continue
		}

		fallback := false
		for _, pattern := range route.hosts {
			switch {
			case pattern == "" || pattern == "*":
				fallback = true
			case strings.HasPrefix(pattern, "*."):
				index.wildcard[pattern[1:]] = append(index.wildcard[pattern[1:]], route)
			default:
				index.exact[pattern] = append(index.exact[pattern], route)
			}
		}
		if fallback {
			index.fallback = append(index.fallback, route)
		}
	}
	return index
}

func (snapshot *routeSnapshot) candidatesForHost(host string) routeCandidateCursor {
	var cursor routeCandidateCursor
	if snapshot == nil {
		return cursor
	}
	if !cursor.add(snapshot.hostIndex.exact[host]) {
		cursor.reset(snapshot.rules)
		return cursor
	}

	for suffixStart := strings.IndexByte(host, '.'); suffixStart >= 0; {
		if !cursor.add(snapshot.hostIndex.wildcard[host[suffixStart:]]) {
			cursor.reset(snapshot.rules)
			return cursor
		}
		nextDot := strings.IndexByte(host[suffixStart+1:], '.')
		if nextDot < 0 {
			break
		}
		suffixStart += nextDot + 1
	}
	if !cursor.add(snapshot.hostIndex.fallback) {
		cursor.reset(snapshot.rules)
	}
	return cursor
}

func (cursor *routeCandidateCursor) add(routes []*compiledRoute) bool {
	if len(routes) == 0 {
		return true
	}
	if cursor.count == len(cursor.lists) {
		return false
	}
	cursor.lists[cursor.count] = routes
	cursor.count++
	return true
}

func (cursor *routeCandidateCursor) reset(routes []*compiledRoute) {
	*cursor = routeCandidateCursor{}
	_ = cursor.add(routes)
}

func (cursor *routeCandidateCursor) next() *compiledRoute {
	var selected *compiledRoute
	for index := 0; index < cursor.count; index++ {
		if cursor.positions[index] >= len(cursor.lists[index]) {
			continue
		}
		candidate := cursor.lists[index][cursor.positions[index]]
		if selected == nil || candidate.rank < selected.rank {
			selected = candidate
		}
	}
	if selected == nil {
		return nil
	}
	for index := 0; index < cursor.count; index++ {
		for cursor.positions[index] < len(cursor.lists[index]) && cursor.lists[index][cursor.positions[index]] == selected {
			cursor.positions[index]++
		}
	}
	return selected
}

// Match finds the first enabled route for a request.
func (r *Router) Match(req *http.Request) *config.RouteConfig {
	if req == nil {
		return nil
	}
	return r.MatchWithClient(req, ClientInfo{IP: hostWithoutPort(req.RemoteAddr)})
}

// MatchWithClient finds the first enabled route for a request using the trusted
// client identity supplied by the identity middleware.
func (r *Router) MatchWithClient(req *http.Request, client ClientInfo) *config.RouteConfig {
	resolved := r.resolveWithClient(req, client)
	if resolved.route == nil || resolved.disabled {
		return nil
	}
	return &resolved.route.rule
}

func (r *Router) resolveWithClient(req *http.Request, client ClientInfo) routeResolution {
	if r == nil || req == nil {
		return routeResolution{}
	}
	snapshot := r.snapshot.Load()
	if snapshot == nil {
		return routeResolution{}
	}

	host := normalizeRouteHost(req.Host)
	requestPath := req.URL.Path
	var query url.Values
	queryParsed := false
	var clientAddr netip.Addr
	clientParsed := false
	var protectedDisabled *compiledRoute

	candidates := snapshot.candidatesForHost(host)
	for route := candidates.next(); route != nil; route = candidates.next() {
		if !matchCompiledHost(route.hosts, host) ||
			!matchCompiledPath(route.paths, requestPath) ||
			!matchCompiledAnyFolded(route.methods, req.Method) ||
			!matchCompiledHeaderMap(route.headers, req.Header) {
			continue
		}
		if len(route.query) > 0 {
			if !queryParsed {
				query = req.URL.Query()
				queryParsed = true
			}
			if !matchCompiledQueryMap(route.query, query) {
				continue
			}
		}
		if len(route.sourcePrefixes) > 0 || len(route.sourceAddrs) > 0 {
			if !clientParsed {
				clientAddr, _ = netip.ParseAddr(strings.TrimSpace(client.IP))
				clientParsed = true
			}
			if !matchCompiledSource(route, clientAddr) {
				continue
			}
		}

		if route.rule.Enabled {
			return routeResolution{route: route}
		}
		if protectedDisabled == nil && routeAccessControlEnabled(route.rule) {
			protectedDisabled = route
		}
	}
	if protectedDisabled != nil {
		return routeResolution{route: protectedDisabled, disabled: true}
	}
	return routeResolution{}
}

// Rules returns an isolated configuration snapshot.
func (r *Router) Rules() []config.RouteConfig {
	if r == nil {
		return nil
	}
	snapshot := r.snapshot.Load()
	if snapshot == nil {
		return nil
	}
	return config.CloneRouteConfigs(snapshot.configs)
}

func compileRoute(rule config.RouteConfig) *compiledRoute {
	compiled := &compiledRoute{
		rule:    rule,
		hosts:   normalizeRouteHosts(routeHosts(rule)),
		paths:   normalizeRoutePaths(routePaths(rule)),
		methods: append([]string(nil), rule.Match.Methods...),
		headers: compileRouteValueMap(rule.Match.Headers, true),
		query:   compileRouteValueMap(rule.Match.Query, false),
	}
	for _, raw := range rule.Match.SourceCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "*" || raw == "" {
			compiled.sourceAny = true
			continue
		}
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			compiled.sourcePrefixes = append(compiled.sourcePrefixes, prefix)
			continue
		}
		if address, err := netip.ParseAddr(raw); err == nil {
			compiled.sourceAddrs = append(compiled.sourceAddrs, address)
		}
	}
	for _, backend := range routeBackends(rule) {
		parsed, err := url.Parse(backend.URL)
		if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			continue
		}
		target := &compiledBackend{target: backend, url: parsed}
		if target.target.Weight <= 0 {
			target.target.Weight = 1
		}
		compiled.backends = append(compiled.backends, target)
	}
	return compiled
}

func (r *Router) selectInlineBackendExcluding(route *compiledRoute, client ClientInfo, excluded map[string]struct{}) *inlineBackendSelection {
	if route == nil || len(route.backends) == 0 {
		return nil
	}
	strategy := routeStrategy(route.rule)
	var target *compiledBackend
	switch strategy {
	case "weighted_rr":
		target = selectInlineWeighted(route, excluded)
	case "least_conn":
		for _, candidate := range route.backends {
			if inlineBackendExcluded(candidate, excluded) {
				continue
			}
			if target == nil || candidate.active.Load() < target.active.Load() {
				target = candidate
			}
		}
		if target != nil {
			target.active.Add(1)
		}
	case "ip_hash":
		hash := fnv.New32a()
		_, _ = hash.Write([]byte(strings.TrimSpace(client.IP)))
		available := 0
		for _, candidate := range route.backends {
			if !inlineBackendExcluded(candidate, excluded) {
				available++
			}
		}
		if available > 0 {
			wanted := int(hash.Sum32() % uint32(available))
			for _, candidate := range route.backends {
				if inlineBackendExcluded(candidate, excluded) {
					continue
				}
				if wanted == 0 {
					target = candidate
					break
				}
				wanted--
			}
		}
	default:
		start := route.next.Add(1) - 1
		for offset := 0; offset < len(route.backends); offset++ {
			candidate := route.backends[(int(start)+offset)%len(route.backends)]
			if !inlineBackendExcluded(candidate, excluded) {
				target = candidate
				break
			}
		}
	}
	if target == nil {
		return nil
	}
	return &inlineBackendSelection{target: target, strategy: strategy}
}

// selectInlineWeighted preserves the original contiguous weighted round-robin
// order without materializing one pointer per configured weight.
func selectInlineWeighted(route *compiledRoute, excluded map[string]struct{}) *compiledBackend {
	if route == nil || len(route.backends) == 0 {
		return nil
	}
	var totalWeight uint64
	for _, candidate := range route.backends {
		weight := candidate.target.Weight
		if weight <= 0 {
			weight = 1
		}
		totalWeight += uint64(weight)
	}
	if totalWeight == 0 {
		return nil
	}

	selectedWeight := (route.next.Add(1) - 1) % totalWeight
	start := 0
	for index, candidate := range route.backends {
		weight := candidate.target.Weight
		if weight <= 0 {
			weight = 1
		}
		if selectedWeight < uint64(weight) {
			start = index
			break
		}
		selectedWeight -= uint64(weight)
	}
	for offset := 0; offset < len(route.backends); offset++ {
		candidate := route.backends[(start+offset)%len(route.backends)]
		if !inlineBackendExcluded(candidate, excluded) {
			return candidate
		}
	}
	return nil
}

func (selection *inlineBackendSelection) release() {
	if selection != nil && selection.target != nil && selection.strategy == "least_conn" && !selection.released.Swap(true) {
		selection.target.active.Add(-1)
	}
}

func inlineBackendExcluded(target *compiledBackend, excluded map[string]struct{}) bool {
	if target == nil || len(excluded) == 0 {
		return false
	}
	_, blocked := excluded[target.url.String()]
	return blocked
}

func routeHosts(rule config.RouteConfig) []string {
	if len(rule.Match.Hosts) > 0 {
		return rule.Match.Hosts
	}
	return rule.Hosts
}

func routePaths(rule config.RouteConfig) []string {
	if len(rule.Match.Paths) > 0 {
		return rule.Match.Paths
	}
	return rule.Paths
}

func routeStripPrefix(rule config.RouteConfig) string {
	if rule.Action.StripPrefix != "" {
		return rule.Action.StripPrefix
	}
	return rule.StripPrefix
}

// routeUpstream returns only a named reusable Origin group. Strategy names are
// intentionally not treated as group names.
func routeUpstream(rule config.RouteConfig) string {
	if strings.TrimSpace(rule.Action.Upstream) != "" {
		return strings.TrimSpace(rule.Action.Upstream)
	}
	if value := strings.TrimSpace(rule.LoadBalance); value != "" && !config.IsRouteStrategy(value) {
		return value
	}
	return ""
}

func routeStrategy(rule config.RouteConfig) string {
	if config.IsRouteStrategy(rule.Action.Strategy) {
		return strings.ToLower(strings.TrimSpace(rule.Action.Strategy))
	}
	if config.IsRouteStrategy(rule.LoadBalance) {
		return strings.ToLower(strings.TrimSpace(rule.LoadBalance))
	}
	if config.IsRouteStrategy(rule.Action.Upstream) && len(routeBackends(rule)) > 0 {
		return strings.ToLower(strings.TrimSpace(rule.Action.Upstream))
	}
	return "round_robin"
}

func routeBackends(rule config.RouteConfig) []config.UpstreamTarget {
	if len(rule.Action.Backends) > 0 {
		return rule.Action.Backends
	}
	return rule.Backends
}

func routeAccessControlEnabled(rule config.RouteConfig) bool {
	return rule.Security.AccessControl != nil && *rule.Security.AccessControl
}

func normalizeRouteHosts(hosts []string) []string {
	normalized := make([]string, 0, len(hosts))
	for _, host := range hosts {
		normalized = append(normalized, normalizeRouteHost(host))
	}
	return normalized
}

func normalizeRoutePaths(paths []string) []string {
	normalized := make([]string, 0, len(paths))
	for _, path := range paths {
		normalized = append(normalized, strings.TrimSpace(path))
	}
	return normalized
}

func normalizeRouteHost(host string) string {
	host = strings.TrimSpace(host)
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.Trim(host, "[]")
	} else if strings.Count(host, ":") == 1 {
		if cutHost, _, ok := strings.Cut(host, ":"); ok {
			host = cutHost
		}
	}
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

func matchCompiledHost(patterns []string, host string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if pattern == "*" || pattern == "" || pattern == host {
			return true
		}
		if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]) {
			return true
		}
	}
	return false
}

func matchCompiledPath(patterns []string, requestPath string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if pattern == "*" || pattern == "/*" || pattern == "" {
			return true
		}
		if pattern == requestPath {
			return true
		}
		if strings.HasSuffix(pattern, "/*") {
			prefix := pattern[:len(pattern)-1]
			if strings.HasPrefix(requestPath, prefix) || requestPath == pattern[:len(pattern)-2] {
				return true
			}
			continue
		}
		if pattern != "/" && strings.HasSuffix(pattern, "/") && strings.HasPrefix(requestPath, pattern) {
			return true
		}
		if !strings.Contains(pattern, "*") && strings.HasPrefix(requestPath, pattern) {
			if len(requestPath) == len(pattern) || requestPath[len(pattern)] == '/' {
				return true
			}
		}
	}
	return false
}

func matchCompiledAnyFolded(allowed []string, value string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, allowedValue := range allowed {
		if allowedValue == "*" || strings.EqualFold(allowedValue, value) {
			return true
		}
	}
	return false
}

func compileRouteValueMap(values map[string][]string, folded bool) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	compiled := make(map[string][]string, len(values))
	for name, allowed := range values {
		compiledAllowed := make([]string, len(allowed))
		for index, value := range allowed {
			value = strings.TrimSpace(value)
			if folded {
				value = strings.ToLower(value)
			}
			compiledAllowed[index] = value
		}
		compiled[name] = compiledAllowed
	}
	return compiled
}

func matchCompiledHeaderMap(expected map[string][]string, headers http.Header) bool {
	for name, allowed := range expected {
		actualValues := headers.Values(name)
		if len(actualValues) == 0 {
			return false
		}
		if len(allowed) == 0 {
			continue
		}
		matched := false
		for _, actual := range actualValues {
			actual = strings.ToLower(strings.TrimSpace(actual))
			for _, wanted := range allowed {
				if wanted == "*" || actual == wanted {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func matchCompiledQueryMap(expected map[string][]string, query url.Values) bool {
	for name, allowed := range expected {
		actualValues := query[name]
		if len(actualValues) == 0 {
			return false
		}
		if len(allowed) == 0 {
			continue
		}
		matched := false
		for _, actual := range actualValues {
			for _, wanted := range allowed {
				if wanted == "*" || actual == wanted {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func matchCompiledSource(route *compiledRoute, address netip.Addr) bool {
	if route.sourceAny {
		return true
	}
	if !address.IsValid() {
		return false
	}
	for _, expected := range route.sourceAddrs {
		if expected == address {
			return true
		}
	}
	for _, prefix := range route.sourcePrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
