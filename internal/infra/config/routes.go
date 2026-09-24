package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/textproto"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	MaxRouteRules        = 10000
	MaxRouteBackends     = 128
	MaxRouteRetries      = 5
	MaxRouteBodyBytes    = 1 << 20
	defaultRouteStrategy = "round_robin"
)

var supportedRouteStrategies = map[string]struct{}{
	"round_robin": {},
	"weighted_rr": {},
	"least_conn":  {},
	"ip_hash":     {},
}

var (
	ErrRouteValidation  = errors.New("route validation failed")
	ErrRoutePersistence = errors.New("route persistence failed")
)

// IsRouteStrategy reports whether value is a supported inline backend strategy.
func IsRouteStrategy(value string) bool {
	_, ok := supportedRouteStrategies[strings.ToLower(strings.TrimSpace(value))]
	return ok
}

// NormalizeRouteConfig accepts legacy route fields but always returns the
// canonical match/action representation. Mutations therefore rewrite legacy
// configuration instead of keeping two divergent copies of the same rule.
func NormalizeRouteConfig(route RouteConfig) RouteConfig {
	route.ID = strings.TrimSpace(route.ID)
	route.Name = strings.TrimSpace(route.Name)
	legacyHosts := cleanRouteStrings(route.Hosts)
	legacyPaths := cleanRouteStrings(route.Paths)
	legacyBackends := normalizeRouteBackends(route.Backends)
	legacyLoadBalance := strings.TrimSpace(route.LoadBalance)
	legacyStripPrefix := strings.TrimSpace(route.StripPrefix)
	route.Match.Hosts = cleanRouteStrings(route.Match.Hosts)
	route.Match.Paths = cleanRouteStrings(route.Match.Paths)
	route.Match.Methods = normalizeRouteMethods(route.Match.Methods)
	route.Match.SourceCIDRs = cleanRouteStrings(route.Match.SourceCIDRs)
	route.Match.Headers = cleanRouteValueMap(route.Match.Headers)
	route.Match.Query = cleanRouteValueMap(route.Match.Query)
	route.Action.Upstream = strings.TrimSpace(route.Action.Upstream)
	route.Action.Strategy = strings.ToLower(strings.TrimSpace(route.Action.Strategy))
	route.Action.StripPrefix = strings.TrimSpace(route.Action.StripPrefix)
	route.Action.RewritePath = strings.TrimSpace(route.Action.RewritePath)
	route.Action.Timeout = strings.TrimSpace(route.Action.Timeout)

	route.Action.Backends = normalizeRouteBackends(route.Action.Backends)
	if len(route.Match.Hosts) == 0 && len(legacyHosts) > 0 {
		route.Match.Hosts = legacyHosts
	}
	if len(route.Match.Paths) == 0 && len(legacyPaths) > 0 {
		route.Match.Paths = legacyPaths
	}
	if len(route.Action.Backends) == 0 && len(legacyBackends) > 0 {
		route.Action.Backends = legacyBackends
	}
	if route.Action.StripPrefix == "" && legacyStripPrefix != "" {
		route.Action.StripPrefix = legacyStripPrefix
	}

	if route.Action.Strategy == "" && len(route.Action.Backends) > 0 {
		switch {
		case IsRouteStrategy(route.Action.Upstream):
			route.Action.Strategy = strings.ToLower(route.Action.Upstream)
			route.Action.Upstream = ""
		case IsRouteStrategy(legacyLoadBalance):
			route.Action.Strategy = strings.ToLower(legacyLoadBalance)
		default:
			route.Action.Strategy = defaultRouteStrategy
		}
	}
	if route.Action.Upstream == "" && legacyLoadBalance != "" && !IsRouteStrategy(legacyLoadBalance) {
		route.Action.Upstream = legacyLoadBalance
	}

	// The struct retains these fields only to read old self-hosted YAML. Never
	// return or persist them after normalization.
	route.Hosts = nil
	route.Paths = nil
	route.Backends = nil
	route.LoadBalance = ""
	route.StripPrefix = ""
	return route
}

// NormalizeAndValidateRouteConfig returns a canonical route or an actionable
// validation error suitable for an API response.
func NormalizeAndValidateRouteConfig(route RouteConfig, groups []UpstreamGroup) (RouteConfig, error) {
	route = NormalizeRouteConfig(route)
	if err := ValidateRouteConfig(route, groups); err != nil {
		return RouteConfig{}, err
	}
	return route, nil
}

// NormalizeAndValidateRouteRules validates the complete route table, including
// duplicate identifiers and exact matcher conflicts at the same priority.
func NormalizeAndValidateRouteRules(routes []RouteConfig, groups []UpstreamGroup) ([]RouteConfig, error) {
	if len(routes) > MaxRouteRules {
		return nil, fmt.Errorf("route count %d exceeds limit %d", len(routes), MaxRouteRules)
	}
	normalized := make([]RouteConfig, len(routes))
	ids := make(map[string]struct{}, len(routes))
	matchers := make(map[string]string, len(routes))
	for index, route := range routes {
		canonical, err := NormalizeAndValidateRouteConfig(route, groups)
		if err != nil {
			return nil, fmt.Errorf("route %d: %w", index+1, err)
		}
		if _, exists := ids[canonical.ID]; exists {
			return nil, fmt.Errorf("duplicate route id %q", canonical.ID)
		}
		ids[canonical.ID] = struct{}{}
		key, err := routeMatcherKey(canonical)
		if err != nil {
			return nil, fmt.Errorf("route %q matcher: %w", canonical.ID, err)
		}
		if existingID, exists := matchers[key]; exists {
			return nil, fmt.Errorf("route %q conflicts with route %q at priority %d", canonical.ID, existingID, canonical.Priority)
		}
		matchers[key] = canonical.ID
		normalized[index] = canonical
	}
	return normalized, nil
}

func ValidateRouteConfig(route RouteConfig, groups []UpstreamGroup) error {
	if route.ID == "" {
		return fmt.Errorf("id is required")
	}
	if len(route.ID) > 128 || strings.ContainsAny(route.ID, "<>\"'`/\\?#\x00\r\n\t ") {
		return fmt.Errorf("id %q contains invalid characters", route.ID)
	}
	if route.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(route.Name) > 160 || strings.ContainsAny(route.Name, "\x00\r\n") {
		return fmt.Errorf("name is invalid")
	}
	if route.Priority < 1 || route.Priority > 10000 {
		return fmt.Errorf("priority must be between 1 and 10000")
	}

	hosts := route.Match.Hosts
	if len(hosts) == 0 {
		hosts = route.Hosts
	}
	for _, host := range hosts {
		if err := validateRouteHost(host); err != nil {
			return err
		}
	}
	paths := route.Match.Paths
	if len(paths) == 0 {
		paths = route.Paths
	}
	for _, path := range paths {
		if err := validateRoutePath(path, "match path"); err != nil {
			return err
		}
	}
	for _, method := range route.Match.Methods {
		if method != "*" && !validHTTPToken(method) {
			return fmt.Errorf("invalid HTTP method %q", method)
		}
	}
	for name := range route.Match.Headers {
		if textproto.CanonicalMIMEHeaderKey(name) == "" {
			return fmt.Errorf("invalid header matcher name %q", name)
		}
	}
	for name := range route.Match.Query {
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return fmt.Errorf("invalid query matcher name %q", name)
		}
	}
	for _, value := range route.Match.SourceCIDRs {
		if value == "*" {
			continue
		}
		if _, err := netip.ParsePrefix(value); err != nil {
			if _, addressErr := netip.ParseAddr(value); addressErr != nil {
				return fmt.Errorf("invalid source CIDR or IP %q", value)
			}
		}
	}

	backends := route.Action.Backends
	if len(backends) == 0 {
		backends = route.Backends
	}
	if len(backends) > MaxRouteBackends {
		return fmt.Errorf("backend count %d exceeds limit %d", len(backends), MaxRouteBackends)
	}
	for index, backend := range backends {
		if err := validateRouteBackend(backend); err != nil {
			return fmt.Errorf("backend %d: %w", index+1, err)
		}
	}
	if route.Action.Strategy != "" && !IsRouteStrategy(route.Action.Strategy) {
		return fmt.Errorf("unsupported inline strategy %q", route.Action.Strategy)
	}
	if route.Action.Upstream != "" {
		found := false
		for _, group := range groups {
			if strings.TrimSpace(group.Name) == route.Action.Upstream {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("upstream group %q does not exist", route.Action.Upstream)
		}
	}
	if route.Action.StripPrefix != "" {
		if err := validateRoutePath(route.Action.StripPrefix, "strip prefix"); err != nil {
			return err
		}
	}
	if route.Action.RewritePath != "" {
		if err := validateRoutePath(route.Action.RewritePath, "rewrite path"); err != nil {
			return err
		}
	}
	if route.Action.Timeout != "" {
		timeout, err := time.ParseDuration(route.Action.Timeout)
		if err != nil || timeout < 10*time.Millisecond || timeout > 5*time.Minute {
			return fmt.Errorf("timeout must be a duration between 10ms and 5m")
		}
	}
	if route.Action.Retries < 0 || route.Action.Retries > MaxRouteRetries {
		return fmt.Errorf("retries must be between 0 and %d", MaxRouteRetries)
	}
	if err := ValidateRouteCountryPolicy(route.Security.Country); err != nil {
		return fmt.Errorf("country policy: %w", err)
	}
	return nil
}

// CloneRouteConfigs returns a deep-enough immutable route snapshot for config
// mutation and runtime compilation.
func CloneRouteConfigs(routes []RouteConfig) []RouteConfig {
	cloned := make([]RouteConfig, len(routes))
	for index := range routes {
		cloned[index] = routes[index]
		cloned[index].Hosts = cloneRouteStringsSnapshot(routes[index].Hosts)
		cloned[index].Paths = cloneRouteStringsSnapshot(routes[index].Paths)
		cloned[index].Backends = cloneUpstreamTargetsSnapshot(routes[index].Backends)
		cloned[index].Match.Hosts = cloneRouteStringsSnapshot(routes[index].Match.Hosts)
		cloned[index].Match.Paths = cloneRouteStringsSnapshot(routes[index].Match.Paths)
		cloned[index].Match.Methods = cloneRouteStringsSnapshot(routes[index].Match.Methods)
		cloned[index].Match.SourceCIDRs = cloneRouteStringsSnapshot(routes[index].Match.SourceCIDRs)
		cloned[index].Match.Headers = cloneRouteValueMap(routes[index].Match.Headers)
		cloned[index].Match.Query = cloneRouteValueMap(routes[index].Match.Query)
		cloned[index].Action.Backends = cloneUpstreamTargetsSnapshot(routes[index].Action.Backends)
		cloned[index].Security.WAFCore = cloneRouteBool(routes[index].Security.WAFCore)
		cloned[index].Security.TrafficControl = cloneRouteBool(routes[index].Security.TrafficControl)
		cloned[index].Security.HTTPSecurity = cloneRouteBool(routes[index].Security.HTTPSecurity)
		cloned[index].Security.BotProtection = cloneRouteBool(routes[index].Security.BotProtection)
		cloned[index].Security.APISecurity = cloneRouteBool(routes[index].Security.APISecurity)
		cloned[index].Security.AccessControl = cloneRouteBool(routes[index].Security.AccessControl)
		cloned[index].Security.Country = cloneRouteCountryPolicy(routes[index].Security.Country)
	}
	return cloned
}

func cloneRouteStringsSnapshot(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func cloneUpstreamTargetsSnapshot(values []UpstreamTarget) []UpstreamTarget {
	if values == nil {
		return nil
	}
	return append([]UpstreamTarget{}, values...)
}

func validateRouteHost(host string) error {
	if host == "" {
		return fmt.Errorf("host matcher cannot be empty")
	}
	if len(host) > 253 || strings.ContainsAny(host, "/\\?#@\x00\r\n\t ") {
		return fmt.Errorf("invalid host matcher %q", host)
	}
	if strings.Contains(host, "*") && (strings.Count(host, "*") != 1 || !strings.HasPrefix(host, "*.")) && host != "*" {
		return fmt.Errorf("host wildcard %q must use *.example.com", host)
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil && parsedHost == "" {
		return fmt.Errorf("invalid host matcher %q", host)
	}
	return nil
}

func validateRoutePath(path, field string) error {
	if path == "*" || path == "/*" {
		return nil
	}
	if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\r\n?#") {
		return fmt.Errorf("%s %q must start with / and cannot contain query, fragment, or control characters", field, path)
	}
	return nil
}

func validateRouteBackend(backend UpstreamTarget) error {
	if backend.Weight < 1 || backend.Weight > 1000 {
		return fmt.Errorf("weight must be between 1 and 1000")
	}
	if len(strings.TrimSpace(backend.URL)) > MaxUpstreamTargetURLLen {
		return fmt.Errorf("URL exceeds maximum length of %d bytes", MaxUpstreamTargetURLLen)
	}
	parsed, err := url.Parse(strings.TrimSpace(backend.URL))
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("URL %q must be an absolute HTTP or HTTPS URL", backend.URL)
	}
	if parsed.User != nil {
		return fmt.Errorf("URL %q cannot contain inline credentials", backend.URL)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("URL %q cannot contain a fragment", backend.URL)
	}
	return nil
}

func routeMatcherKey(route RouteConfig) (string, error) {
	match := route.Match
	if len(match.Hosts) == 0 {
		match.Hosts = route.Hosts
	}
	if len(match.Paths) == 0 {
		match.Paths = route.Paths
	}
	sort.Strings(match.Hosts)
	sort.Strings(match.Paths)
	sort.Strings(match.Methods)
	sort.Strings(match.SourceCIDRs)
	encoded, err := json.Marshal(match)
	return fmt.Sprintf("%d:%s", route.Priority, encoded), err
}

func normalizeRouteBackends(backends []UpstreamTarget) []UpstreamTarget {
	normalized := make([]UpstreamTarget, 0, len(backends))
	for _, backend := range backends {
		backend.URL = strings.TrimSpace(backend.URL)
		if backend.URL == "" {
			continue
		}
		if backend.Weight <= 0 {
			backend.Weight = 1
		}
		normalized = append(normalized, backend)
	}
	return normalized
}

func normalizeRouteMethods(methods []string) []string {
	normalized := cleanRouteStrings(methods)
	for index := range normalized {
		normalized[index] = strings.ToUpper(normalized[index])
	}
	return normalized
}

func cleanRouteStrings(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			cleaned = append(cleaned, value)
		}
	}
	return cleaned
}

func cleanRouteValueMap(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	cleaned := make(map[string][]string, len(values))
	for name, allowed := range values {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		cleaned[name] = cleanRouteStrings(allowed)
	}
	return cleaned
}

func cloneRouteValueMap(values map[string][]string) map[string][]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string][]string, len(values))
	for name, allowed := range values {
		cloned[name] = cloneRouteStringsSnapshot(allowed)
	}
	return cloned
}

func cloneRouteBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneRouteCountryPolicy(value *RouteCountryPolicy) *RouteCountryPolicy {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.AllowCountries = cloneRouteStringsSnapshot(value.AllowCountries)
	cloned.BlockCountries = cloneRouteStringsSnapshot(value.BlockCountries)
	cloned.Groups = cloneRouteStringsSnapshot(value.Groups)
	cloned.Exceptions = cloneRouteStringsSnapshot(value.Exceptions)
	return &cloned
}

func validHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char <= 32 || char >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", char) {
			return false
		}
	}
	return true
}
