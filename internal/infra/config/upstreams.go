package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	MaxUpstreamGroups       = 1024
	MaxUpstreamTargetWeight = 1000
	MaxUpstreamTargetURLLen = 8192
)

var (
	ErrUpstreamValidation  = errors.New("upstream validation failed")
	ErrUpstreamPersistence = errors.New("upstream persistence failed")
	ErrUpstreamDependency  = errors.New("upstream group is referenced by a route")
)

// NormalizeAndValidateUpstreamGroups canonicalizes and validates the complete
// Origin group collection before it is persisted or applied at runtime.
func NormalizeAndValidateUpstreamGroups(groups []UpstreamGroup) ([]UpstreamGroup, error) {
	if len(groups) > MaxUpstreamGroups {
		return nil, fmt.Errorf("upstream group count %d exceeds limit %d", len(groups), MaxUpstreamGroups)
	}
	normalized := CloneUpstreamGroups(groups)
	names := make(map[string]struct{}, len(normalized))
	for groupIndex := range normalized {
		group := &normalized[groupIndex]
		group.Name = strings.TrimSpace(group.Name)
		group.Strategy = strings.ToLower(strings.TrimSpace(group.Strategy))
		if group.Strategy == "" {
			group.Strategy = "round_robin"
		}
		if group.Name == "" {
			return nil, fmt.Errorf("upstream group %d: name is required", groupIndex+1)
		}
		if len(group.Name) > 128 || strings.ContainsAny(group.Name, "\x00\r\n") {
			return nil, fmt.Errorf("upstream group %d: name is invalid", groupIndex+1)
		}
		if _, exists := names[group.Name]; exists {
			return nil, fmt.Errorf("duplicate upstream group %q", group.Name)
		}
		names[group.Name] = struct{}{}
		if !IsRouteStrategy(group.Strategy) {
			return nil, fmt.Errorf("upstream group %q uses unsupported strategy %q", group.Name, group.Strategy)
		}
		if len(group.Targets) == 0 {
			return nil, fmt.Errorf("upstream group %q requires at least one target", group.Name)
		}
		if len(group.Targets) > MaxRouteBackends {
			return nil, fmt.Errorf("upstream group %q has %d targets; maximum is %d", group.Name, len(group.Targets), MaxRouteBackends)
		}
		targetURLs := make(map[string]struct{}, len(group.Targets))
		for targetIndex := range group.Targets {
			group.Targets[targetIndex].URL = strings.TrimSpace(group.Targets[targetIndex].URL)
			if group.Targets[targetIndex].Weight <= 0 {
				group.Targets[targetIndex].Weight = 1
			}
			if err := validateRouteBackend(group.Targets[targetIndex]); err != nil {
				return nil, fmt.Errorf("upstream group %q target %d: %w", group.Name, targetIndex+1, err)
			}
			canonicalURL := canonicalUpstreamURL(group.Targets[targetIndex].URL)
			if _, exists := targetURLs[canonicalURL]; exists {
				return nil, fmt.Errorf("upstream group %q has duplicate target URL %q", group.Name, group.Targets[targetIndex].URL)
			}
			targetURLs[canonicalURL] = struct{}{}
		}
		if group.HealthCheck.Enabled {
			group.HealthCheck.Interval = strings.TrimSpace(group.HealthCheck.Interval)
			if group.HealthCheck.Interval == "" {
				group.HealthCheck.Interval = "10s"
			}
			interval, err := time.ParseDuration(strings.TrimSpace(group.HealthCheck.Interval))
			if err != nil || interval < time.Second || interval > 24*time.Hour {
				return nil, fmt.Errorf("upstream group %q health-check interval must be between 1s and 24h", group.Name)
			}
			group.HealthCheck.Timeout = strings.TrimSpace(group.HealthCheck.Timeout)
			if group.HealthCheck.Timeout == "" {
				group.HealthCheck.Timeout = "3s"
			}
			timeout, err := time.ParseDuration(group.HealthCheck.Timeout)
			if err != nil || timeout < 100*time.Millisecond || timeout > 30*time.Second {
				return nil, fmt.Errorf("upstream group %q health-check timeout must be between 100ms and 30s", group.Name)
			}
			group.HealthCheck.Path = strings.TrimSpace(group.HealthCheck.Path)
			if group.HealthCheck.Path == "" {
				group.HealthCheck.Path = "/"
			}
			if err := validateRoutePath(group.HealthCheck.Path, "health-check path"); err != nil {
				return nil, fmt.Errorf("upstream group %q: %w", group.Name, err)
			}
			group.HealthCheck.Method = strings.ToUpper(strings.TrimSpace(group.HealthCheck.Method))
			if group.HealthCheck.Method == "" {
				group.HealthCheck.Method = "GET"
			}
			if group.HealthCheck.Method != "GET" && group.HealthCheck.Method != "HEAD" {
				return nil, fmt.Errorf("upstream group %q health-check method must be GET or HEAD", group.Name)
			}
			if len(group.HealthCheck.Headers) > 32 {
				return nil, fmt.Errorf("upstream group %q health-check headers exceed limit 32", group.Name)
			}
			for name, value := range group.HealthCheck.Headers {
				if !validHTTPToken(name) || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
					return nil, fmt.Errorf("upstream group %q has invalid health-check header %q", group.Name, name)
				}
			}
			if len(group.HealthCheck.ExpectedStatuses) > 64 {
				return nil, fmt.Errorf("upstream group %q health-check expected statuses exceed limit 64", group.Name)
			}
			seenStatuses := make(map[int]struct{}, len(group.HealthCheck.ExpectedStatuses))
			expectedStatuses := make([]int, 0, len(group.HealthCheck.ExpectedStatuses))
			for _, status := range group.HealthCheck.ExpectedStatuses {
				if status < 100 || status > 599 {
					return nil, fmt.Errorf("upstream group %q has invalid expected health status %d", group.Name, status)
				}
				if _, exists := seenStatuses[status]; !exists {
					seenStatuses[status] = struct{}{}
					expectedStatuses = append(expectedStatuses, status)
				}
			}
			group.HealthCheck.ExpectedStatuses = expectedStatuses
			if group.HealthCheck.HealthyThreshold <= 0 {
				group.HealthCheck.HealthyThreshold = 2
			}
			if group.HealthCheck.UnhealthyThreshold <= 0 {
				group.HealthCheck.UnhealthyThreshold = 3
			}
			if group.HealthCheck.HealthyThreshold > 20 || group.HealthCheck.UnhealthyThreshold > 20 {
				return nil, fmt.Errorf("upstream group %q health-check thresholds must be between 1 and 20", group.Name)
			}
		}
		if group.Sticky.Cookie != "" && !validHTTPToken(group.Sticky.Cookie) {
			return nil, fmt.Errorf("upstream group %q sticky cookie name is invalid", group.Name)
		}
		if group.Sticky.TTL != "" {
			ttl, err := time.ParseDuration(strings.TrimSpace(group.Sticky.TTL))
			if err != nil || ttl < time.Second || ttl > 365*24*time.Hour {
				return nil, fmt.Errorf("upstream group %q sticky TTL must be between 1s and 365d", group.Name)
			}
		}
	}
	return normalized, nil
}

func canonicalUpstreamURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String()
}

// ValidateRouteUpstreamReferences prevents an Origin group mutation from
// leaving a route with a dangling named-Origin reference.
func ValidateRouteUpstreamReferences(routes []RouteConfig, groups []UpstreamGroup) error {
	names := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		names[strings.TrimSpace(group.Name)] = struct{}{}
	}
	for _, configuredRoute := range routes {
		route := NormalizeRouteConfig(configuredRoute)
		name := strings.TrimSpace(route.Action.Upstream)
		if name == "" || IsRouteStrategy(name) {
			continue
		}
		if _, exists := names[name]; !exists {
			return fmt.Errorf("%w: route %q references upstream group %q", ErrUpstreamDependency, route.ID, name)
		}
	}
	return nil
}

// ValidateLegacyRouteUpstreamReferences requires every legacy host mapping to
// select either an existing named Origin or an explicit absolute HTTP(S) URL.
func ValidateLegacyRouteUpstreamReferences(routes map[string]string, groups []UpstreamGroup) error {
	names := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		names[group.Name] = struct{}{}
	}
	for host, configuredTarget := range routes {
		host = strings.TrimSpace(host)
		target := strings.TrimSpace(configuredTarget)
		if host == "" || strings.ContainsAny(host, "\x00\r\n") {
			return fmt.Errorf("legacy upstream route host %q is invalid", host)
		}
		if _, exists := names[target]; exists {
			continue
		}
		if err := validateRouteBackend(UpstreamTarget{URL: target, Weight: 1}); err != nil {
			return fmt.Errorf("legacy upstream route %q references unknown Origin %q and is not a valid target URL", host, target)
		}
	}
	return nil
}

// CloneUpstreamGroups returns a mutation-safe Origin group snapshot.
func CloneUpstreamGroups(groups []UpstreamGroup) []UpstreamGroup {
	cloned := make([]UpstreamGroup, len(groups))
	for index := range groups {
		cloned[index] = groups[index]
		cloned[index].Targets = append([]UpstreamTarget(nil), groups[index].Targets...)
		cloned[index].HealthCheck.Headers = make(map[string]string, len(groups[index].HealthCheck.Headers))
		for name, value := range groups[index].HealthCheck.Headers {
			cloned[index].HealthCheck.Headers[name] = value
		}
		if groups[index].HealthCheck.ExpectedStatuses != nil {
			cloned[index].HealthCheck.ExpectedStatuses = make([]int, len(groups[index].HealthCheck.ExpectedStatuses))
			copy(cloned[index].HealthCheck.ExpectedStatuses, groups[index].HealthCheck.ExpectedStatuses)
		}
	}
	return cloned
}
