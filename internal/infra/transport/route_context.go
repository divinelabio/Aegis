package transport

import (
	"context"
	"net/http"

	"github.com/divinelab-io/aegis/internal/infra/config"
)

type routeContextKey struct{}

type MatchedRoute struct {
	Rule       config.RouteConfig
	ClientInfo ClientInfo
	compiled   *compiledRoute
}

func NewRouteContextMiddleware(router *Router, infraCfg config.InfrastructureConfig) (func(http.Handler) http.Handler, error) {
	_ = infraCfg

	return func(next http.Handler) http.Handler {
		if router == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientInfo := clientInfoFromIdentity(r)
			resolved := router.resolveWithClient(r, clientInfo)
			if resolved.disabled {
				w.Header().Set("Retry-After", "60")
				if !WriteConfiguredErrorPage(w, r, http.StatusServiceUnavailable) {
					http.Error(w, "503 Service Unavailable - protected route is disabled", http.StatusServiceUnavailable)
				}
				return
			}
			if resolved.route != nil {
				ctx := context.WithValue(r.Context(), routeContextKey{}, MatchedRoute{
					Rule:       resolved.route.rule,
					ClientInfo: clientInfo,
					compiled:   resolved.route,
				})
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

func RouteFromRequest(r *http.Request) (MatchedRoute, bool) {
	if r == nil {
		return MatchedRoute{}, false
	}
	matched, ok := r.Context().Value(routeContextKey{}).(MatchedRoute)
	return matched, ok
}

func RouteAllowsSection(r *http.Request, sectionID string) bool {
	matched, ok := RouteFromRequest(r)
	if !ok {
		return true
	}

	var allowed *bool
	switch sectionID {
	case "waf_core":
		allowed = matched.Rule.Security.WAFCore
	case "traffic_control":
		allowed = matched.Rule.Security.TrafficControl
	case "http_security":
		allowed = matched.Rule.Security.HTTPSecurity
	case "bot_protection":
		allowed = matched.Rule.Security.BotProtection
	case "api_security":
		allowed = matched.Rule.Security.APISecurity
	case "access_control":
		allowed = matched.Rule.Security.AccessControl
	}
	if allowed == nil {
		return true
	}
	return *allowed
}
