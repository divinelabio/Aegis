package admin

import (
	"net/http"
	"strings"
)

const (
	botProtectionSectionPrefix = "/api/sections/bot_protection"
	botProtectionV2RulesPrefix = "/api/v2/security/bot/rules"
)

type botProtectionPermissionRequirement struct {
	permissions []string
	requireAll  bool
}

func (s *AdminServer) guardBotProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requirement, guarded := botProtectionPermissionForRequest(r.Method, r.URL.Path)
		if !guarded {
			next.ServeHTTP(w, r)
			return
		}

		var protected http.Handler
		if requirement.requireAll {
			protected = s.rbacMW.RequireAllPermissionsJSON("bot_protection", requirement.permissions...)(next)
		} else {
			protected = s.rbacMW.RequireAnyPermissionJSON("bot_protection", requirement.permissions...)(next)
		}
		protected.ServeHTTP(w, r)
	})
}

func botProtectionPermissionForRequest(method, path string) (botProtectionPermissionRequirement, bool) {
	switch {
	case path == botProtectionSectionPrefix || strings.HasPrefix(path, botProtectionSectionPrefix+"/"):
		if method == http.MethodGet || method == http.MethodHead {
			return botProtectionPermissionRequirement{permissions: []string{"waf:read"}}, true
		}
		return botProtectionPermissionRequirement{permissions: []string{"waf:write"}}, true

	case path == botProtectionV2RulesPrefix || strings.HasPrefix(path, botProtectionV2RulesPrefix+"/"):
		if method == http.MethodGet || method == http.MethodHead ||
			strings.HasSuffix(path, "/templates") ||
			strings.HasSuffix(path, "/fields") ||
			strings.HasSuffix(path, "/test") {
			return botProtectionPermissionRequirement{permissions: []string{"waf:read"}}, true
		}
		return botProtectionPermissionRequirement{
			permissions: []string{"waf:write", "rules:write"},
			requireAll:  true,
		}, true
	}

	return botProtectionPermissionRequirement{}, false
}
