package admin

import (
	"net/http"
	"strings"
)

const wafCoreSectionPrefix = "/api/sections/waf_core"

type wafCorePermissionRequirement struct {
	permissions []string
	requireAll  bool
}

func (s *AdminServer) guardWAFSection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requirement, guarded := wafCoreSectionPermissionRequirement(r.Method, r.URL.Path)
		if !guarded {
			next.ServeHTTP(w, r)
			return
		}

		var protected http.Handler
		if requirement.requireAll {
			protected = s.rbacMW.RequireAllPermissionsJSON("waf_core", requirement.permissions...)(next)
		} else {
			protected = s.rbacMW.RequireAnyPermissionJSON("waf_core", requirement.permissions...)(next)
		}
		protected.ServeHTTP(w, r)
	})
}

func wafCoreSectionPermissionRequirement(method, path string) (wafCorePermissionRequirement, bool) {
	if path != wafCoreSectionPrefix && !strings.HasPrefix(path, wafCoreSectionPrefix+"/") {
		return wafCorePermissionRequirement{}, false
	}
	if method == http.MethodGet || method == http.MethodHead {
		return wafCorePermissionRequirement{permissions: []string{"waf:read"}}, true
	}
	if isWAFRawRulesMutationPath(path) {
		return wafCorePermissionRequirement{
			permissions: []string{"waf:write", "rules:write"},
			requireAll:  true,
		}, true
	}
	return wafCorePermissionRequirement{permissions: []string{"waf:write"}}, true
}

func isWAFRawRulesMutationPath(path string) bool {
	rawRulesPath := wafCoreSectionPrefix + "/rules/crs"
	return path == rawRulesPath || strings.HasPrefix(path, rawRulesPath+"/")
}
