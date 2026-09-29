package admin

import (
	"net/http"
	"strings"
)

const appSecuritySectionPrefix = "/api/sections/http_security"

func (s *AdminServer) guardAppSecuritySection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permission := appSecuritySectionPermission(r.Method, r.URL.Path)
		if permission == "" {
			next.ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequireAnyPermissionJSON("http_security", permission)(next).ServeHTTP(w, r)
	})
}

func appSecuritySectionPermission(method, path string) string {
	if path != appSecuritySectionPrefix && !strings.HasPrefix(path, appSecuritySectionPrefix+"/") {
		return ""
	}
	if method == http.MethodGet || method == http.MethodHead {
		return "app_security:read"
	}
	return "app_security:write"
}
