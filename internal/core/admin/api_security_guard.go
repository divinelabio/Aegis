package admin

import (
	"net/http"
	"strings"
)

const apiSecuritySectionPrefix = "/api/sections/api_security"

func (s *AdminServer) guardAPISecuritySection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permission, guarded := apiSecuritySectionPermission(r.Method, r.URL.Path)
		if !guarded {
			next.ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequireAnyPermissionJSON("api_security", permission)(next).ServeHTTP(w, r)
	})
}

func apiSecuritySectionPermission(method, path string) (string, bool) {
	if path != apiSecuritySectionPrefix && !strings.HasPrefix(path, apiSecuritySectionPrefix+"/") {
		return "", false
	}
	if method == http.MethodGet || method == http.MethodHead {
		return "api_security:read", true
	}
	return "api_security:write", true
}
