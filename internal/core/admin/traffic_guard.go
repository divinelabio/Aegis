package admin

import (
	"net/http"
	"strings"
)

const trafficSectionPrefix = "/api/sections/traffic_control"

// guardTrafficSection keeps Traffic's control plane behind an explicit RBAC
// boundary. Config can contain security sources and credential changes, so it
// is an administrative action; normal blacklist mutations are traffic:write.
func (s *AdminServer) guardTrafficSection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permission, guarded := trafficSectionPermission(r.Method, r.URL.Path)
		if !guarded {
			next.ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequireAnyPermissionJSON("traffic_control", permission)(next).ServeHTTP(w, r)
	})
}

func trafficSectionPermission(method, path string) (string, bool) {
	if path != trafficSectionPrefix && !strings.HasPrefix(path, trafficSectionPrefix+"/") {
		return "", false
	}
	if method == http.MethodGet || method == http.MethodHead {
		return "traffic:read", true
	}
	if path == trafficSectionPrefix+"/config" {
		return "traffic:admin", true
	}
	return "traffic:write", true
}
