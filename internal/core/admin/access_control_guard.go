package admin

import (
	"net/http"
	"strings"
)

const (
	accessControlSectionPrefix = "/api/sections/access_control"
)

func (s *AdminServer) guardAccessControlSection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permission := accessControlSectionPermission(r.Method, r.URL.Path)
		if permission == "" {
			next.ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequireAnyPermission(accessControlSectionPermissionOptions(permission)...)(next).ServeHTTP(w, r)
	})
}

func accessControlSectionPermission(method, path string) string {
	if !isAccessControlSectionPath(path) {
		return ""
	}
	if method == http.MethodGet || method == http.MethodHead {
		return "system:read"
	}
	if isAccessControlActivitySessionMutationPath(path) {
		return "sessions:delete"
	}
	return "system:config"
}

func isAccessControlSectionPath(path string) bool {
	return path == accessControlSectionPrefix || strings.HasPrefix(path, accessControlSectionPrefix+"/")
}

func isAccessControlActivitySessionMutationPath(path string) bool {
	activityPrefix := accessControlSectionPrefix + "/activity/sessions"
	return path == activityPrefix || strings.HasPrefix(path, activityPrefix+"/")
}

func accessControlSectionPermissionOptions(permission string) []string {
	if permission == "system:read" {
		return []string{"system:read", "system:config"}
	}
	return []string{permission}
}
