package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/alexedwards/scs/v2"
)

type RBACMiddleware struct {
	sessionManager *scs.SessionManager
}

func NewRBACMiddleware(sm *scs.SessionManager) *RBACMiddleware {
	return &RBACMiddleware{sessionManager: sm}
}

// RequireAnyPermissionJSON is the API-safe RBAC variant used by section
// control planes that require a stable machine-readable error contract.
func (m *RBACMiddleware) RequireAnyPermissionJSON(section string, permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !m.hasAnyPermission(r, permissions...) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]interface{}{
						"code":    "FORBIDDEN",
						"message": "The authenticated user is not authorized for this App Security action.",
						"details": map[string]interface{}{"section": section, "required_permissions": permissions},
					},
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllPermissionsJSON enforces actor-separation and operational actions
// that intentionally require more than one independent permission.
func (m *RBACMiddleware) RequireAllPermissionsJSON(section string, permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, permission := range permissions {
				if !m.hasAnyPermission(r, permission) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"error": map[string]interface{}{
							"code": "FORBIDDEN", "message": "The authenticated user is not authorized for this App Security action.",
							"details": map[string]interface{}{"section": section, "required_permissions": permissions},
						},
					})
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (m *RBACMiddleware) hasAnyPermission(r *http.Request, permissions ...string) bool {
	if !m.sessionManager.Exists(r.Context(), "permissions") {
		return false
	}
	perms, ok := m.sessionManager.Get(r.Context(), "permissions").([]string)
	if !ok {
		return false
	}
	for _, actual := range perms {
		for _, required := range permissions {
			if actual == required {
				return true
			}
		}
	}
	return false
}

// RequirePermission middleware ensures the user has the specific permission slug
func (m *RBACMiddleware) RequirePermission(permission string) func(http.Handler) http.Handler {
	return m.RequireAnyPermission(permission)
}

// RequireAnyPermission middleware ensures the user has at least one permission slug.
func (m *RBACMiddleware) RequireAnyPermission(permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Debug Check
			// fmt.Printf("Checking permissions: %v\n", permissions)

			if !m.sessionManager.Exists(r.Context(), "permissions") {
				// fmt.Println("No permissions in session")
				http.Error(w, "Forbidden (No Permissions)", http.StatusForbidden)
				return
			}

			permsInterface := m.sessionManager.Get(r.Context(), "permissions")
			perms, ok := permsInterface.([]string)
			if !ok {
				// fmt.Println("Invalid permissions type")
				http.Error(w, "Forbidden (Invalid Permissions)", http.StatusForbidden)
				return
			}

			// fmt.Printf("User has permissions: %v\n", perms)

			hasPerm := false
			for _, p := range perms {
				for _, permission := range permissions {
					if p == permission {
						hasPerm = true
						break
					}
				}
				if hasPerm {
					break
				}
			}

			if !hasPerm {
				// fmt.Printf("Missing permissions: %v\n", permissions)
				http.Error(w, "Forbidden (Missing Permission)", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
