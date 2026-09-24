package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var builtInAdminRoles = map[string]struct{}{
	"super_admin": {}, "admin": {}, "auditor": {}, "viewer": {},
}

var customRoleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)

type managedRoleInput struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
}

func isBuiltInAdminRole(name string) bool {
	_, ok := builtInAdminRoles[name]
	return ok
}

func normalizeManagedRoleInput(input managedRoleInput) (managedRoleInput, error) {
	input.Name = strings.ToLower(strings.TrimSpace(input.Name))
	input.Description = strings.TrimSpace(input.Description)
	if !customRoleNamePattern.MatchString(input.Name) || isBuiltInAdminRole(input.Name) {
		return input, fmt.Errorf("role name must be a unique lowercase identifier and cannot replace a built-in role")
	}
	if len(input.Description) > 256 {
		return input, fmt.Errorf("role description must be at most 256 characters")
	}
	if len(input.Permissions) == 0 {
		return input, fmt.Errorf("select at least one permission")
	}
	seen := make(map[string]struct{}, len(input.Permissions))
	permissions := make([]string, 0, len(input.Permissions))
	for _, raw := range input.Permissions {
		slug := strings.TrimSpace(raw)
		if slug == "" {
			return input, fmt.Errorf("permission values must not be empty")
		}
		if _, exists := seen[slug]; exists {
			continue
		}
		seen[slug] = struct{}{}
		permissions = append(permissions, slug)
	}
	sort.Strings(permissions)
	input.Permissions = permissions
	return input, nil
}

func (h *Handler) resolveDelegablePermissions(w http.ResponseWriter, r *http.Request, slugs []string) ([]user.Permission, bool) {
	catalog, err := h.UserRepo.ListPermissions(r.Context())
	if err != nil {
		h.Logger.Error("Failed to list permission catalog", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return nil, false
	}
	bySlug := make(map[string]user.Permission, len(catalog))
	for _, permission := range catalog {
		bySlug[permission.Slug] = permission
	}
	actorPermissions, _ := h.Sessions.Get(r.Context(), "permissions").([]string)
	actorSet := make(map[string]struct{}, len(actorPermissions))
	for _, permission := range actorPermissions {
		actorSet[permission] = struct{}{}
	}
	resolved := make([]user.Permission, 0, len(slugs))
	for _, slug := range slugs {
		permission, exists := bySlug[slug]
		if !exists {
			h.JSONError(w, "Selected permission does not exist: "+slug, http.StatusBadRequest)
			return nil, false
		}
		if _, allowed := actorSet[slug]; !allowed {
			h.JSONError(w, "You cannot grant a permission you do not hold", http.StatusForbidden)
			return nil, false
		}
		resolved = append(resolved, permission)
	}
	return resolved, true
}

func (h *Handler) HandleListPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.UserRepo.ListPermissions(r.Context())
	if err != nil {
		h.Logger.Error("Failed to list permissions", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": permissions})
}

func (h *Handler) HandleCreateRole(w http.ResponseWriter, r *http.Request) {
	var input managedRoleInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.JSONError(w, "Invalid input", http.StatusBadRequest)
		return
	}
	input, err := normalizeManagedRoleInput(input)
	if err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Serialize role creation with identity assignment: a user must never see a
	// role between its metadata insert and its permission assignment.
	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()
	h.roleMutationMu.Lock()
	defer h.roleMutationMu.Unlock()
	if existing, err := h.UserRepo.GetRoleByName(r.Context(), input.Name); err != nil {
		h.Logger.Error("Failed to validate role name", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	} else if existing != nil {
		h.JSONError(w, "Role name is already in use", http.StatusConflict)
		return
	}
	permissions, ok := h.resolveDelegablePermissions(w, r, input.Permissions)
	if !ok {
		return
	}
	role := &user.Role{Name: input.Name, Description: input.Description}
	if err := h.UserRepo.CreateRole(r.Context(), role); err != nil {
		h.Logger.Error("Failed to create role", zap.Error(err))
		h.JSONError(w, "Failed to create role", http.StatusInternalServerError)
		return
	}
	if err := h.UserRepo.SetPermissionsForRole(r.Context(), role.ID, permissions); err != nil {
		h.Logger.Error("Failed to assign role permissions", zap.Error(err))
		_ = h.UserRepo.DeleteRole(r.Context(), role.ID)
		h.JSONError(w, "Failed to assign role permissions", http.StatusInternalServerError)
		return
	}
	h.auditUserMutation(r, "role:create", role.ID, map[string]interface{}{"name": role.Name, "permissions": input.Permissions})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "created", "id": role.ID.String()})
}

// HandleUpdateRole changes an unassigned custom role. Roles which have ever
// been assigned must be replaced and users explicitly re-assigned so an
// operator cannot accidentally change another user's effective privileges.
func (h *Handler) HandleUpdateRole(w http.ResponseWriter, r *http.Request) {
	var input managedRoleInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.ID == uuid.Nil {
		h.JSONError(w, "role id is required", http.StatusBadRequest)
		return
	}
	input, err := normalizeManagedRoleInput(input)
	if err != nil {
		h.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Use the same lock as user updates so an identity cannot be assigned while
	// this handler is checking the role's assignment count.
	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()
	h.roleMutationMu.Lock()
	defer h.roleMutationMu.Unlock()
	role, err := h.UserRepo.GetRoleByID(r.Context(), input.ID)
	if err != nil {
		h.Logger.Error("Failed to get role", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if role == nil {
		h.JSONError(w, "Role not found", http.StatusNotFound)
		return
	}
	if isBuiltInAdminRole(role.Name) {
		h.JSONError(w, "Built-in roles cannot be changed", http.StatusConflict)
		return
	}
	assigned, err := h.UserRepo.CountUsersByRole(r.Context(), role.ID)
	if err != nil {
		h.Logger.Error("Failed to count role assignments", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if assigned > 0 {
		h.JSONError(w, "Create a replacement role and reassign all users before changing this role", http.StatusConflict)
		return
	}
	if existing, err := h.UserRepo.GetRoleByName(r.Context(), input.Name); err != nil {
		h.Logger.Error("Failed to validate role name", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	} else if existing != nil && existing.ID != role.ID {
		h.JSONError(w, "Role name is already in use", http.StatusConflict)
		return
	}
	permissions, ok := h.resolveDelegablePermissions(w, r, input.Permissions)
	if !ok {
		return
	}
	role.Name = input.Name
	role.Description = input.Description
	if err := h.UserRepo.UpdateRole(r.Context(), role); err != nil {
		h.Logger.Error("Failed to update role", zap.Error(err))
		h.JSONError(w, "Failed to update role", http.StatusInternalServerError)
		return
	}
	if err := h.UserRepo.SetPermissionsForRole(r.Context(), role.ID, permissions); err != nil {
		h.Logger.Error("Failed to update role permissions", zap.Error(err))
		h.JSONError(w, "Failed to update role permissions", http.StatusInternalServerError)
		return
	}
	h.auditUserMutation(r, "role:update", role.ID, map[string]interface{}{"name": role.Name, "permissions": input.Permissions})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "updated", "id": role.ID.String()})
}

func (h *Handler) HandleDeleteRole(w http.ResponseWriter, r *http.Request) {
	var input managedRoleInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.ID == uuid.Nil {
		h.JSONError(w, "role id is required", http.StatusBadRequest)
		return
	}
	// Use the same lock as user updates so an identity cannot be assigned while
	// this handler is checking the role's assignment count.
	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()
	h.roleMutationMu.Lock()
	defer h.roleMutationMu.Unlock()
	role, err := h.UserRepo.GetRoleByID(r.Context(), input.ID)
	if err != nil || role == nil {
		h.JSONError(w, "Role not found", http.StatusNotFound)
		return
	}
	if isBuiltInAdminRole(role.Name) {
		h.JSONError(w, "Built-in roles cannot be removed", http.StatusConflict)
		return
	}
	assigned, err := h.UserRepo.CountUsersByRole(r.Context(), role.ID)
	if err != nil {
		h.Logger.Error("Failed to count role assignments", zap.Error(err))
		h.JSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if assigned > 0 {
		h.JSONError(w, "Reassign all users before removing this role", http.StatusConflict)
		return
	}
	if err := h.UserRepo.DeleteRole(r.Context(), role.ID); err != nil {
		h.Logger.Error("Failed to delete role", zap.Error(err))
		h.JSONError(w, "Failed to remove role", http.StatusInternalServerError)
		return
	}
	h.auditUserMutation(r, "role:delete", role.ID, map[string]interface{}{"name": role.Name})
	w.WriteHeader(http.StatusNoContent)
}
