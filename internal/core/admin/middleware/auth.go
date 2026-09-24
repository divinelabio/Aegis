package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
)

type AuthMiddleware struct {
	sessionManager *scs.SessionManager
	userRepo       user.Repository
	userCache      map[uuid.UUID]cachedUserState
	userCacheMu    sync.RWMutex
}

type cachedUserState struct {
	active    bool
	revision  string
	expiresAt time.Time
}

const userStateCacheTTL = 5 * time.Second

// NewAuthMiddleware accepts an optional repository to validate the identity
// revision stored in the session. Keeping it optional preserves lightweight
// middleware-only tests and callers that do not manage user sessions.
func NewAuthMiddleware(sessionManager *scs.SessionManager, repos ...user.Repository) *AuthMiddleware {
	var userRepo user.Repository
	if len(repos) > 0 {
		userRepo = repos[0]
	}
	return &AuthMiddleware{
		sessionManager: sessionManager,
		userRepo:       userRepo,
		userCache:      make(map[uuid.UUID]cachedUserState),
	}
}

// RequireAuth middleware ensures the request has a valid session
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is authenticated via SCS
		// We expect "user_id" to be present in the session
		if !m.sessionManager.Exists(r.Context(), "user_id") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !m.sessionIdentityIsCurrent(r) {
			_ = m.sessionManager.Destroy(r.Context())
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// InvalidateUser causes all current sessions for the identity to be checked
// against storage again on their next protected request.
func (m *AuthMiddleware) InvalidateUser(id uuid.UUID) {
	m.userCacheMu.Lock()
	delete(m.userCache, id)
	m.userCacheMu.Unlock()
}

func (m *AuthMiddleware) sessionIdentityIsCurrent(r *http.Request) bool {
	if m.userRepo == nil {
		return true
	}

	id, err := uuid.Parse(m.sessionManager.GetString(r.Context(), "user_uuid"))
	if err != nil {
		return false
	}
	sessionRevision := m.sessionManager.GetString(r.Context(), "auth_revision")
	if sessionRevision == "" {
		return false
	}

	state, ok := m.cachedUserState(r, id)
	if !ok {
		return false
	}
	return state.active && state.revision == sessionRevision
}

func (m *AuthMiddleware) cachedUserState(r *http.Request, id uuid.UUID) (cachedUserState, bool) {
	now := time.Now()
	m.userCacheMu.RLock()
	state, ok := m.userCache[id]
	m.userCacheMu.RUnlock()
	if ok && now.Before(state.expiresAt) {
		return state, true
	}

	u, err := m.userRepo.GetUserByID(r.Context(), id)
	if err != nil || u == nil {
		return cachedUserState{}, false
	}
	state = cachedUserState{
		active:    u.IsActive,
		revision:  userRevision(u.UpdatedAt),
		expiresAt: now.Add(userStateCacheTTL),
	}
	m.userCacheMu.Lock()
	m.userCache[id] = state
	m.userCacheMu.Unlock()
	return state, true
}

func userRevision(updatedAt time.Time) string {
	return updatedAt.UTC().Format(time.RFC3339Nano)
}

// RequireCSRF middleware validates CSRF tokens on state-changing requests
func (m *AuthMiddleware) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only check CSRF on state-changing methods
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				writeCSRFError(w, r, "Missing CSRF token")
				return
			}

			// Validate session exists
			if !m.sessionManager.Exists(r.Context(), "user_id") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Retrieve expected CSRF token from session
			expectedToken := m.sessionManager.GetString(r.Context(), "csrf_token")

			if expectedToken == "" || expectedToken != csrfToken {
				writeCSRFError(w, r, "Invalid CSRF token")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func writeCSRFError(w http.ResponseWriter, r *http.Request, message string) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]interface{}{
			"code": "CSRF_REQUIRED", "message": message,
		}})
		return
	}
	http.Error(w, message, http.StatusForbidden)
}
