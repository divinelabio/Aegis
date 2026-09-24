package session

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alexedwards/scs/redisstore"
	"github.com/alexedwards/scs/v2"
	"github.com/gomodule/redigo/redis"
)

// NewManager initializes the session manager (SCS)
// It supports InMemory (default) or Redis (if REDIS_URL is set)
func NewManager(secure bool) *scs.SessionManager {
	sessionManager := scs.New()
	sessionManager.Lifetime = 24 * time.Hour
	sessionManager.Cookie.Name = "aegis_session"
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	sessionManager.Cookie.Secure = secure // Ensure TLS (or localhost)

	// Persist sessions in Redis if configured. REDIS_URL is preferred for
	// standard self-hosted deployments; REDIS_HOST/REDIS_PORT remain supported.
	redisURL := strings.TrimSpace(os.Getenv("REDIS_URL"))
	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")

	if redisURL != "" || (redisHost != "" && redisPort != "") {
		pool := &redis.Pool{
			MaxIdle: 10,
			Dial: func() (redis.Conn, error) {
				if redisURL != "" {
					return redis.DialURL(redisURL)
				}
				return redis.Dial("tcp", redisHost+":"+redisPort)
			},
		}
		sessionManager.Store = redisstore.New(pool)
	}

	return sessionManager
}

// Helper to get user ID from context
func GetUserID(ctx context.Context, sm *scs.SessionManager) string {
	return sm.GetString(ctx, "user_id")
}
