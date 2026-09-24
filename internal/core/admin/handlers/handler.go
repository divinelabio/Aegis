package handlers

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/divinelab-io/aegis/internal/analytics"
	"github.com/divinelab-io/aegis/internal/app"
	"github.com/divinelab-io/aegis/internal/core/admin/audit"
	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/health"
	"github.com/divinelab-io/aegis/internal/infra/mail"
	"github.com/divinelab-io/aegis/internal/infra/storage"
	"github.com/divinelab-io/aegis/internal/infra/transport"
	"github.com/divinelab-io/aegis/internal/licensing"
	"github.com/divinelab-io/aegis/internal/rules"
	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
)

// Server start time for uptime calculation
var ServerStartTime = time.Now()

// Version info
var (
	Version   string
	BuildDate string
)

// licenseTierStore holds the licence tier provider set by commercial overlays.
// Using atomic.Value is goroutine-safe, explicit, and race-detector clean.
var licenseTierStore atomic.Value    // stores func() string
var licenseManagerStore atomic.Value // stores licenseManagerHolder

type licenseManagerHolder struct {
	manager licensing.Manager
}

// SetLicenseTierFunc registers a function that returns the current license tier string
// (for example, "professional" or "enterprise").
// Safe to call concurrently; subsequent calls override the previous value.
func SetLicenseTierFunc(f func() string) {
	licenseTierStore.Store(f)
}

// SetLicenseManager registers the runtime licence manager used by the admin API.
func SetLicenseManager(manager licensing.Manager) {
	licenseManagerStore.Store(licenseManagerHolder{manager: manager})
}

func getLicenseManager() licensing.Manager {
	if holder, ok := licenseManagerStore.Load().(licenseManagerHolder); ok {
		return holder.manager
	}
	return nil
}

// getLicenseTier returns the current license tier. Falls back to "COMMUNITY"
// if no commercial overlay has registered a provider.
func getLicenseTier() string {
	if f, ok := licenseTierStore.Load().(func() string); ok && f != nil {
		return f()
	}
	return "COMMUNITY"
}

type Handler struct {
	Logger                *zap.Logger
	Config                config.ServerConfig
	Sessions              *scs.SessionManager
	UserRepo              user.Repository
	Sections              *app.SectionManager
	Health                *health.Handler
	ProxyTransport        *transport.BreakerTransport
	UpstreamManager       *transport.UpstreamManager
	LoginLimiter          RateLimiter
	PasswordResetLimiter  RateLimiter
	MFAAttemptLimiter     RateLimiter
	AuthWorkLimiter       chan struct{}
	Audit                 *audit.AuditLogger
	Mailer                *mail.Mailer
	TLSManager            *transport.TLSManager
	RealIPResolver        *transport.RealIPResolver
	Router                *transport.Router
	RuleStore             *rules.Store
	AnalyticsStore        *analytics.Store
	CaptchaStore          config.CaptchaStore
	ErrorPagesStore       config.ErrorPagesStore
	SecurityTXTStore      config.SecurityTXTStore
	InfrastructureStore   config.InfrastructureStore
	UpstreamRuntimeStore  config.UpstreamRuntimeStore
	UpstreamGroupsStore   config.UpstreamGroupsStore
	RouteRulesStore       config.RouteRulesStore
	CircuitBreakerStore   config.CircuitBreakerStore
	LegacyRoutesStore     config.LegacyRoutesStore
	StickySecretStore     config.StickySecretStore
	TrafficControlStore   config.TrafficControlStore
	WAFStore              config.WAFStore
	BotStore              config.BotStore
	HTTPSecurityStore     config.HTTPSecurityStore
	APISecurityStore      config.APISecurityStore
	AccessControlStore    config.AccessControlStore
	ReputationStore       config.ReputationStore
	ChallengeStore        config.ChallengeStore
	ControlPlaneDocuments ConfigurationDocumentInspector
	PostgreSQLPreflight   storage.PostgreSQLPreflightRunner
	ClickHousePreflight   storage.ClickHousePreflightRunner
	License               licensing.Manager
	UpdaterSocket         string
	SessionInvalidator    UserSessionInvalidator
	tlsMutationMu         sync.Mutex
	userMutationMu        sync.Mutex
	roleMutationMu        sync.Mutex
	tlsInventoryMu        sync.Mutex
	tlsInventoryAt        time.Time
	tlsInventory          []map[string]interface{}
	alertStateMu          sync.Mutex
	alertState            *alertStateStore
	TLSListenerEnabled    bool
	tlsRestartRequired    atomic.Bool
	routeReferences       protectedRouteReferenceChecker
}

// ConfigurationDocumentInspector reports whether any operator-managed
// configuration documents exist in PostgreSQL. Archive recovery uses this to
// avoid presenting a YAML-only bundle as a complete configuration backup.
type ConfigurationDocumentInspector interface {
	HasActiveDocuments(context.Context) (bool, error)
}

// UserSessionInvalidator clears the middleware cache for a changed identity so
// existing sessions are rejected on their next protected request.
type UserSessionInvalidator interface {
	InvalidateUser(uuid.UUID)
}

func NewHandler(
	logger *zap.Logger,
	cfg config.ServerConfig,
	sessions *scs.SessionManager,
	userRepo user.Repository,
	sections *app.SectionManager,
	health *health.Handler,
	proxyTransport *transport.BreakerTransport,
	upstreamMgr *transport.UpstreamManager,
	loginLimiter RateLimiter,
	passwordResetLimiter RateLimiter,
	mfaAttemptLimiter RateLimiter,
	auditLogger *audit.AuditLogger,
	mailer *mail.Mailer,
	tlsMgr *transport.TLSManager,
	realIPResolver *transport.RealIPResolver,
	router *transport.Router,
	ruleStore *rules.Store,
	analyticsStore *analytics.Store,
	updaterSocket string,
	invalidators ...UserSessionInvalidator,
) *Handler {
	var sessionInvalidator UserSessionInvalidator
	if len(invalidators) > 0 {
		sessionInvalidator = invalidators[0]
	}
	return &Handler{
		Logger:               logger,
		Config:               cfg,
		Sessions:             sessions,
		UserRepo:             userRepo,
		Sections:             sections,
		Health:               health,
		ProxyTransport:       proxyTransport,
		UpstreamManager:      upstreamMgr,
		LoginLimiter:         loginLimiter,
		PasswordResetLimiter: passwordResetLimiter,
		MFAAttemptLimiter:    mfaAttemptLimiter,
		AuthWorkLimiter:      make(chan struct{}, 4),
		Audit:                auditLogger,
		Mailer:               mailer,
		TLSManager:           tlsMgr,
		RealIPResolver:       realIPResolver,
		Router:               router,
		RuleStore:            ruleStore,
		AnalyticsStore:       analyticsStore,
		PostgreSQLPreflight:  storage.NewPostgreSQLPreflightRunner(),
		ClickHousePreflight:  storage.NewClickHousePreflightRunner(),
		License:              getLicenseManager(),
		UpdaterSocket:        updaterSocket,
		SessionInvalidator:   sessionInvalidator,
		TLSListenerEnabled:   cfg.TLS.Enabled,
	}
}

// authClientKey returns the verified client identity when Aegis is behind a
// configured trusted proxy. Direct connections remain keyed by their peer IP.
func (h *Handler) authClientKey(r *http.Request) string {
	if h.RealIPResolver != nil {
		if identity := h.RealIPResolver.Resolve(r); identity.IP != "" {
			return identity.IP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// acquireAuthWork rejects excess password-hash work instead of allowing a
// burst of deliberately expensive Argon2 calculations to exhaust the admin
// process. A nil limiter preserves lightweight handler fixtures in tests.
func (h *Handler) acquireAuthWork() bool {
	if h.AuthWorkLimiter == nil {
		return true
	}
	select {
	case h.AuthWorkLimiter <- struct{}{}:
		return true
	default:
		return false
	}
}

func (h *Handler) releaseAuthWork() {
	if h.AuthWorkLimiter == nil {
		return
	}
	<-h.AuthWorkLimiter
}

func (h *Handler) allowPasswordReset(key string) bool {
	return h.PasswordResetLimiter == nil || h.PasswordResetLimiter.Allow(key)
}

func (h *Handler) allowMFAAttempt(key string) bool {
	return h.MFAAttemptLimiter == nil || h.MFAAttemptLimiter.Allow(key)
}

func (h *Handler) invalidateUserSessions(id uuid.UUID) {
	if h.SessionInvalidator != nil {
		h.SessionInvalidator.InvalidateUser(id)
	}
}

// recordAudit keeps best-effort audit writes from changing the result of a
// completed control-plane action. AuditLogger exposes write health separately
// so an operator can detect a persistence failure without receiving database
// internals in an authentication response.
func (h *Handler) recordAudit(r *http.Request, action, resource, metadata string) {
	if h.Audit != nil {
		_ = h.Audit.Log(r, action, resource, metadata)
	}
}

type RateLimiter interface {
	Allow(string) bool
}

// JSONError returns a JSON response with the given message and status code
func (h *Handler) JSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"error":  message,
		"status": "error",
	})
}
