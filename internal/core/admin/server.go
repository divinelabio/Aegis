package admin

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/divinelab-io/aegis/internal/analytics"
	"github.com/divinelab-io/aegis/internal/app"
	"github.com/divinelab-io/aegis/internal/core/admin/audit"
	"github.com/divinelab-io/aegis/internal/core/admin/handlers"
	"github.com/divinelab-io/aegis/internal/core/admin/middleware"
	"github.com/divinelab-io/aegis/internal/core/admin/session"
	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/divinelab-io/aegis/internal/edition"
	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/health"
	"github.com/divinelab-io/aegis/internal/infra/mail"
	"github.com/divinelab-io/aegis/internal/infra/metrics"
	"github.com/divinelab-io/aegis/internal/infra/telemetry"
	"github.com/divinelab-io/aegis/internal/infra/transport"
	"github.com/divinelab-io/aegis/internal/rules"
	"github.com/divinelab-io/aegis/internal/sections"
	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
)

// Version info (set via ldflags: -X 'github.com/.../admin.Version=1.0.0')
var (
	Version   string // Set via ldflags
	BuildDate string // Set via ldflags
)

// AdminServer manages the administration interface.
type AdminServer struct {
	logger         *zap.Logger
	config         config.ServerConfig
	mux            *http.ServeMux
	sessions       *scs.SessionManager
	userRepo       user.Repository
	sections       *app.SectionManager
	health         *health.Handler
	proxyTransport *transport.BreakerTransport
	tlsManager     *transport.TLSManager
	router         *transport.Router
	ruleStore      *rules.Store
	analyticsStore *analytics.Store

	// Handlers and Middleware
	authMW     *middleware.AuthMiddleware
	rbacMW     *middleware.RBACMiddleware
	handlers   *handlers.Handler
	metricsHdl *handlers.MetricsHandler
	identityMW func(http.Handler) http.Handler
}

// NewAdminServer creates a new admin server.
func NewAdminServer(userRepo user.Repository, cfg config.ServerConfig, logger *zap.Logger, sectionMgr *app.SectionManager, healthHdl *health.Handler, proxyTransport *transport.BreakerTransport, upstreamMgr *transport.UpstreamManager, tlsMgr *transport.TLSManager, realIPResolver *transport.RealIPResolver, router *transport.Router, unifiedMetrics *metrics.UnifiedCollector, ruleStore *rules.Store, analyticsStore *analytics.Store, updaterSocket string, identityMW func(http.Handler) http.Handler, errorPagesStores ...config.ErrorPagesStore) *AdminServer {
	// Identity and RBAC use PostgreSQL control-plane storage. Analytics storage
	// is injected independently through ruleStore and analyticsStore.

	// Create the configured bootstrap account only for a brand-new installation.
	// Existing administration identities remain authoritative across restarts.
	ctx := context.Background()
	if err := ensureConfiguredAdminUser(ctx, userRepo, cfg, logger); err != nil {
		logger.Error("Failed to ensure configured admin user", zap.Error(err))
	}

	// Secure cookies can be enabled when the loopback-only admin server is
	// published through an HTTPS reverse proxy.
	sessionManager := session.NewManager(cfg.Admin.SecureCookies)
	authMW := middleware.NewAuthMiddleware(sessionManager, userRepo)
	rbacMW := middleware.NewRBACMiddleware(sessionManager)

	// Authentication endpoints use independent, bounded budgets. This prevents
	// reset traffic from exhausting login capacity and limits TOTP guessing.
	loginLimiter := middleware.NewRateLimiter(20, 1*time.Minute)
	passwordResetLimiter := middleware.NewRateLimiter(10, 15*time.Minute)
	mfaAttemptLimiter := middleware.NewRateLimiter(5, 5*time.Minute)

	// Initialize Audit Logger
	auditLogger := audit.NewAuditLogger(userRepo, sessionManager, logger)
	auditLogger.SetRealIPResolver(realIPResolver)
	auditLogger.ConfigureRetention(cfg.Admin.AuditRetentionDays)

	// Initialize Mailer
	mailer := mail.NewMailer(cfg.SMTP, logger)

	// Initialize Handlers
	h := handlers.NewHandler(
		logger,
		cfg,
		sessionManager,
		userRepo,
		sectionMgr,
		healthHdl,
		proxyTransport,
		upstreamMgr,
		loginLimiter,
		passwordResetLimiter,
		mfaAttemptLimiter,
		auditLogger,
		mailer,
		tlsMgr,
		realIPResolver,
		router,
		ruleStore,
		analyticsStore,
		updaterSocket,
		authMW,
	)
	if len(errorPagesStores) > 0 {
		h.ErrorPagesStore = errorPagesStores[0]
		if captchaStore, ok := errorPagesStores[0].(config.CaptchaStore); ok {
			h.CaptchaStore = captchaStore
		}
		if securityTXTStore, ok := errorPagesStores[0].(config.SecurityTXTStore); ok {
			h.SecurityTXTStore = securityTXTStore
		}
		if infrastructureStore, ok := errorPagesStores[0].(config.InfrastructureStore); ok {
			h.InfrastructureStore = infrastructureStore
		}
		if upstreamRuntimeStore, ok := errorPagesStores[0].(config.UpstreamRuntimeStore); ok {
			h.UpstreamRuntimeStore = upstreamRuntimeStore
		}
		if upstreamGroupsStore, ok := errorPagesStores[0].(config.UpstreamGroupsStore); ok {
			h.UpstreamGroupsStore = upstreamGroupsStore
		}
		if routeRulesStore, ok := errorPagesStores[0].(config.RouteRulesStore); ok {
			h.RouteRulesStore = routeRulesStore
		}
		if circuitBreakerStore, ok := errorPagesStores[0].(config.CircuitBreakerStore); ok {
			h.CircuitBreakerStore = circuitBreakerStore
		}
		if legacyRoutesStore, ok := errorPagesStores[0].(config.LegacyRoutesStore); ok {
			h.LegacyRoutesStore = legacyRoutesStore
		}
		if stickySecretStore, ok := errorPagesStores[0].(config.StickySecretStore); ok {
			h.StickySecretStore = stickySecretStore
		}
		if trafficControlStore, ok := errorPagesStores[0].(config.TrafficControlStore); ok {
			h.TrafficControlStore = trafficControlStore
		}
		if wafStore, ok := errorPagesStores[0].(config.WAFStore); ok {
			h.WAFStore = wafStore
		}
		if botStore, ok := errorPagesStores[0].(config.BotStore); ok {
			h.BotStore = botStore
		}
		if httpSecurityStore, ok := errorPagesStores[0].(config.HTTPSecurityStore); ok {
			h.HTTPSecurityStore = httpSecurityStore
		}
		if apiSecurityStore, ok := errorPagesStores[0].(config.APISecurityStore); ok {
			h.APISecurityStore = apiSecurityStore
		}
		if accessControlStore, ok := errorPagesStores[0].(config.AccessControlStore); ok {
			h.AccessControlStore = accessControlStore
		}
		if reputationStore, ok := errorPagesStores[0].(config.ReputationStore); ok {
			h.ReputationStore = reputationStore
		}
		if challengeStore, ok := errorPagesStores[0].(config.ChallengeStore); ok {
			h.ChallengeStore = challengeStore
		}
		if controlPlaneDocuments, ok := errorPagesStores[0].(handlers.ConfigurationDocumentInspector); ok {
			h.ControlPlaneDocuments = controlPlaneDocuments
		}
	}

	// Set Version info into handlers package vars
	handlers.Version = Version
	handlers.BuildDate = BuildDate
	// ServerStartTime is already set on init in handlers package

	// Initialize Metrics Handler with unified collector
	metricsHdl := handlers.NewMetricsHandler(unifiedMetrics, logger)

	s := &AdminServer{
		logger:         logger,
		config:         cfg,
		mux:            http.NewServeMux(),
		userRepo:       userRepo,
		sections:       sectionMgr,
		health:         healthHdl,
		sessions:       sessionManager,
		proxyTransport: proxyTransport,
		tlsManager:     tlsMgr,
		router:         router,
		ruleStore:      ruleStore,
		analyticsStore: analyticsStore,
		handlers:       h,
		authMW:         authMW,
		rbacMW:         rbacMW,
		metricsHdl:     metricsHdl,
		identityMW:     identityMW,
	}
	s.routes()
	return s
}

func ensureConfiguredAdminUser(ctx context.Context, userRepo user.Repository, cfg config.ServerConfig, logger *zap.Logger) error {
	if !cfg.Admin.SetupCompleted {
		logger.Info("First-run setup pending. Skipping bootstrap admin creation.")
		return nil
	}

	role, err := userRepo.GetRoleByName(ctx, "super_admin")
	if err != nil {
		return err
	}
	if role == nil {
		return fmt.Errorf("super_admin role not found")
	}

	adminUsername := cfg.Admin.Username
	if adminUsername == "" {
		adminUsername = "admin"
	}

	count, err := userRepo.CountUsers(ctx)
	if err != nil {
		return err
	}

	if count == 0 {
		if cfg.Admin.Password == "" {
			return errors.New("initial administrator account setup requires AEGIS_ADMIN_PASSWORD (configure in aegis.env or set the environment variable)")
		}
		adminHash, err := user.HashPassword(cfg.Admin.Password)
		if err != nil {
			return err
		}
		logger.Warn("Configured admin user missing. Creating bootstrap admin.", zap.String("username", adminUsername))
		adminUser := &user.User{
			ID:           uuid.New(),
			Username:     adminUsername,
			Email:        fmt.Sprintf("%s@aegis.local", adminUsername),
			PasswordHash: adminHash,
			RoleID:       role.ID,
			IsActive:     true,
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
		}
		if err := userRepo.CreateUser(ctx, adminUser); err != nil {
			return err
		}
		logger.Warn("Bootstrap admin user created.", zap.String("username", adminUsername))
	}

	return nil
}

// withAuthenticatedOperator propagates the server-issued session identity to
// revisioned control-plane handlers. It never accepts an identity from a
// client header or request body.
func (s *AdminServer) withAuthenticatedOperator(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		operator := ""
		if s.sessions != nil {
			operator = s.sessions.GetString(r.Context(), "user_uuid")
			if operator == "" {
				operator = s.sessions.GetString(r.Context(), "user_id")
			}
		}
		handler(w, r.WithContext(sections.WithAuthenticatedOperator(r.Context(), operator)))
	}
}

func (s *AdminServer) routes() {
	// Serve Frontend Static Files with SPA support
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		normalizedPath := r.URL.Path
		if len(normalizedPath) > 1 {
			normalizedPath = strings.TrimSuffix(normalizedPath, "/")
		}

		// If API path not matched by specific handlers, return 404
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		// Explicitly serve login.html for /admin/login
		if normalizedPath == "/admin/login" {
			if s.shouldServeFirstRunSetup(r.Context()) {
				http.ServeFile(w, r, "web/admin/index.html")
				return
			}
			http.ServeFile(w, r, "web/admin/login.html")
			return
		}
		if normalizedPath == "/admin/request-reset" {
			http.ServeFile(w, r, "web/admin/reset_request.html")
			return
		}
		if normalizedPath == "/admin/reset-confirm" {
			http.ServeFile(w, r, "web/admin/reset_confirm.html")
			return
		}

		// Check if physical file exists

		// Check if physical file exists
		path := filepath.Join("web/admin", r.URL.Path)
		info, err := os.Stat(path)

		// If file doesn't exist or is a directory (and not requesting root), serve index.html
		if os.IsNotExist(err) || (info.IsDir() && r.URL.Path != "/") {
			http.ServeFile(w, r, "web/admin/index.html")
			return
		}

		// Otherwise serve the static file
		http.ServeFile(w, r, path)
	})

	// Serve WAF Tester
	testerFs := http.FileServer(http.Dir("./web/tester"))
	s.mux.Handle("/tester/", http.StripPrefix("/tester/", testerFs))

	auditConfig := func(resource string, h http.Handler) http.Handler {
		if s.handlers == nil || s.handlers.Audit == nil {
			return h
		}
		return s.handlers.Audit.LogConfigMutation(resource, h)
	}

	// Section-specific API routes - PROTECTED WITH AUTH
	if s.sections != nil {
		authMux := http.NewServeMux()
		s.sections.RegisterRoutes(authMux)
		guardedSections := s.guardTrafficSection(s.guardBotProtection(s.guardWAFSection(s.guardAPISecuritySection(s.guardAccessControlSection(s.guardAppSecuritySection(authMux))))))
		sectionOperatorContext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			operator := ""
			if s.sessions != nil {
				operator = s.sessions.GetString(r.Context(), "user_uuid")
				if operator == "" {
					operator = s.sessions.GetString(r.Context(), "user_id")
				}
			}
			guardedSections.ServeHTTP(w, r.WithContext(sections.WithAuthenticatedOperator(r.Context(), operator)))
		})
		s.mux.Handle("/api/sections/", auditConfig("sections", s.authMW.RequireAuth(s.authMW.RequireCSRF(sectionOperatorContext))))
	}
	// Global Health status
	if s.health != nil {
		s.mux.HandleFunc("/api/health", s.health.HealthHandler)
	}

	// API Endpoints (Login is Public, optionally rate limited inside handler)
	s.mux.HandleFunc("/api/login", s.handlers.HandleLogin)
	s.mux.Handle("/api/logout", s.authMW.RequireAuth(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleLogout))))
	s.mux.Handle("/api/verify_session", s.authMW.RequireAuth(http.HandlerFunc(s.handlers.HandleVerifySession)))
	s.mux.HandleFunc("/api/request-reset", s.handlers.HandleRequestPasswordReset)
	s.mux.HandleFunc("/api/reset-password", s.handlers.HandleResetPassword)
	s.mux.HandleFunc("/api/login/mfa", s.handlers.HandleVerifyMFA) // 2nd step login

	// Protected API Endpoints
	// Protected API Endpoints
	// We wrap all these with RequireAuth defined below
	// Define wrappers first
	wrap := func(h http.HandlerFunc) http.Handler {
		return s.authMW.RequireAuth(h)
	}
	wrapCSRF := func(h http.HandlerFunc) http.Handler {
		return s.authMW.RequireAuth(s.authMW.RequireCSRF(h))
	}

	wrapPerm := func(perm string, h http.HandlerFunc) http.Handler {
		return s.authMW.RequireAuth(s.rbacMW.RequirePermission(perm)(h))
	}
	wrapPermCSRF := func(perm string, h http.HandlerFunc) http.Handler {
		return s.authMW.RequireAuth(s.rbacMW.RequirePermission(perm)(s.authMW.RequireCSRF(h)))
	}
	wrapFeaturesPerm := func(features []edition.FeatureID, perm string, h http.HandlerFunc) http.Handler {
		return s.authMW.RequireAuth(s.requireEditionFeatures(features...)(s.rbacMW.RequirePermission(perm)(h)))
	}

	// First-run setup
	s.mux.HandleFunc("/api/setup/status", s.handlers.HandleSetupStatus)
	s.mux.HandleFunc("/api/setup/bootstrap", s.handlers.HandleSetupBootstrap)
	s.mux.HandleFunc("/api/setup/first-admin", s.handlers.HandleSetupFirstAdmin)
	s.mux.HandleFunc("/api/setup/storage/control/postgresql/preflight", s.handlers.HandleSetupStorageControlPostgreSQLPreflight)
	s.mux.HandleFunc("/api/setup/storage/control/postgresql/pending", s.handlers.HandleSetupStorageControlPostgreSQLPending)
	s.mux.HandleFunc("/api/setup/storage/analytics/clickhouse/preflight", s.handlers.HandleSetupStorageAnalyticsClickHousePreflight)
	s.mux.HandleFunc("/api/setup/storage/analytics/clickhouse/pending", s.handlers.HandleSetupStorageAnalyticsClickHousePending)
	s.mux.Handle("/api/setup/complete", auditConfig("system.setup", wrapPermCSRF("system:config", s.handlers.HandleSetupComplete)))

	// MFA
	s.mux.Handle("/api/mfa/setup", wrapCSRF(s.handlers.HandleSetupMFA))
	s.mux.Handle("/api/mfa/enable", wrapCSRF(s.handlers.HandleEnableMFA))
	s.mux.Handle("/api/mfa/disable", wrapCSRF(s.handlers.HandleDisableMFA))

	// Stats & Logs
	s.mux.Handle("/api/stats", wrap(s.handlers.HandleStats)) // General stats
	s.mux.Handle("/api/security/command-center", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "analytics:read", s.handlers.HandleCommandCenter))
	s.mux.Handle("/api/security/dashboard", wrapPerm("waf:read", s.handlers.HandleSecurityDashboard))
	s.mux.Handle("/api/security/dashboard/", wrapPerm("waf:read", s.handlers.HandleSecurityDashboard))
	s.mux.Handle("/api/stats/pipeline", wrapPerm("waf:read", s.handlers.HandlePipelineStats))
	s.mux.Handle("/api/logs", wrapPerm("logs:read", s.handlers.HandleLogs)) // WAF Threat Logs
	s.mux.Handle("/api/analytics", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "analytics:read", s.handlers.HandleAnalytics))
	s.mux.Handle("/api/analytics/", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "analytics:read", s.handlers.HandleAnalytics))
	s.mux.Handle("/api/traffic-events", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "traffic:read", s.handlers.HandleTrafficEvents))
	s.mux.Handle("/api/traffic-events/", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "traffic:read", s.handlers.HandleTrafficEvents))
	s.mux.Handle("/api/audit-logs", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAdminAudit}, "audit:read", s.handlers.HandleListAuditLogs))
	s.mux.Handle("/api/audit-logs/export", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAdminAudit}, "audit:read", s.handlers.HandleExportAuditLogs))

	// Prometheus Metrics
	s.mux.Handle("/api/metrics", s.authMW.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprint(w, s.prometheusFormat())
	})))

	// Config & Rules
	s.mux.Handle("/api/config", auditConfig("system.config", wrapPermCSRF("system:config", s.withAuthenticatedOperator(s.handlers.HandleConfig))))
	s.mux.Handle("/api/config/export", auditConfig("system.config.export", wrapPerm("system:config", s.handlers.HandleConfigExport)))
	s.mux.Handle("/api/config/backup", auditConfig("system.config.backup", wrapPerm("system:config", s.handlers.HandleConfigBackup)))
	s.mux.Handle("/api/config/import", auditConfig("system.config.import", wrapPermCSRF("system:config", s.handlers.HandleConfigImport)))
	s.mux.Handle("/api/config/reset", auditConfig("system.config.reset", wrapPermCSRF("system:config", s.handlers.HandleConfigReset)))
	// The PostgreSQL preflight is deliberately not audited as a config mutation:
	// its body contains a temporary password and the operation neither persists
	// nor activates a database configuration.
	s.mux.Handle("/api/storage/control/postgresql/preflight", wrapPermCSRF("system:config", s.handlers.HandleStorageControlPostgreSQLPreflight))
	s.mux.Handle("/api/storage/status", wrapPerm("system:config", s.handlers.HandleStorageStatus))
	// Saving a control configuration accepts only connection metadata and an
	// env: secret reference. It is audited and remains pending until restart.
	s.mux.Handle("/api/storage/control/postgresql/pending", auditConfig("storage.control.pending", wrapPermCSRF("system:config", s.handlers.HandleStorageControlPostgreSQLPending)))
	// ClickHouse receives the same staged, secret-safe operator flow, but it is
	// an analytics dependency and cannot alter PostgreSQL control state.
	s.mux.Handle("/api/storage/analytics/clickhouse/preflight", wrapPermCSRF("system:config", s.handlers.HandleStorageAnalyticsClickHousePreflight))
	s.mux.Handle("/api/storage/analytics/clickhouse/pending", auditConfig("storage.analytics.pending", wrapPermCSRF("system:config", s.handlers.HandleStorageAnalyticsClickHousePending)))
	// Rules API moved to WAF section (waf/api_editor.go)

	// Alerts
	s.mux.Handle("/api/alerts", wrap(s.handlers.HandleAlerts))
	s.mux.Handle("/api/alerts/read", wrapCSRF(s.handlers.HandleAlertsRead))

	// Module Configs
	s.mux.Handle("/api/modules/captcha/config", auditConfig("modules.captcha", wrapPermCSRF("waf:write", s.handlers.HandleCaptchaConfig)))
	s.mux.Handle("/api/modules/challenge/config", auditConfig("modules.challenge", wrapPerm("waf:write", s.handlers.HandleChallengeConfig)))
	s.mux.Handle("/api/modules/reputation/config", auditConfig("modules.reputation", wrapPerm("waf:write", s.handlers.HandleReputationConfig)))

	// Enterprise Rule Editor routes moved to WAF section

	// System & Infra
	s.mux.Handle("/api/system/update/check", wrap(s.handlers.HandleSystemUpdateCheck))
	s.mux.Handle("/api/system/update/apply", auditConfig("system.update", wrapPermCSRF("system:config", s.handlers.HandleSystemUpdateApply)))
	s.mux.Handle("/api/license", wrapPerm("system:config", s.handlers.HandleLicense))
	s.mux.Handle("/api/license/", auditConfig("system.license", s.authMW.RequireAuth(s.rbacMW.RequirePermission("system:config")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleLicenseAction))))))
	s.mux.Handle("/api/system", wrapPerm("system:config", s.handlers.HandleSystem))
	s.mux.Handle("/api/system/info", wrapPerm("infra:read", s.handlers.HandleSystemInfo))
	s.mux.Handle("/api/edge/overview", wrapPerm("infra:read", s.handlers.HandleInfrastructureOverview))
	s.mux.Handle("/api/edge/routes/test", wrapPerm("infra:read", s.handlers.HandleRouteTest))
	s.mux.Handle("/api/edge/templates/", wrapPerm("infra:read", s.handlers.HandleInfrastructureTemplate))
	s.mux.Handle("/api/infrastructure/overview", wrapPerm("infra:read", s.handlers.HandleInfrastructureOverview))
	s.mux.Handle("/api/infrastructure/routes/test", wrapPerm("infra:read", s.handlers.HandleRouteTest))
	s.mux.Handle("/api/infrastructure/templates/", wrapPerm("infra:read", s.handlers.HandleInfrastructureTemplate))
	s.mux.Handle("/api/infrastructure/proxy-settings", auditConfig("infrastructure.proxy_settings", s.authMW.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.rbacMW.RequirePermission("infra:read")(http.HandlerFunc(s.handlers.HandleProxySettings)).ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequirePermission("infra:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleProxySettings))).ServeHTTP(w, r)
	}))))
	s.mux.Handle("/api/upstreams/status", wrapPerm("infra:read", s.handlers.HandleUpstreamStatus))
	s.mux.Handle("/api/upstreams/settings", auditConfig("infrastructure.upstream_settings", s.authMW.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.rbacMW.RequirePermission("infra:read")(http.HandlerFunc(s.handlers.HandleUpstreamSettings)).ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequirePermission("infra:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleUpstreamSettings))).ServeHTTP(w, r)
	}))))
	s.mux.Handle("/api/upstreams/circuit-breaker", auditConfig("infrastructure.circuit_breaker", s.authMW.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.rbacMW.RequirePermission("infra:read")(http.HandlerFunc(s.handlers.HandleCircuitBreakerSettings)).ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequirePermission("infra:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleCircuitBreakerSettings))).ServeHTTP(w, r)
	}))))
	s.mux.Handle("/api/upstreams/legacy-routes", auditConfig("infrastructure.legacy_routes", s.authMW.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.rbacMW.RequirePermission("infra:read")(http.HandlerFunc(s.handlers.HandleLegacyRoutes)).ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequirePermission("infra:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleLegacyRoutes))).ServeHTTP(w, r)
	}))))
	s.mux.Handle("/api/upstreams/sticky-secret", auditConfig("infrastructure.sticky_secret", s.authMW.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.rbacMW.RequirePermission("infra:read")(http.HandlerFunc(s.handlers.HandleStickySecret)).ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequirePermission("infra:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleStickySecret))).ServeHTTP(w, r)
	}))))
	s.mux.Handle("/api/upstreams", auditConfig("infrastructure.upstreams", s.authMW.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.rbacMW.RequirePermission("infra:read")(http.HandlerFunc(s.handlers.HandleUpstreams)).ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequirePermission("infra:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleUpstreams))).ServeHTTP(w, r)
	}))))
	s.mux.Handle("/api/certificates", auditConfig("infrastructure.certificates", s.authMW.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.rbacMW.RequirePermission("infra:read")(http.HandlerFunc(s.handlers.HandleCertificates)).ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequirePermission("infra:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleCertificates))).ServeHTTP(w, r)
	}))))
	s.mux.Handle("/api/certificates/config", auditConfig("infrastructure.certificates", s.authMW.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.rbacMW.RequirePermission("infra:read")(http.HandlerFunc(s.handlers.HandleCertificatesConfig)).ServeHTTP(w, r)
		} else {
			s.rbacMW.RequirePermission("infra:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleCertificatesConfig))).ServeHTTP(w, r)
		}
	}))))
	s.mux.Handle("/api/modules", wrap(s.handlers.HandleModules))

	// Mount protected routes

	s.mux.Handle("/api/profile", s.authMW.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handlers.HandleGetProfile(w, r)
		case http.MethodPut:
			s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleUpdateProfile)).ServeHTTP(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	// Routes Config
	s.mux.Handle("/api/routes", auditConfig("infrastructure.routes", s.authMW.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.rbacMW.RequirePermission("infra:read")(http.HandlerFunc(s.handlers.HandleRoutes)).ServeHTTP(w, r)
			return
		}
		s.rbacMW.RequirePermission("infra:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleRoutes))).ServeHTTP(w, r)
	}))))

	// Unified Metrics API
	s.mux.Handle("/api/metrics/global", wrapPerm("infra:read", s.metricsHdl.HandleGlobalMetrics))
	s.mux.Handle("/api/metrics/sections", wrapPerm("infra:read", s.metricsHdl.HandleSections))
	s.mux.Handle("/api/metrics/sections/detail", wrapPerm("infra:read", s.metricsHdl.HandleSectionMetrics))

	// Traffic Metrics (Analytics Dashboard)
	s.mux.Handle("/api/metrics/traffic/realtime", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "infra:read", s.metricsHdl.HandleRealtime))
	s.mux.Handle("/api/metrics/traffic/timeseries", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "infra:read", s.metricsHdl.HandleTimeSeries))
	s.mux.Handle("/api/metrics/traffic/endpoints", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "infra:read", s.metricsHdl.HandleTopEndpoints))
	s.mux.Handle("/api/metrics/traffic/ips", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "infra:read", s.metricsHdl.HandleTopIPs))
	s.mux.Handle("/api/metrics/traffic/methods", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "infra:read", s.metricsHdl.HandleMethods))
	s.mux.Handle("/api/metrics/traffic/geographic", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "infra:read", s.metricsHdl.HandleGeographic))

	// Bot rule APIs
	botRuleHandler := s.authMW.RequireAuth(s.requireEditionFeatures(edition.FeatureBotProtection)(s.guardBotProtection(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleV2BotRules)))))
	s.mux.Handle("/api/v2/security/bot/rules", auditConfig("security.bot.rules", botRuleHandler))
	s.mux.Handle("/api/v2/security/bot/rules/", auditConfig("security.bot.rules", botRuleHandler))
	s.mux.Handle("/api/v2/security/waf/", wrapPerm("waf:read", s.handlers.HandleV2SecurityConfig))
	s.mux.Handle("/api/v2/security/bot/", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureBotProtection}, "waf:read", s.handlers.HandleV2SecurityConfig))
	s.mux.Handle("/api/v2/security/ddos/", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureTrafficDDoS}, "waf:read", s.handlers.HandleV2SecurityConfig))
	s.mux.Handle("/api/v2/security/api/", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAPISecurity}, "waf:read", s.handlers.HandleV2SecurityConfig))
	s.mux.Handle("/api/v2/security/app/", wrapPerm("waf:read", s.handlers.HandleV2SecurityConfig))
	s.mux.Handle("/api/v2/analytics/", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAnalyticsBasic}, "logs:read", s.handlers.HandleV2Analytics))

	// User Management API
	// API uses Method checks inside handler, but we can verify perm first.
	// Since creating a separate Handler for e.g. HandleCreateUser vs HandleListUsers is cleaner for granularity:
	// Wait, I created separate functions in users.go: HandleListUsers, HandleCreateUser, etc.
	// But server.go previously mostly used single endpoint per resource?
	// Looking at users.go:
	// HandleListUsers (GET), HandleCreateUser (POST)
	// I should register them separately if I want distinct permissions or URL patterns?
	// Actually, standard REST often uses same URL with different methods.
	// Go's ServeMux in 1.22+ supports "METHOD /path".
	// But I am using standard 1.21 probably?
	// My users.go handlers don't check method?
	// Wait, users.go:
	// HandleListUsers checks URL query?
	// HandleCreateUser expects body.

	// I must wrap them based on Method if I map them to the same path "/api/users".
	// OR I can use a sub-mux or a helper that dispatches by method.
	// Given the existing patterns (e.g. HandleStats), usually specific handlers are mapped.

	// Let's create a wrapper that dispatches by method to avoid cluttering server.go logic too much,
	// OR register distinct paths if possible? No, REST is /api/users.

	// I will define a helper closure to dispatch methods for /api/users
	// AND check permissions per method.

	s.mux.Handle("/api/users", s.authMW.RequireAuth(s.requireEditionFeatures(edition.FeatureAdminMultiUser, edition.FeatureAdminRBAC)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.rbacMW.RequirePermission("users:read")(http.HandlerFunc(s.handlers.HandleListUsers)).ServeHTTP(w, r)
		case http.MethodPost:
			s.rbacMW.RequirePermission("users:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleCreateUser))).ServeHTTP(w, r)
		case http.MethodPut:
			s.rbacMW.RequirePermission("users:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleUpdateUser))).ServeHTTP(w, r)
		case http.MethodDelete:
			s.rbacMW.RequirePermission("users:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleDeleteUser))).ServeHTTP(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))))
	s.mux.Handle("/api/roles", s.authMW.RequireAuth(s.requireEditionFeatures(edition.FeatureAdminRBAC)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.rbacMW.RequirePermission("users:read")(http.HandlerFunc(s.handlers.HandleListRoles)).ServeHTTP(w, r)
		case http.MethodPost:
			s.rbacMW.RequirePermission("users:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleCreateRole))).ServeHTTP(w, r)
		case http.MethodPut:
			s.rbacMW.RequirePermission("users:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleUpdateRole))).ServeHTTP(w, r)
		case http.MethodDelete:
			s.rbacMW.RequirePermission("users:write")(s.authMW.RequireCSRF(http.HandlerFunc(s.handlers.HandleDeleteRole))).ServeHTTP(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))))
	s.mux.Handle("/api/permissions", wrapFeaturesPerm([]edition.FeatureID{edition.FeatureAdminRBAC}, "users:read", s.handlers.HandleListPermissions))
}

func (s *AdminServer) shouldServeFirstRunSetup(ctx context.Context) bool {
	cfg := config.GetGlobalConfig()
	if cfg == nil || cfg.Server.Admin.SetupCompleted || s.userRepo == nil {
		return false
	}
	userCount, err := s.userRepo.CountUsers(ctx)
	if err != nil {
		s.logger.Warn("Failed to count admin users for first-run setup route", zap.Error(err))
		return false
	}
	if userCount == 0 {
		return true
	}
	if s.sessions != nil && s.sessions.Exists(ctx, "user_id") {
		return true
	}
	return false
}

// Start runs the admin server.
func (s *AdminServer) Start() error {
	host := strings.TrimSpace(s.config.Admin.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, strconv.Itoa(s.config.Admin.Port))
	s.logger.Info("Starting Admin Panel", zap.String("addr", addr))
	if !config.IsLoopbackHost(host) {
		s.logger.Warn(
			"Admin panel is exposed beyond loopback; place it behind an HTTPS reverse proxy",
			zap.String("addr", addr),
			zap.Bool("secure_cookies", s.config.Admin.SecureCookies),
		)
	}
	retentionCtx, cancelRetention := context.WithCancel(context.Background())
	defer cancelRetention()
	if s.handlers != nil && s.handlers.Audit != nil {
		s.handlers.Audit.StartRetention(retentionCtx)
	}

	// Wrap mux with global middleware (Security Headers AND Session LoadAndSave)
	// IMPORTANT: LoadAndSave must be outer-most to ensure context is populated
	adminHandler := s.sessions.LoadAndSave(middleware.SecurityHeaders(s.mux))
	handler := telemetry.Middleware(s.prometheusExporter(adminHandler))
	handler = http.MaxBytesHandler(handler, 1<<20)
	if s.identityMW != nil {
		handler = s.identityMW(handler)
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       configuredAdminTimeout(s.config.ReadTimeout, 15*time.Second),
		WriteTimeout:      configuredAdminTimeout(s.config.WriteTimeout, 30*time.Second),
		ReadHeaderTimeout: configuredAdminTimeout(s.config.ReadHeaderTimeout, 5*time.Second),
		IdleTimeout:       configuredAdminTimeout(s.config.IdleTimeout, 60*time.Second),
		MaxHeaderBytes:    configuredAdminMaxHeaderBytes(s.config.MaxHeaderBytes),
	}
	return server.ListenAndServe()
}

func configuredAdminTimeout(raw string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func configuredAdminMaxHeaderBytes(value int) int {
	if value <= 0 {
		return 1 << 20
	}
	return value
}

func (s *AdminServer) prometheusExporter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := config.GetGlobalConfig()
		if cfg == nil {
			next.ServeHTTP(w, r)
			return
		}
		telemetryCfg := cfg.Telemetry
		if strings.TrimSpace(telemetryCfg.PrometheusPath) == "" {
			telemetryCfg.PrometheusPath = "/metrics"
		}
		if err := config.ValidatePrometheusPath(telemetryCfg.PrometheusPath); err != nil {
			// A stale or hand-edited invalid setting must never let the exporter
			// claim an admin route before authentication middleware runs.
			next.ServeHTTP(w, r)
			return
		}

		if r.URL.Path != telemetryCfg.PrometheusPath {
			next.ServeHTTP(w, r)
			return
		}

		if !telemetryCfg.PrometheusEnabled {
			http.NotFound(w, r)
			return
		}

		adminHost := strings.TrimSpace(s.config.Admin.Host)
		if adminHost == "" {
			adminHost = "127.0.0.1"
		}
		requiresToken := !config.IsLoopbackHost(adminHost)
		if (requiresToken || telemetryCfg.PrometheusToken != "") && !validPrometheusToken(r, telemetryCfg.PrometheusToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="aegis metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, s.prometheusFormat())
	})
}

func (s *AdminServer) prometheusFormat() string {
	var output strings.Builder
	output.WriteString(s.metricsHdl.PrometheusFormat())
	if s.handlers != nil && s.handlers.Audit != nil {
		auditStatus := s.handlers.Audit.WriteStatus()
		output.WriteString("# HELP aegis_audit_write_successes_total Successful primary audit-log writes since process start.\n")
		output.WriteString("# TYPE aegis_audit_write_successes_total counter\n")
		fmt.Fprintf(&output, "aegis_audit_write_successes_total %d\n", auditStatus.SuccessfulWrites)
		output.WriteString("# HELP aegis_audit_last_write_success_timestamp_seconds Unix timestamp of the latest successful primary audit-log write, or zero.\n")
		output.WriteString("# TYPE aegis_audit_last_write_success_timestamp_seconds gauge\n")
		lastSuccessAt := float64(0)
		if !auditStatus.LastSuccessAt.IsZero() {
			lastSuccessAt = float64(auditStatus.LastSuccessAt.UnixNano()) / float64(time.Second)
		}
		fmt.Fprintf(&output, "aegis_audit_last_write_success_timestamp_seconds %.9f\n", lastSuccessAt)
		output.WriteString("# HELP aegis_audit_write_failures_total Failed primary audit-log writes since process start.\n")
		output.WriteString("# TYPE aegis_audit_write_failures_total counter\n")
		fmt.Fprintf(&output, "aegis_audit_write_failures_total %d\n", auditStatus.FailedWrites)
		output.WriteString("# HELP aegis_audit_last_write_failure_timestamp_seconds Unix timestamp of the latest primary audit-log write failure, or zero.\n")
		output.WriteString("# TYPE aegis_audit_last_write_failure_timestamp_seconds gauge\n")
		lastFailureAt := float64(0)
		if !auditStatus.LastFailureAt.IsZero() {
			lastFailureAt = float64(auditStatus.LastFailureAt.UnixNano()) / float64(time.Second)
		}
		fmt.Fprintf(&output, "aegis_audit_last_write_failure_timestamp_seconds %.9f\n", lastFailureAt)
	}
	if s.sections != nil {
		if section, ok := s.sections.GetSection("traffic_control"); ok {
			if source, ok := section.(interface{ PrometheusMetrics() string }); ok {
				output.WriteString(source.PrometheusMetrics())
			}
		}
	}
	if s.tlsManager == nil {
		return output.String()
	}
	metrics := s.tlsManager.Metrics()
	output.WriteString("# HELP aegis_tls_certificate_lookups_total TLS certificate selection attempts.\n")
	output.WriteString("# TYPE aegis_tls_certificate_lookups_total counter\n")
	fmt.Fprintf(&output, "aegis_tls_certificate_lookups_total %d\n", metrics["certificate_lookups_total"])
	output.WriteString("# HELP aegis_tls_lookup_failures_total TLS certificate selection failures.\n")
	output.WriteString("# TYPE aegis_tls_lookup_failures_total counter\n")
	fmt.Fprintf(&output, "aegis_tls_lookup_failures_total %d\n", metrics["lookup_failures_total"])
	output.WriteString("# HELP aegis_tls_cold_cache_misses_total Auto-TLS domains not ready during a client handshake.\n")
	output.WriteString("# TYPE aegis_tls_cold_cache_misses_total counter\n")
	fmt.Fprintf(&output, "aegis_tls_cold_cache_misses_total %d\n", metrics["cold_cache_misses_total"])
	output.WriteString("# HELP aegis_tls_acme_challenges_total TLS-ALPN-01 challenge certificate lookups.\n")
	output.WriteString("# TYPE aegis_tls_acme_challenges_total counter\n")
	fmt.Fprintf(&output, "aegis_tls_acme_challenges_total %d\n", metrics["acme_challenges_total"])
	return output.String()
}

func validPrometheusToken(r *http.Request, expected string) bool {
	auth := r.Header.Get("Authorization")
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}
