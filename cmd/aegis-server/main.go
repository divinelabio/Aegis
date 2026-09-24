package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/divinelab-io/aegis/internal/analytics"
	"github.com/divinelab-io/aegis/internal/app"
	"github.com/divinelab-io/aegis/internal/core/admin"
	"github.com/divinelab-io/aegis/internal/core/pipeline"
	"github.com/divinelab-io/aegis/internal/core/user"
	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/configstore"
	"github.com/divinelab-io/aegis/internal/infra/geoip"
	"github.com/divinelab-io/aegis/internal/infra/health"
	"github.com/divinelab-io/aegis/internal/infra/metrics"
	"github.com/divinelab-io/aegis/internal/infra/storage"
	"github.com/divinelab-io/aegis/internal/infra/telemetry"
	"github.com/divinelab-io/aegis/internal/infra/transport"
	"github.com/divinelab-io/aegis/internal/modules/captcha"
	"github.com/divinelab-io/aegis/internal/rules"
	"github.com/divinelab-io/aegis/internal/sections"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

// Version info injected at build time via ldflags:
//
//	-X main.Version=1.0.0 -X main.BuildDate=2025-01-01
var (
	Version   = "dev"
	BuildDate = "unknown"

	// CommercialInit is nil in Community builds. The Professional and
	// Enterprise overlays set it before main runs.
	CommercialInit func(ctx interface{}, cfg interface{}, ruleStore interface{}, logger interface{}, version string) error
)

func printUsage() {
	fmt.Printf(`Aegis Web Application Firewall & Reverse Proxy

Usage:
  aegis [command] [flags]

Commands:
  run              Start Aegis in the foreground (default)
  start            Alias for run
  config check     Validate configuration file syntax and integrity
  version          Print version and build details

Flags:
  -c, --config     Path to configuration file (default: "config.yaml" or $AEGIS_CONFIG)
  -e, --env        Path to environment file (default: "aegis.env" or ".env")
  -v, --version    Print version and exit
  -h, --help       Print this help message
`)
}

func parseCLI(args []string) (command string, configPath string, envPath string, err error) {
	configPath = os.Getenv("AEGIS_CONFIG")
	if configPath == "" {
		configPath = "config.yaml"
	}

	command = "run"
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help" || arg == "help":
			return "help", configPath, envPath, nil
		case arg == "-v" || arg == "--version":
			return "version", configPath, envPath, nil
		case arg == "-c" || arg == "--config":
			if i+1 >= len(args) {
				return "", "", "", fmt.Errorf("%s requires a file path", arg)
			}
			i++
			configPath = args[i]
		case strings.HasPrefix(arg, "--config="):
			configPath = strings.TrimPrefix(arg, "--config=")
		case arg == "-e" || arg == "--env":
			if i+1 >= len(args) {
				return "", "", "", fmt.Errorf("%s requires a file path", arg)
			}
			i++
			envPath = args[i]
		case strings.HasPrefix(arg, "--env="):
			envPath = strings.TrimPrefix(arg, "--env=")
		default:
			if strings.HasPrefix(arg, "-") {
				return "", "", "", fmt.Errorf("unknown flag %q; run 'aegis --help' for usage", arg)
			}
			positional = append(positional, arg)
		}
	}

	if len(positional) > 0 {
		switch positional[0] {
		case "version":
			return "version", configPath, envPath, nil
		case "help":
			return "help", configPath, envPath, nil
		case "run", "start":
			command = "run"
		case "config":
			if len(positional) > 1 && (positional[1] == "check" || positional[1] == "test" || positional[1] == "validate") {
				return "config-check", configPath, envPath, nil
			}
			return "", "", "", fmt.Errorf("unknown config subcommand %q; use 'aegis config check'", strings.Join(positional[1:], " "))
		default:
			return "", "", "", fmt.Errorf("unknown command %q; run 'aegis --help' for usage", positional[0])
		}
	}

	return command, configPath, envPath, nil
}

func main() {
	cmd, configPath, envPath, err := parseCLI(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis: %v\n", err)
		os.Exit(1)
	}

	switch cmd {
	case "help":
		printUsage()
		return
	case "version":
		fmt.Printf("Aegis Web Application Firewall %s (built %s)\n", Version, BuildDate)
		return
	case "config-check":
		if envPath != "" {
			if err := config.LoadEnvFile(envPath); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to load %s: %v\n", envPath, err)
			}
		} else {
			config.AutoLoadEnv()
		}
		if _, err := config.LoadConfig(configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Configuration error in %s: %v\n", configPath, err)
			os.Exit(1)
		}
		fmt.Printf("Configuration %s is valid.\n", configPath)
		return
	}

	// 1. Auto-load environment secrets
	if envPath != "" {
		if err := config.LoadEnvFile(envPath); err != nil {
			fmt.Printf("Warning: failed to load %s: %v\n", envPath, err)
		}
	} else {
		config.AutoLoadEnv()
	}

	// 2. Load Configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// 2. Initialize Telemetry (Logger)
	if err = telemetry.InitLogger(cfg.Log.Level); err != nil {
		fmt.Printf("Failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer telemetry.Sync()
	logger := telemetry.Logger
	config.SetCaptchaRuntimeActivator(configureCaptchaModule)
	if err := configureCaptcha(cfg); err != nil {
		logger.Fatal("Invalid CAPTCHA configuration", zap.Error(err))
	}
	if captcha.GetManager().PublicConfig().SecretKeyMigrationRequired {
		logger.Warn("CAPTCHA uses a legacy clear-text credential; migrate it to an env: secret reference before the next configuration save")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 3. Initialize transactional control-plane storage before any identity or
	// administration component. The password is resolved from its env: reference
	// and is not retained in the runtime configuration.
	ensureLocalPostgres(logger, cfg.Storage.Control.Host, cfg.Storage.Control.Port)
	controlDB, err := storage.InitControlDB(ctx, cfg.Storage.Control)
	if err != nil {
		logger.Fatal("Failed to initialize PostgreSQL control database", zap.Error(err))
	}
	defer storage.CloseControlDB()
	userRepo, err := user.NewPostgreSQLRepository(ctx, controlDB)
	if err != nil {
		logger.Fatal("Failed to initialize PostgreSQL control repository", zap.Error(err))
	}
	controlConfigStore, err := configstore.New(ctx, controlDB)
	if err != nil {
		logger.Fatal("Failed to initialize PostgreSQL configuration store", zap.Error(err))
	}
	kpiRollupStore := storage.NewKPIRollupStore(controlDB)
	if err := kpiRollupStore.EnsureKPIRollupSchema(ctx); err != nil {
		logger.Warn("Failed to ensure PostgreSQL KPI rollup schema", zap.Error(err))
	} else {
		logger.Info("PostgreSQL KPI rollup schema verified")
	}
	errorPagesDocument, errorPagesImported, err := config.InitializeErrorPagesControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize Error Pages control-plane configuration", zap.Error(err))
	}
	logger.Info("Error Pages control-plane configuration activated",
		zap.Int64("revision", errorPagesDocument.Revision),
		zap.Bool("yaml_imported", errorPagesImported),
	)
	securityTXTDocument, securityTXTImported, err := config.InitializeSecurityTXTControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize Security.txt control-plane configuration", zap.Error(err))
	}
	logger.Info("Security.txt control-plane configuration activated",
		zap.Int64("revision", securityTXTDocument.Revision),
		zap.Bool("yaml_imported", securityTXTImported),
	)
	captchaDocument, captchaImported, captchaInitializationErr := config.InitializeCaptchaControlPlane(ctx, controlConfigStore, cfg)
	if captchaInitializationErr != nil && !errors.Is(captchaInitializationErr, config.ErrCaptchaLegacySecretMigrationRequired) {
		logger.Fatal("Failed to initialize CAPTCHA control-plane configuration", zap.Error(captchaInitializationErr))
	}
	if errors.Is(captchaInitializationErr, config.ErrCaptchaLegacySecretMigrationRequired) {
		logger.Warn("CAPTCHA remains YAML-managed until its legacy clear-text credential is replaced with an env: reference")
	} else {
		logger.Info("CAPTCHA control-plane configuration activated",
			zap.Int64("revision", captchaDocument.Revision),
			zap.Bool("yaml_imported", captchaImported),
		)
	}
	infrastructureDocument, infrastructureImported, err := config.InitializeInfrastructureControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize infrastructure control-plane configuration", zap.Error(err))
	}
	logger.Info("Infrastructure control-plane configuration activated",
		zap.Int64("revision", infrastructureDocument.Revision),
		zap.Bool("yaml_imported", infrastructureImported),
	)
	upstreamRuntimeDocument, upstreamRuntimeImported, err := config.InitializeUpstreamRuntimeControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize upstream runtime control-plane configuration", zap.Error(err))
	}
	logger.Info("Upstream runtime control-plane configuration activated",
		zap.Int64("revision", upstreamRuntimeDocument.Revision),
		zap.Bool("yaml_imported", upstreamRuntimeImported),
	)
	stickySecretDocument, stickySecretImported, stickySecretInitializationErr := config.InitializeStickySecretControlPlane(ctx, controlConfigStore, cfg)
	if stickySecretInitializationErr != nil && !errors.Is(stickySecretInitializationErr, config.ErrStickySecretLegacyMigrationRequired) {
		logger.Fatal("Failed to initialize sticky-session secret control-plane configuration", zap.Error(stickySecretInitializationErr))
	}
	if errors.Is(stickySecretInitializationErr, config.ErrStickySecretLegacyMigrationRequired) {
		logger.Warn("Sticky sessions remain YAML-managed until their legacy clear-text secret is replaced with an env: reference")
	} else {
		logger.Info("Sticky-session secret control-plane configuration activated",
			zap.Int64("revision", stickySecretDocument.Revision),
			zap.Bool("yaml_imported", stickySecretImported),
		)
	}
	upstreamGroupsDocument, upstreamGroupsImported, err := config.InitializeUpstreamGroupsControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize upstream Origin-pool control-plane configuration", zap.Error(err))
	}
	logger.Info("Upstream Origin-pool control-plane configuration activated",
		zap.Int64("revision", upstreamGroupsDocument.Revision),
		zap.Bool("yaml_imported", upstreamGroupsImported),
	)
	legacyRoutesDocument, legacyRoutesImported, err := config.InitializeLegacyRoutesControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize legacy host-route control-plane configuration", zap.Error(err))
	}
	logger.Info("Legacy host-route control-plane configuration activated",
		zap.Int64("revision", legacyRoutesDocument.Revision),
		zap.Bool("yaml_imported", legacyRoutesImported),
	)
	routeRulesDocument, routeRulesImported, err := config.InitializeRouteRulesControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize route-rule control-plane configuration", zap.Error(err))
	}
	logger.Info("Route-rule control-plane configuration activated",
		zap.Int64("revision", routeRulesDocument.Revision),
		zap.Bool("yaml_imported", routeRulesImported),
	)
	circuitBreakerDocument, circuitBreakerImported, err := config.InitializeCircuitBreakerControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize circuit-breaker control-plane configuration", zap.Error(err))
	}
	logger.Info("Circuit-breaker control-plane configuration activated",
		zap.Int64("revision", circuitBreakerDocument.Revision),
		zap.Bool("yaml_imported", circuitBreakerImported),
	)
	trafficControlDocument, trafficControlImported, err := config.InitializeTrafficControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize traffic-control control-plane configuration", zap.Error(err))
	}
	logger.Info("Traffic-control control-plane configuration activated",
		zap.Int64("revision", trafficControlDocument.Revision),
		zap.Bool("yaml_imported", trafficControlImported),
	)
	wafDocument, wafImported, err := config.InitializeWAFControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize waf control-plane configuration", zap.Error(err))
	}
	logger.Info("WAF control-plane configuration activated",
		zap.Int64("revision", wafDocument.Revision),
		zap.Bool("yaml_imported", wafImported),
	)
	botDocument, botImported, err := config.InitializeBotControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize bot control-plane configuration", zap.Error(err))
	}
	logger.Info("Bot Protection control-plane configuration activated",
		zap.Int64("revision", botDocument.Revision),
		zap.Bool("yaml_imported", botImported),
	)
	httpSecurityDocument, httpSecurityImported, err := config.InitializeHTTPSecurityControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize http-security control-plane configuration", zap.Error(err))
	}
	logger.Info("HTTP Security control-plane configuration activated",
		zap.Int64("revision", httpSecurityDocument.Revision),
		zap.Bool("yaml_imported", httpSecurityImported),
	)
	apiSecurityDocument, apiSecurityImported, err := config.InitializeAPISecurityControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize api-security control-plane configuration", zap.Error(err))
	}
	logger.Info("API Security control-plane configuration activated",
		zap.Int64("revision", apiSecurityDocument.Revision),
		zap.Bool("yaml_imported", apiSecurityImported),
	)
	accessControlDocument, accessControlImported, err := config.InitializeAccessControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize access-control control-plane configuration", zap.Error(err))
	}
	logger.Info("Access Control control-plane configuration activated",
		zap.Int64("revision", accessControlDocument.Revision),
		zap.Bool("yaml_imported", accessControlImported),
	)
	reputationDocument, reputationImported, err := config.InitializeReputationControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize reputation control-plane configuration", zap.Error(err))
	}
	logger.Info("Reputation control-plane configuration activated",
		zap.Int64("revision", reputationDocument.Revision),
		zap.Bool("yaml_imported", reputationImported),
	)
	challengeDocument, challengeImported, err := config.InitializeChallengeControlPlane(ctx, controlConfigStore, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize challenge control-plane configuration", zap.Error(err))
	}
	logger.Info("Smart Challenge control-plane configuration activated",
		zap.Int64("revision", challengeDocument.Revision),
		zap.Bool("yaml_imported", challengeImported),
	)
	config.SetRouteRulesControlPlaneMutator(func(mutator func([]config.RouteConfig) ([]config.RouteConfig, error)) ([]config.RouteConfig, error) {
		document, err := config.MutateRouteRulesControlPlane(ctx, controlConfigStore, mutator, "system:access_control", "edge_access_route_mutation")
		if err != nil {
			return nil, err
		}
		return document.Rules, nil
	})
	if err := controlConfigStore.StartErrorPagesChangeListener(ctx, func(_ context.Context, document config.ErrorPagesDocument) error {
		if err := config.ApplyErrorPagesControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Error Pages control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Error Pages control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start Error Pages control-plane listener", zap.Error(err))
	}
	if err := controlConfigStore.StartSecurityTXTChangeListener(ctx, func(_ context.Context, document config.SecurityTXTDocument) error {
		if err := config.ApplySecurityTXTControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Security.txt control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Security.txt control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start Security.txt control-plane listener", zap.Error(err))
	}
	if err := controlConfigStore.StartCaptchaChangeListener(ctx, func(_ context.Context, document config.CaptchaDocument) error {
		if err := config.ApplyCaptchaControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("CAPTCHA control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("CAPTCHA control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start CAPTCHA control-plane listener", zap.Error(err))
	}

	// 4. Initialize optional ClickHouse analytics after the transactional
	// control plane. Analytics failure must not prevent a PostgreSQL-backed
	// self-hosted deployment from enforcing its committed controls.
	analyticsMode := cfg.Storage.Analytics.EffectiveMode()
	analyticsAvailable, analyticsInitErr := storage.InitAnalytics(cfg.Storage.Analytics)
	if analyticsInitErr != nil {
		if analyticsMode == storage.AnalyticsModeRequired {
			logger.Fatal("Failed to initialize required ClickHouse analytics database", zap.Error(analyticsInitErr))
		}
		logger.Warn("ClickHouse analytics is unavailable; continuing with PostgreSQL control plane only", zap.Error(analyticsInitErr))
	}
	if err := telemetry.InitAccessLogger(telemetry.AccessLogConfig{
		Enabled:      cfg.AccessLog.Enabled,
		Path:         cfg.AccessLog.Path,
		RotateSizeMB: cfg.AccessLog.RotateSizeMB,
		KeepFiles:    cfg.AccessLog.KeepFiles,
	}); err != nil {
		logger.Fatal("Failed to initialize access logger", zap.Error(err))
	}
	ruleStore, err := rules.NewStore(ctx, controlDB)
	if err != nil {
		logger.Fatal("Failed to initialize rule store", zap.Error(err))
	}
	var analyticsStore *analytics.Store
	if analyticsAvailable {
		analyticsStore, err = analytics.NewStore(storage.DB)
		if err != nil {
			logger.Fatal("Failed to initialize analytics store", zap.Error(err))
		}
	} else {
		logger.Info("ClickHouse analytics disabled", zap.String("mode", string(analyticsMode)))
	}

	logger.Info("Starting Aegis WAF", zap.Int("port", cfg.Server.Port))

	unifiedMetrics := metrics.NewUnifiedCollector()
	healthHandler := health.NewHandler("2.0.0")

	geoConfig, err := cfg.GeoConfig()
	if err != nil {
		logger.Fatal("Invalid GeoIP configuration", zap.Error(err))
	}
	geoTTL, err := time.ParseDuration(geoConfig.CacheTTL)
	if err != nil {
		logger.Fatal("Invalid GeoIP cache TTL", zap.Error(err))
	}
	geoService := geoip.New(geoConfig.DBPath, geoTTL, geoip.DefaultCacheSize, logger)
	geoService.Start(ctx)

	// 5. Initialize sections via the active bundle (community or enterprise overlay)
	//    CommercialInit is nil in Community builds and initializes licensing in
	//    Professional and Enterprise builds before sections are registered.
	if CommercialInit != nil {
		if err := CommercialInit(ctx, cfg, ruleStore, logger, Version); err != nil {
			logger.Fatal("Commercial init failed", zap.Error(err))
		}
	}

	router := transport.NewRouter(cfg.Upstream.Rules)
	bundle := app.DefaultBundle()
	sectionMgr, err := app.NewSectionManager(bundle, logger, unifiedMetrics, app.BundleDependencies{
		Logger:               logger,
		Metrics:              unifiedMetrics,
		Geo:                  geoService,
		RuleStore:            ruleStore,
		AnalyticsStore:       analyticsStore,
		Router:               router,
		PersistSectionConfig: func(sectionID string, sectionConfig sections.SectionConfig) error {
			if sectionID == "traffic_control" {
				actor := "system:admin"
				_, err := config.SaveTrafficControlControlPlane(ctx, controlConfigStore, sectionConfig, actor, "admin_section_update")
				return err
			}
			if sectionID == "waf_core" {
				actor := "system:admin"
				_, err := config.SaveWAFControlPlane(ctx, controlConfigStore, sectionConfig, actor, "admin_section_update")
				return err
			}
			if sectionID == "bot_protection" {
				actor := "system:admin"
				_, err := config.SaveBotControlPlane(ctx, controlConfigStore, sectionConfig, actor, "admin_section_update")
				return err
			}
			if sectionID == "http_security" {
				actor := "system:admin"
				_, err := config.SaveHTTPSecurityControlPlane(ctx, controlConfigStore, sectionConfig, actor, "admin_section_update")
				return err
			}
			if sectionID == "api_security" {
				actor := "system:admin"
				_, err := config.SaveAPISecurityControlPlane(ctx, controlConfigStore, sectionConfig, actor, "admin_section_update")
				return err
			}
			if sectionID == "access_control" {
				actor := "system:admin"
				_, err := config.SaveAccessControlControlPlane(ctx, controlConfigStore, sectionConfig, actor, "admin_section_update")
				return err
			}
			return config.UpdateSectionConfig(sectionID, sectionConfig)
		},
	})
	if err != nil {
		logger.Fatal("Failed to register edition sections", zap.Error(err))
	}
	if err := sectionMgr.Init(cfg.GetSectionsConfigMap()); err != nil {
		logger.Fatal("Failed to initialize sections", zap.Error(err))
	}

	realIPResolver, err := transport.NewRealIPResolver(cfg.Infrastructure.TrustedProxies)
	if err != nil {
		logger.Fatal("Failed to initialize trusted proxy resolver", zap.Error(err))
	}
	fingerprintStore := transport.NewTLSFingerprintStore(0, 0)
	identityMiddleware := transport.NewIdentityMiddleware(ctx, realIPResolver, geoService, fingerprintStore)

	if err := sectionMgr.Start(ctx); err != nil {
		logger.Fatal("Failed to start sections", zap.Error(err))
	}
	logger.Info("Sections initialized", zap.Int("count", len(sectionMgr.ListSections())))

	healthHandler.RegisterCheck(func() health.Check {
		return sectionMgr.GlobalHealth()
	})
	healthHandler.RegisterCheck(func() health.Check {
		if analyticsAvailable {
			return health.Check{Name: "Analytics", Status: health.StatusHealthy, Message: "ClickHouse analytics available"}
		}
		if analyticsMode == storage.AnalyticsModeOptional {
			return health.Check{Name: "Analytics", Status: health.StatusDegraded, Message: "ClickHouse analytics unavailable; control plane remains active"}
		}
		return health.Check{Name: "Analytics", Status: health.StatusHealthy, Message: "ClickHouse analytics disabled by configuration"}
	})

	// 5. Build pipeline
	pipe := pipeline.New()
	telemetry.SetUnifiedMetrics(unifiedMetrics)
	telemetry.SetAnalyticsStore(analyticsStore)

	pipe.Use(identityMiddleware)
	pipe.Use(telemetry.Middleware)

	routeContextMiddleware, err := transport.NewRouteContextMiddleware(router, cfg.Infrastructure)
	if err != nil {
		logger.Fatal("Failed to initialize route context middleware", zap.Error(err))
	}
	pipe.Use(routeContextMiddleware)

	var analyticsSink rules.EventSink
	if analyticsStore != nil {
		analyticsSink = analytics.NewAsyncRuleEventSink(ctx, analyticsStore, logger)
	}
	ruleEngine := rules.NewEngine(ruleStore, analyticsSink)
	if err := ruleStore.StartRuleChangeListener(ctx, func(err error) {
		logger.Warn("Security rule change listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start security rule change listener", zap.Error(err))
	}
	if err := ruleEngine.Refresh(ctx); err != nil {
		logger.Warn("Security rule cache unavailable; request evaluation will retry", zap.Error(err))
	}
	pipe.Use(ruleEngine.Middleware)
	for _, mw := range sectionMgr.BuildMiddlewareChain() {
		pipe.Use(mw)
	}

	upstreamMgr, err := transport.NewUpstreamManager(cfg.Upstream, logger)
	if err != nil {
		logger.Fatal("Failed to initialize upstream manager", zap.Error(err))
	}
	upstreamMgr.StartHealthChecks(ctx)

	proxyHandler, router, err := transport.NewProxyWithRouter(cfg.Upstream.Target, cfg.Upstream.Routes, router, upstreamMgr, cfg.Server.ReadTimeout, cfg.Upstream.InsecureSkipVerify, cfg.Upstream.CircuitBreaker, cfg.Infrastructure)
	if err != nil {
		logger.Fatal("Failed to create reverse proxy", zap.Error(err))
	}
	breakerTransport := transport.BreakerTransportFrom(proxyHandler.Transport)
	if breakerTransport == nil {
		logger.Fatal("Failed to locate proxy runtime transport")
	}
	if err := breakerTransport.ReloadUpstream(cfg.Upstream, cfg.Server.ReadTimeout); err != nil {
		logger.Fatal("Failed to apply upstream runtime settings", zap.Error(err))
	}
	config.SetInfrastructureRuntimeActivator(func(next config.InfrastructureConfig) error {
		if err := realIPResolver.Reload(next.TrustedProxies); err != nil {
			return err
		}
		breakerTransport.ReloadInfrastructure(next)
		return nil
	})
	if err := controlConfigStore.StartInfrastructureChangeListener(ctx, func(_ context.Context, document config.InfrastructureDocument) error {
		if err := config.ApplyInfrastructureControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Infrastructure control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Infrastructure control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start infrastructure control-plane listener", zap.Error(err))
	}
	config.SetUpstreamRuntimeActivator(func(next config.UpstreamConfig) error {
		current := config.GetGlobalConfig()
		if current == nil {
			return errors.New("configuration is not loaded")
		}
		previous := current.Upstream
		if err := upstreamMgr.Reload(next); err != nil {
			return err
		}
		if err := breakerTransport.ReloadUpstream(next, current.Server.ReadTimeout); err != nil {
			_ = upstreamMgr.Reload(previous)
			return err
		}
		return nil
	})
	config.SetRouteRulesActivator(func(rules []config.RouteConfig) error {
		router.UpdateRules(rules)
		return nil
	})
	config.SetCircuitBreakerActivator(func(policy config.CircuitBreakerConfig) error {
		return breakerTransport.ReloadCircuitBreaker(policy)
	})
	config.SetLegacyRoutesActivator(func(routes map[string]string) error {
		return breakerTransport.ReloadLegacyRoutes(routes)
	})
	config.SetStickySecretRuntimeActivator(func(secret string) error {
		return upstreamMgr.ReloadStickySecret(secret)
	})
	if err := controlConfigStore.StartUpstreamRuntimeChangeListener(ctx, func(_ context.Context, document config.UpstreamRuntimeDocument) error {
		if err := config.ApplyUpstreamRuntimeControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Upstream runtime control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Upstream runtime control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start upstream runtime control-plane listener", zap.Error(err))
	}
	if err := controlConfigStore.StartStickySecretChangeListener(ctx, func(_ context.Context, document config.StickySecretDocument) error {
		if err := config.ApplyStickySecretControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Sticky-session secret control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Sticky-session secret control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start sticky-session secret control-plane listener", zap.Error(err))
	}
	if err := controlConfigStore.StartUpstreamGroupsChangeListener(ctx, func(_ context.Context, document config.UpstreamGroupsDocument) error {
		if err := config.ApplyUpstreamGroupsControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Upstream Origin-pool control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Upstream Origin-pool control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start upstream Origin-pool control-plane listener", zap.Error(err))
	}
	if err := controlConfigStore.StartLegacyRoutesChangeListener(ctx, func(_ context.Context, document config.LegacyRoutesDocument) error {
		if err := config.ApplyLegacyRoutesControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Legacy host-route control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Legacy host-route control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start legacy host-route control-plane listener", zap.Error(err))
	}
	if err := controlConfigStore.StartRouteRulesChangeListener(ctx, func(_ context.Context, document config.RouteRulesDocument) error {
		if err := config.ApplyRouteRulesControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Route-rule control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Route-rule control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start route-rule control-plane listener", zap.Error(err))
	}
	if err := controlConfigStore.StartCircuitBreakerChangeListener(ctx, func(_ context.Context, document config.CircuitBreakerDocument) error {
		if err := config.ApplyCircuitBreakerControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Circuit-breaker control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Circuit-breaker control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start circuit-breaker control-plane listener", zap.Error(err))
	}
	config.SetTrafficControlRuntimeActivator(func(next sections.SectionConfig) error {
		if sectionMgr == nil {
			return nil
		}
		sec, ok := sectionMgr.GetSection("traffic_control")
		if !ok || sec == nil {
			return nil
		}
		return sec.Init(next)
	})
	if err := controlConfigStore.StartTrafficControlChangeListener(ctx, func(_ context.Context, document config.TrafficControlDocument) error {
		if err := config.ApplyTrafficControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Traffic-control control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Traffic-control control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start traffic-control control-plane listener", zap.Error(err))
	}
	config.SetWAFRuntimeActivator(func(next sections.SectionConfig) error {
		if sectionMgr == nil {
			return nil
		}
		sec, ok := sectionMgr.GetSection("waf_core")
		if !ok || sec == nil {
			return nil
		}
		return sec.Init(next)
	})
	if err := controlConfigStore.StartWAFChangeListener(ctx, func(_ context.Context, document config.WAFDocument) error {
		if err := config.ApplyWAFControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("WAF control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("WAF control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start WAF control-plane listener", zap.Error(err))
	}
	config.SetBotRuntimeActivator(func(next sections.SectionConfig) error {
		if sectionMgr == nil {
			return nil
		}
		sec, ok := sectionMgr.GetSection("bot_protection")
		if !ok || sec == nil {
			return nil
		}
		return sec.Init(next)
	})
	if err := controlConfigStore.StartBotChangeListener(ctx, func(_ context.Context, document config.BotDocument) error {
		if err := config.ApplyBotControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Bot Protection control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Bot Protection control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start Bot Protection control-plane listener", zap.Error(err))
	}
	config.SetHTTPSecurityRuntimeActivator(func(next sections.SectionConfig) error {
		if sectionMgr == nil {
			return nil
		}
		sec, ok := sectionMgr.GetSection("http_security")
		if !ok || sec == nil {
			return nil
		}
		return sec.Init(next)
	})
	if err := controlConfigStore.StartHTTPSecurityChangeListener(ctx, func(_ context.Context, document config.HTTPSecurityDocument) error {
		if err := config.ApplyHTTPSecurityControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("HTTP Security control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("HTTP Security control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start HTTP Security control-plane listener", zap.Error(err))
	}
	config.SetAPISecurityRuntimeActivator(func(next sections.SectionConfig) error {
		if sectionMgr == nil {
			return nil
		}
		sec, ok := sectionMgr.GetSection("api_security")
		if !ok || sec == nil {
			return nil
		}
		return sec.Init(next)
	})
	if err := controlConfigStore.StartAPISecurityChangeListener(ctx, func(_ context.Context, document config.APISecurityDocument) error {
		if err := config.ApplyAPISecurityControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("API Security control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("API Security control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start API Security control-plane listener", zap.Error(err))
	}
	config.SetAccessControlRuntimeActivator(func(next sections.SectionConfig) error {
		if sectionMgr == nil {
			return nil
		}
		sec, ok := sectionMgr.GetSection("access_control")
		if !ok || sec == nil {
			return nil
		}
		return sec.Init(next)
	})
	if err := controlConfigStore.StartAccessControlChangeListener(ctx, func(_ context.Context, document config.AccessControlDocument) error {
		if err := config.ApplyAccessControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Access Control control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Access Control control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start Access Control control-plane listener", zap.Error(err))
	}
	if err := controlConfigStore.StartReputationChangeListener(ctx, func(_ context.Context, document config.ReputationDocument) error {
		if err := config.ApplyReputationControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Reputation control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Reputation control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start Reputation control-plane listener", zap.Error(err))
	}
	if err := controlConfigStore.StartChallengeChangeListener(ctx, func(_ context.Context, document config.ChallengeDocument) error {
		if err := config.ApplyChallengeControlPlaneDocument(document); err != nil {
			return err
		}
		logger.Info("Smart Challenge control-plane configuration synchronized", zap.Int64("revision", document.Revision))
		return nil
	}, func(err error) {
		logger.Warn("Smart Challenge control-plane listener will retry", zap.Error(err))
	}); err != nil {
		logger.Fatal("Failed to start Smart Challenge control-plane listener", zap.Error(err))
	}

	// 6. TLS
	tlsMgr, err := transport.NewTLSManager(cfg.Server.TLS, logger, fingerprintStore)
	if err != nil {
		logger.Fatal("Failed to initialize TLS Manager", zap.Error(err))
	}
	var tlsConfig *tls.Config = tlsMgr.GetTLSConfig()

	// 7. Build HTTP handler
	finalHandler := pipe.Build(proxyHandler)
	mainMux := http.NewServeMux()
	healthHandler.RegisterRoutes(mainMux)
	sectionMgr.RegisterPublicRoutes(mainMux)
	mainMux.HandleFunc("/.well-known/security.txt", app.SecurityTXTHandler)
	mainMux.Handle("/", finalHandler)

	serverAddr := fmt.Sprintf(":%d", cfg.Server.Port)
	var rootHandler http.Handler = mainMux

	if cfg.Server.EnableHTTP3 && cfg.Server.TLS.Enabled {
		rootHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=2592000`, cfg.Server.Port))
			mainMux.ServeHTTP(w, r)
		})
		go func() {
			logger.Info("Starting HTTP/3 (QUIC) listener", zap.String("addr", serverAddr))
			h3Server := &http3.Server{
				Addr:      serverAddr,
				Handler:   mainMux,
				TLSConfig: tlsConfig,
			}
			udpConn, err := net.ListenPacket("udp", serverAddr)
			if err != nil {
				logger.Error("HTTP/3 failed to listen UDP", zap.Error(err))
				return
			}
			if err := h3Server.Serve(udpConn); err != nil {
				logger.Error("HTTP/3 server failed", zap.Error(err))
			}
		}()
	}

	server := &http.Server{
		Addr:              serverAddr,
		Handler:           rootHandler,
		ReadTimeout:       parseDuration(cfg.Server.ReadTimeout),
		WriteTimeout:      parseDuration(cfg.Server.WriteTimeout),
		ReadHeaderTimeout: parseDuration(cfg.Server.ReadHeaderTimeout),
		IdleTimeout:       parseDuration(cfg.Server.IdleTimeout),
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
		TLSConfig:         tlsConfig,
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				fingerprintStore.ForgetConn(conn)
			}
		},
	}

	// 8. Start Admin Panel
	go func() {
		adminServer := admin.NewAdminServer(
			userRepo, cfg.Server, logger,
			sectionMgr, healthHandler,
			breakerTransport, upstreamMgr,
			tlsMgr, realIPResolver, router,
			unifiedMetrics, ruleStore, analyticsStore,
			cfg.Updater.SocketPath, identityMiddleware, controlConfigStore,
		)
		if err := adminServer.Start(); err != nil {
			logger.Error("Admin server failed", zap.Error(err))
		}
	}()

	// 9. Start proxy server
	go func() {
		logger.Info("Listening on", zap.String("addr", serverAddr), zap.Bool("tls", cfg.Server.TLS.Enabled))
		var err error
		if cfg.Server.TLS.Enabled {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed", zap.Error(err))
		}
	}()

	// 10. Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigChan
		if sig == syscall.SIGHUP {
			logger.Info("Received SIGHUP, reloading configuration...")
			newCfg, err := config.LoadConfig(configPath)
			if err != nil {
				logger.Error("Failed to reload config", zap.Error(err))
				continue
			}
			errorPagesDocument, _, err := config.InitializeErrorPagesControlPlane(ctx, controlConfigStore, newCfg)
			if err != nil {
				logger.Error("Failed to reload Error Pages control-plane configuration", zap.Error(err))
				continue
			}
			logger.Info("Error Pages control-plane configuration reloaded", zap.Int64("revision", errorPagesDocument.Revision))
			securityTXTDocument, _, err := config.InitializeSecurityTXTControlPlane(ctx, controlConfigStore, newCfg)
			if err != nil {
				logger.Error("Failed to reload Security.txt control-plane configuration", zap.Error(err))
				continue
			}
			logger.Info("Security.txt control-plane configuration reloaded", zap.Int64("revision", securityTXTDocument.Revision))
			captchaDocument, _, captchaInitializationErr := config.InitializeCaptchaControlPlane(ctx, controlConfigStore, newCfg)
			if captchaInitializationErr != nil && !errors.Is(captchaInitializationErr, config.ErrCaptchaLegacySecretMigrationRequired) {
				logger.Error("Failed to reload CAPTCHA control-plane configuration", zap.Error(captchaInitializationErr))
				continue
			}
			if errors.Is(captchaInitializationErr, config.ErrCaptchaLegacySecretMigrationRequired) {
				logger.Warn("CAPTCHA remains YAML-managed until its legacy clear-text credential is replaced with an env: reference")
			} else {
				logger.Info("CAPTCHA control-plane configuration reloaded", zap.Int64("revision", captchaDocument.Revision))
			}
			infrastructureDocument, _, err := config.InitializeInfrastructureControlPlane(ctx, controlConfigStore, newCfg)
			if err != nil {
				logger.Error("Failed to reload infrastructure control-plane configuration", zap.Error(err))
				continue
			}
			logger.Info("Infrastructure control-plane configuration reloaded", zap.Int64("revision", infrastructureDocument.Revision))
			upstreamRuntimeDocument, _, err := config.InitializeUpstreamRuntimeControlPlane(ctx, controlConfigStore, newCfg)
			if err != nil {
				logger.Error("Failed to reload upstream runtime control-plane configuration", zap.Error(err))
				continue
			}
			logger.Info("Upstream runtime control-plane configuration reloaded", zap.Int64("revision", upstreamRuntimeDocument.Revision))
			stickySecretDocument, _, stickySecretInitializationErr := config.InitializeStickySecretControlPlane(ctx, controlConfigStore, newCfg)
			if stickySecretInitializationErr != nil && !errors.Is(stickySecretInitializationErr, config.ErrStickySecretLegacyMigrationRequired) {
				logger.Error("Failed to reload sticky-session secret control-plane configuration", zap.Error(stickySecretInitializationErr))
				continue
			}
			if errors.Is(stickySecretInitializationErr, config.ErrStickySecretLegacyMigrationRequired) {
				logger.Warn("Sticky sessions remain YAML-managed until their legacy clear-text secret is replaced with an env: reference")
			} else {
				logger.Info("Sticky-session secret control-plane configuration reloaded", zap.Int64("revision", stickySecretDocument.Revision))
			}
			upstreamGroupsDocument, _, err := config.InitializeUpstreamGroupsControlPlane(ctx, controlConfigStore, newCfg)
			if err != nil {
				logger.Error("Failed to reload upstream Origin-pool control-plane configuration", zap.Error(err))
				continue
			}
			logger.Info("Upstream Origin-pool control-plane configuration reloaded", zap.Int64("revision", upstreamGroupsDocument.Revision))
			legacyRoutesDocument, _, err := config.InitializeLegacyRoutesControlPlane(ctx, controlConfigStore, newCfg)
			if err != nil {
				logger.Error("Failed to reload legacy host-route control-plane configuration", zap.Error(err))
				continue
			}
			logger.Info("Legacy host-route control-plane configuration reloaded", zap.Int64("revision", legacyRoutesDocument.Revision))
			routeRulesDocument, _, err := config.InitializeRouteRulesControlPlane(ctx, controlConfigStore, newCfg)
			if err != nil {
				logger.Error("Failed to reload route-rule control-plane configuration", zap.Error(err))
				continue
			}
			logger.Info("Route-rule control-plane configuration reloaded", zap.Int64("revision", routeRulesDocument.Revision))
			circuitBreakerDocument, _, err := config.InitializeCircuitBreakerControlPlane(ctx, controlConfigStore, newCfg)
			if err != nil {
				logger.Error("Failed to reload circuit-breaker control-plane configuration", zap.Error(err))
				continue
			}
			logger.Info("Circuit-breaker control-plane configuration reloaded", zap.Int64("revision", circuitBreakerDocument.Revision))
			if err := tlsMgr.Reload(newCfg.Server.TLS); err != nil {
				logger.Error("Failed to reload TLS", zap.Error(err))
			} else {
				logger.Info("TLS configuration reloaded")
			}
			if err := sectionMgr.Init(newCfg.GetSectionsConfigMap()); err != nil {
				logger.Error("Failed to reload sections", zap.Error(err))
			} else {
				logger.Info("Security sections reloaded")
			}
			if err := configureCaptcha(newCfg); err != nil {
				logger.Error("CAPTCHA configuration was not reloaded", zap.Error(err))
			} else {
				logger.Info("CAPTCHA configuration reloaded")
				if captcha.GetManager().PublicConfig().SecretKeyMigrationRequired {
					logger.Warn("CAPTCHA uses a legacy clear-text credential; migrate it to an env: secret reference before the next configuration save")
				}
			}
			if err := upstreamMgr.Reload(newCfg.Upstream); err != nil {
				logger.Error("Failed to reload upstreams", zap.Error(err))
			} else {
				logger.Info("Upstream configuration reloaded")
			}
			if err := breakerTransport.ReloadUpstream(newCfg.Upstream, newCfg.Server.ReadTimeout); err != nil {
				logger.Error("Failed to reload proxy runtime settings", zap.Error(err))
			} else {
				logger.Info("Proxy runtime settings reloaded")
			}
			router.UpdateRules(newCfg.Upstream.Rules)
			logger.Info("Router rules reloaded")
			continue
		}
		logger.Info("Shutting down...", zap.String("signal", sig.String()))
		break
	}

	shutdownCtx, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()
	if err := sectionMgr.Stop(shutdownCtx); err != nil {
		logger.Error("Error stopping sections", zap.Error(err))
	}
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}
	logger.Info("Server exited properly")
}

func configureCaptcha(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is required")
	}
	return configureCaptchaModule(cfg.Modules.Captcha)
}

func configureCaptchaModule(cfg config.CaptchaConfig) error {
	captchaConfig := captcha.Config{
		Enabled:        cfg.Enabled,
		ProviderName:   captcha.ProviderType(cfg.ProviderName),
		SiteKey:        cfg.SiteKey,
		SecretKey:      cfg.SecretKey,
		SecretKeyRef:   cfg.SecretKeyRef,
		ScoreThreshold: cfg.ScoreThreshold,
	}
	resolved, err := captcha.ResolveConfig(captchaConfig)
	if err != nil {
		return err
	}
	captcha.GetManager().UpdateConfig(resolved)
	return nil
}

func parseDuration(d string) time.Duration {
	dur, err := time.ParseDuration(d)
	if err != nil {
		return 10 * time.Second
	}
	return dur
}
