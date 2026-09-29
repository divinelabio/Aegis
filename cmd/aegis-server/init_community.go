//go:build !professional && !enterprise

package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"time"

	"github.com/divinelab-io/aegis/internal/app"
	"github.com/divinelab-io/aegis/internal/core/admin/handlers"
	"github.com/divinelab-io/aegis/internal/edition"
	"github.com/divinelab-io/aegis/internal/licensing"
	"go.uber.org/zap"
)

var (
	LicenseAPIURL        = "https://license.divinelab.io"
	LicenseIssuer        = "https://license.divinelab.io"
	LicenseAudience      = "aegis-runtime"
	LicenseRootPublicKey = ""
	LicenseSignedKeySet  = ""
)

var communityLicenseManager licensing.Manager

func init() {
	previousHook := app.DepsHook
	app.DepsHook = func(deps *app.BundleDependencies) {
		if previousHook != nil {
			previousHook(deps)
		}
		deps.License = communityLicenseManager
	}

	handlers.SetLicenseTierFunc(func() string {
		if communityLicenseManager == nil {
			return string(edition.CommunityTier)
		}
		return string(communityLicenseManager.Snapshot().EffectiveTier)
	})

	CommercialInit = initializeCommunityLicensing
}

func initializeCommunityLicensing(ctxRaw, cfgRaw, _, loggerRaw interface{}, version string) error {
	logger, ok := loggerRaw.(*zap.Logger)
	if !ok {
		return nil
	}
	compiledTier := edition.CommunityTier
	compiledFeatures := edition.FeaturesForTier(compiledTier)

	apiURL := LicenseAPIURL
	if envURL := os.Getenv("AEGIS_LICENSE_API_URL"); envURL != "" {
		apiURL = envURL
	}
	stateDir := "./data/license"
	if cfg, ok := cfgRaw.(interface{ GetLicenseConfig() (string, string) }); ok {
		configuredURL, configuredStateDir := cfg.GetLicenseConfig()
		if configuredURL != "" {
			apiURL = configuredURL
		}
		if configuredStateDir != "" {
			stateDir = configuredStateDir
		}
	}

	rootPubKey := LicenseRootPublicKey
	if rootPubKey == "" {
		rootPubKey = os.Getenv("AEGIS_LICENSE_ROOT_PUBLIC_KEY")
	}
	signedKeySet := LicenseSignedKeySet
	if signedKeySet == "" {
		signedKeySet = os.Getenv("AEGIS_LICENSE_SIGNED_KEY_SET")
	}

	issuer := LicenseIssuer
	if envIssuer := os.Getenv("AEGIS_LICENSE_ISSUER"); envIssuer != "" {
		issuer = envIssuer
	}

	var trustedKeys map[string]ed25519.PublicKey
	if rootPubKey != "" && signedKeySet != "" {
		var err error
		trustedKeys, err = licensing.CertifiedTrustedKeys(
			rootPubKey, signedKeySet, licensing.KeyPurposeLease, time.Now().UTC(),
		)
		if err != nil {
			logger.Warn("Failed to load trusted licence keys", zap.Error(err))
		}
	}

	realManager, err := licensing.NewManager(licensing.Config{
		StateDir:         stateDir,
		APIURL:           apiURL,
		Issuer:           issuer,
		Audience:         LicenseAudience,
		Version:          version,
		CompiledTier:     compiledTier,
		CompiledFeatures: compiledFeatures,
		TrustedKeys:      trustedKeys,
	})
	if err != nil {
		logger.Error("Failed to initialize licence manager", zap.Error(err))
		return err
	}

	if realCtx, ok := ctxRaw.(context.Context); ok {
		realManager.Start(realCtx)
	}
	communityLicenseManager = realManager
	handlers.SetLicenseManager(communityLicenseManager)

	logger.Info("Licensing manager started",
		zap.String("api_url", apiURL),
		zap.String("issuer", issuer),
		zap.String("effective_tier", string(realManager.Snapshot().EffectiveTier)),
	)
	return nil
}
