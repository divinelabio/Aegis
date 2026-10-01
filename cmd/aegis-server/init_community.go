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
	LicenseRootPublicKey = "QaL+N7zeR2BPphhqoUTBB3ddp7y3KW6u33LHWBSQ8BU"
	LicenseSignedKeySet  = "eyJwYXlsb2FkIjoiZXlKMlpYSnphVzl1SWpveExDSnJaWGx6SWpwN0lteGxZWE5sTFRJd01qWWlPbnNpWVd4bmIzSnBkR2h0SWpvaVJXUXlOVFV4T1NJc0luQjFjbkJ2YzJVaU9pSnNaV0Z6WlNJc0luQjFZbXhwWTE5clpYa2lPaUlyVVdaa2NucEdRM2QxZGpad2VHOVlMeTl3UVZkTVJFOUZlbmR2YWswdmJrODVaa1ZCWm5GTUsyTnpJaXdpYm05MFgySmxabTl5WlNJNklqSXdNall0TURrdE1EUlVNVEk2TWpZNk5USXVOelkyTURZeU5sb2lMQ0p1YjNSZllXWjBaWElpT2lJeU1ETTJMVEE1TFRBMFZERXpPakkyT2pVeUxqYzJOakEyTWpaYUluMTlmUSIsInNpZ25hdHVyZSI6Ikg0d1g4QldJTEhFV3FlUDM4dE9nakp3YjlLd24zZ3lsbl83SkxxOTF2QzhybENmdlh2UzBjalFxNkxiTkw3bFVXOXZxNDZnU0xxWGhKZTAtRm8tTkRnIn0"
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
