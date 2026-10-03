package licensing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/divinelabio/aegis/internal/edition"
	"github.com/golang-jwt/jwt/v5"
)

func testManager(t *testing.T, tier edition.BuildTier) (*RuntimeManager, ed25519.PrivateKey, *time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	m, err := NewManager(Config{StateDir: t.TempDir(), Version: "1.0.2", CompiledTier: tier, TrustedKeys: map[string]ed25519.PublicKey{"test": pub}, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return m, priv, &now
}

func testEntitlement(t *testing.T, m *RuntimeManager, priv ed25519.PrivateKey, status Status) string {
	t.Helper()
	now := m.config.Clock()
	claims := entitlementClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: m.config.Issuer, Subject: "test-license", Audience: jwt.ClaimStrings{m.config.Audience}, ID: "test-token", IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}, Type: entitlementTokenType, LicenseID: "test-license", ActivationID: "test-activation", InstallationPublicKeyHash: publicKeyHash(m.identity.PublicKey), Tier: edition.ProfessionalTier,
		Features: edition.FeaturesForTier(edition.ProfessionalTier).Sorted(), OfflineUntil: jwt.NewNumericDate(now.Add(2 * time.Hour)), LicenseStatus: status}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"], token.Header["kid"] = entitlementTokenType, "test"
	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestUpgradeRequiresCompatibleArtifact(t *testing.T) {
	m, priv, _ := testManager(t, edition.CommunityTier)
	for _, response := range []apiResponse{
		{TargetTier: "professional"},
		{TargetTier: "professional", TargetVersion: "1.0.1", ArtifactManifest: "signed-manifest"},
		{TargetTier: "professional", TargetVersion: "garbage", ArtifactManifest: "signed-manifest"},
	} {
		upgrade, err := m.upgradeFromResponse(response)
		if err != nil || !upgrade.Required || upgrade.Available || upgrade.State == "ready" {
			t.Fatalf("unavailable release marked ready: %+v, %v", upgrade, err)
		}
	}
	upgrade, err := m.upgradeFromResponse(apiResponse{TargetTier: "professional", TargetVersion: "1.0.2", ArtifactManifest: testArtifact(t, m, priv, "professional", "1.0.2")})
	if err != nil || !upgrade.Required || !upgrade.Available {
		t.Fatalf("same-version edition upgrade rejected: %+v, %v", upgrade, err)
	}
}

func TestRestartRetainsReleaseAndIdentity(t *testing.T) {
	m, priv, now := testManager(t, edition.CommunityTier)
	response := apiResponse{ActivationID: "test-activation", Entitlement: testEntitlement(t, m, priv, StatusActive), ServerTime: *now, TargetTier: "professional", TargetVersion: "1.0.2", ArtifactManifest: testArtifact(t, m, priv, "professional", "1.0.2"), ArtifactCredential: "short-lived-secret"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(response) }))
	defer server.Close()
	m.client, _ = newAPIClient(server.URL)
	if _, err := m.Activate(context.Background(), "test-key"); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(m.config)
	if err != nil {
		t.Fatal(err)
	}
	upgrade := restarted.Snapshot().Upgrade
	if !upgrade.Available || upgrade.Manifest != response.ArtifactManifest || upgrade.TargetVersion != response.TargetVersion || upgrade.Credential != "" {
		t.Fatalf("bad recovered release: %+v", upgrade)
	}
	if m.identity.InstallationID != restarted.identity.InstallationID || m.identity.RuntimeID != restarted.identity.RuntimeID {
		t.Fatal("identity changed on restart")
	}
}

func testArtifact(t *testing.T, m *RuntimeManager, priv ed25519.PrivateKey, tier, version string) string {
	t.Helper()
	return testArtifactClaims(t, m, priv, tier, version, nil)
}

func testArtifactClaims(t *testing.T, m *RuntimeManager, priv ed25519.PrivateKey, tier, version string, overrides jwt.MapClaims) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": m.config.Issuer, "aud": "aegis-updater", "exp": m.config.Clock().Add(time.Hour).Unix(), "typ": "aegis-artifact-manifest+jwt", "edition": tier, "version": version, "os": platformName(), "architecture": architectureName(), "format": m.config.ArtifactFormat, "digest": "sha256:" + strings.Repeat("a", 64), "url": "https://get.divinelab.io/release.tar.gz"}
	for key, value := range overrides {
		claims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"], token.Header["kid"] = "aegis-artifact-manifest+jwt", "test"
	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignedArtifactUsesNativePlatformFormat(t *testing.T) {
	m, priv, _ := testManager(t, edition.CommunityTier)
	m.config.ArtifactFormat = "zip"
	if platformName() == "windows" {
		m.config.ArtifactFormat = "tar.gz"
	}
	upgrade, err := m.upgradeFromResponse(apiResponse{TargetTier: "professional", TargetVersion: "1.0.2", ArtifactManifest: testArtifact(t, m, priv, "professional", "1.0.2")})
	if err != nil || upgrade.Available || !strings.Contains(upgrade.Reason, "artifact location") {
		t.Fatalf("wrong native format marked ready: %+v, %v", upgrade, err)
	}
}

func TestSignedOCIArtifactRequiresExactDigestPin(t *testing.T) {
	if platformName() != "linux" {
		t.Skip("OCI installation is Linux-only")
	}
	m, priv, _ := testManager(t, edition.CommunityTier)
	m.config.ArtifactFormat = "oci"
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, image := range []string{"registry.test/aegis@" + digest, "registry.test/aegis@sha256:prefix" + digest, "registry.test/aegis@other@" + digest, "@" + digest} {
		manifest := testArtifactClaims(t, m, priv, "professional", "1.0.2", jwt.MapClaims{"url": "", "image": image})
		upgrade, err := m.upgradeFromResponse(apiResponse{TargetTier: "professional", TargetVersion: "1.0.2", ArtifactManifest: manifest})
		if err != nil || upgrade.Available != (image == "registry.test/aegis@"+digest) {
			t.Fatalf("incorrect OCI pin readiness for %s: %+v, %v", image, upgrade, err)
		}
	}
}

func TestUpgradePlanAuthenticatesReleaseIdentity(t *testing.T) {
	m, priv, _ := testManager(t, edition.CommunityTier)
	for _, manifest := range []string{"malformed", testArtifact(t, m, priv, "enterprise", "1.0.2"), testArtifact(t, m, priv, "professional", "1.0.3")} {
		upgrade, err := m.upgradeFromResponse(apiResponse{TargetTier: "professional", TargetVersion: "1.0.2", ArtifactManifest: manifest})
		if err != nil || !upgrade.Required || upgrade.Available || upgrade.Reason == "" {
			t.Fatalf("untrusted or mismatched manifest advertised ready: %+v, %v", upgrade, err)
		}
	}
	m.config.Version = "dev"
	upgrade, _ := m.upgradeFromResponse(apiResponse{TargetTier: "professional", TargetVersion: "1.0.2", ArtifactManifest: testArtifact(t, m, priv, "professional", "1.0.2")})
	if upgrade.Available {
		t.Fatal("unknown running version permitted an upgrade")
	}
}

func TestNewSoftwareVersionWithoutArtifactRemainsPending(t *testing.T) {
	m, _, _ := testManager(t, edition.ProfessionalTier)
	upgrade, err := m.upgradeFromResponse(apiResponse{TargetTier: "professional", TargetVersion: "1.0.3"})
	if err != nil || !upgrade.Required || upgrade.Available || upgrade.Reason == "" {
		t.Fatalf("missing release hidden as up to date: %+v, %v", upgrade, err)
	}
}

func TestPaidCatalogUnavailableDoesNotInventAnUpgrade(t *testing.T) {
	for _, status := range []string{"resolver_unavailable", "unavailable", "not_entitled"} {
		t.Run(status, func(t *testing.T) {
			m, _, _ := testManager(t, edition.ProfessionalTier)
			upgrade, err := m.upgradeFromResponse(apiResponse{TargetTier: "professional", ArtifactStatus: status})
			if err != nil || upgrade.Required || upgrade.Available || upgrade.TargetVersion != "" || upgrade.State != "unavailable" || upgrade.Reason == "" {
				t.Fatalf("unavailable catalog disguised as up to date or fabricated an upgrade: %+v, %v", upgrade, err)
			}
		})
	}
	m, priv, _ := testManager(t, edition.ProfessionalTier)
	upgrade, err := m.upgradeFromResponse(apiResponse{TargetTier: "professional", TargetVersion: "1.0.2", ArtifactStatus: "available", ArtifactManifest: testArtifact(t, m, priv, "professional", "1.0.2")})
	if err != nil || upgrade.Required || upgrade.Available || upgrade.State == "unavailable" || upgrade.Reason != "" {
		t.Fatalf("successful equal-version catalog did not remain up to date: %+v, %v", upgrade, err)
	}
}

func TestCatalogOutageSurvivesActivationAndRestart(t *testing.T) {
	m, priv, now := testManager(t, edition.ProfessionalTier)
	response := apiResponse{ActivationID: "test-activation", Entitlement: testEntitlement(t, m, priv, StatusActive), ServerTime: *now, TargetTier: "professional", ArtifactStatus: "resolver_unavailable"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(response) }))
	defer server.Close()
	m.client, _ = newAPIClient(server.URL)
	result, err := m.Activate(context.Background(), "test-key")
	if err != nil || result.Snapshot.Status != StatusActive || result.Upgrade.Required || result.Upgrade.Available || result.Upgrade.State != "unavailable" {
		t.Fatalf("catalog outage invalidated licence or lost availability state: %+v, %v", result, err)
	}
	restarted, err := NewManager(m.config)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Snapshot().Upgrade.State != "unavailable" || restarted.Snapshot().Upgrade.Reason == "" {
		t.Fatal("catalog outage became up to date after restart")
	}
}

func TestUnavailableTierCatalogExplainsUpdaterCompatibility(t *testing.T) {
	m, _, _ := testManager(t, edition.CommunityTier)
	upgrade, err := m.upgradeFromResponse(apiResponse{TargetTier: "professional", ArtifactStatus: "unavailable"})
	if err != nil || !upgrade.Required || upgrade.Available || !strings.Contains(upgrade.Reason, "updater version") {
		t.Fatalf("tier compatibility failure lacks recovery guidance: %+v, %v", upgrade, err)
	}
}

func TestUpdaterMinimumDiagnosticPreservesTargetAndBlocksInstall(t *testing.T) {
	m, priv, _ := testManager(t, edition.ProfessionalTier)
	response := apiResponse{TargetTier: "professional", TargetVersion: "1.0.3", ArtifactStatus: "updater_upgrade_required", ArtifactMinimumUpdaterVersion: "1.0.4", ArtifactManifest: testArtifact(t, m, priv, "professional", "1.0.3"), ArtifactCredential: "must-not-be-used"}
	upgrade, err := m.upgradeFromResponse(response)
	if err != nil || !upgrade.Required || upgrade.Available || upgrade.State != "unavailable" || upgrade.TargetVersion != "1.0.3" || upgrade.MinimumUpdaterVersion != "1.0.4" || upgrade.Manifest != "" || upgrade.Credential != "" || !strings.Contains(upgrade.Reason, "1.0.4 or later") || !strings.Contains(upgrade.Reason, "standalone updater") {
		t.Fatalf("updater minimum diagnostic lost target/guidance or permitted install: %+v, %v", upgrade, err)
	}
	response.ArtifactMinimumUpdaterVersion = "invalid-minimum"
	upgrade, err = m.upgradeFromResponse(response)
	if err != nil || upgrade.Available || upgrade.MinimumUpdaterVersion != "" || strings.Contains(upgrade.Reason, "invalid-minimum") {
		t.Fatalf("invalid minimum accepted as a release version: %+v, %v", upgrade, err)
	}
}

func TestUpdaterMinimumDiagnosticSurvivesRestart(t *testing.T) {
	m, priv, now := testManager(t, edition.ProfessionalTier)
	response := apiResponse{ActivationID: "test-activation", Entitlement: testEntitlement(t, m, priv, StatusActive), ServerTime: *now, TargetTier: "professional", TargetVersion: "1.0.3", ArtifactStatus: "updater_upgrade_required", ArtifactMinimumUpdaterVersion: "1.0.4"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(response) }))
	defer server.Close()
	m.client, _ = newAPIClient(server.URL)
	if _, err := m.Activate(context.Background(), "test-key"); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(m.config)
	if err != nil {
		t.Fatal(err)
	}
	upgrade := restarted.Snapshot().Upgrade
	if !upgrade.Required || upgrade.Available || upgrade.TargetVersion != "1.0.3" || upgrade.MinimumUpdaterVersion != "1.0.4" || !strings.Contains(upgrade.Reason, "1.0.4 or later") {
		t.Fatalf("updater compatibility requirement lost after restart: %+v", upgrade)
	}
}

func TestArtifactExpiryAndEntitlementEditionMismatch(t *testing.T) {
	m, priv, now := testManager(t, edition.CommunityTier)
	upgrade, err := m.upgradeFromResponse(apiResponse{TargetTier: "professional", TargetVersion: "1.0.2", ArtifactManifest: testArtifact(t, m, priv, "professional", "1.0.2")})
	if err != nil || !upgrade.Available {
		t.Fatal("valid manifest rejected", err)
	}
	if err := m.applyEntitlement(testEntitlement(t, m, priv, StatusActive), *now, upgrade); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Hour)
	if m.Snapshot().Upgrade.Available {
		t.Fatal("expired artifact remained ready")
	}
	*now = now.Add(-time.Hour)
	upgrade.TargetTier = edition.EnterpriseTier
	snapshot, err := m.entitlementSnapshot(testEntitlement(t, m, priv, StatusActive), *now, time.Time{}, *now, upgrade, "test-activation")
	if err != nil || snapshot.Upgrade.Available || snapshot.Upgrade.Manifest != "" || snapshot.Upgrade.TargetTier != edition.ProfessionalTier {
		t.Fatalf("paid plan did not constrain artifact: %+v, %v", snapshot, err)
	}
}

func TestNewerCompiledTrustBundleDoesNotBlockRestart(t *testing.T) {
	m, priv, now := testManager(t, edition.CommunityTier)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodeBundle := func(version int) string {
		payload, err := json.Marshal(KeySetPayload{Version: version, Keys: map[string]CertifiedKey{"test": {Algorithm: "Ed25519", Purpose: KeyPurposeLease, PublicKey: base64.RawStdEncoding.EncodeToString(m.config.TrustedKeys["test"]), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}}})
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := json.Marshal(SignedKeySet{Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(rootPrivate, payload))})
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawStdEncoding.EncodeToString(envelope)
	}
	state := persistedState{ActivationID: "test-activation", Entitlement: testEntitlement(t, m, priv, StatusActive), LastServerTime: *now, SignedKeySet: encodeBundle(1)}
	if err := savePersistedState(m.config.StateDir, state); err != nil {
		t.Fatal(err)
	}
	config := m.config
	config.RootPublicKey = base64.RawStdEncoding.EncodeToString(rootPublic)
	config.SignedKeySet = encodeBundle(2)
	restarted, err := NewManager(config)
	if err != nil || restarted.Snapshot().Status != StatusUpgradeRequired {
		t.Fatalf("new compiled trust blocked restored licence: %v", err)
	}
	if restarted.config.SignedKeySet != config.SignedKeySet {
		t.Fatal("restored bundle rolled trust backwards")
	}
}

func TestActivationWithoutReleaseRecoversOnRefresh(t *testing.T) {
	m, priv, now := testManager(t, edition.CommunityTier)
	response := apiResponse{ActivationID: "test-activation", Entitlement: testEntitlement(t, m, priv, StatusActive), ServerTime: *now, TargetTier: "invalid-release-tier"}
	var responseMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseMu.Lock()
		defer responseMu.Unlock()
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	m.client, _ = newAPIClient(server.URL)
	result, err := m.Activate(context.Background(), "test-key")
	if err != nil || result.Snapshot.ActivationID == "" || !result.Upgrade.Required || result.Upgrade.Available {
		t.Fatalf("missing/bad release rejected licence or advertised ready: %+v, %v", result, err)
	}
	responseMu.Lock()
	response.TargetTier, response.TargetVersion = "professional", "1.0.2"
	response.ArtifactManifest = testArtifact(t, m, priv, "professional", "1.0.2")
	responseMu.Unlock()
	if err := m.Refresh(context.Background()); err != nil || !m.Snapshot().Upgrade.Available {
		t.Fatal("published release did not recover on refresh", err)
	}
}

func TestInvalidStoredEntitlementKeepsActivationRecoverable(t *testing.T) {
	m, _, _ := testManager(t, edition.CommunityTier)
	if err := savePersistedState(m.config.StateDir, persistedState{ActivationID: "recoverable-activation", Entitlement: "invalid-old-token"}); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(m.config)
	if err != nil || restarted.Snapshot().Status != StatusInvalid || restarted.Snapshot().ActivationID != "recoverable-activation" {
		t.Fatalf("stored activation lost its refresh/deactivation path: %v", err)
	}
}

func TestPaidFeaturesExpireWithoutNetwork(t *testing.T) {
	m, priv, now := testManager(t, edition.ProfessionalTier)
	if err := m.applyEntitlement(testEntitlement(t, m, priv, StatusActive), *now, UpgradeInfo{}); err != nil {
		t.Fatal(err)
	}
	cached := m.Snapshot()
	*now = now.Add(time.Hour)
	if m.Snapshot().Status != StatusGrace || !m.Has(edition.FeatureBotProtection) {
		t.Fatal("valid offline grace was lost")
	}
	*now = now.Add(time.Hour)
	if m.Has(edition.FeatureBotProtection) || cached.Has(edition.FeatureBotProtection) || m.Snapshot().Status != StatusExpired {
		t.Fatal("paid feature remained active at offline deadline")
	}
}

func TestFailedActivationPreservesEntitlement(t *testing.T) {
	m, priv, now := testManager(t, edition.ProfessionalTier)
	if err := m.applyEntitlement(testEntitlement(t, m, priv, StatusActive), *now, UpgradeInfo{}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_license_key"})
	}))
	defer server.Close()
	m.client, _ = newAPIClient(server.URL)
	if _, err := m.Activate(context.Background(), "bad-key"); err == nil {
		t.Fatal("bad key was accepted")
	}
	if m.Snapshot().Status != StatusActive || !m.Has(edition.FeatureBotProtection) {
		t.Fatal("failed activation changed a working entitlement")
	}
}

func TestDeniedEntitlementCannotUpgrade(t *testing.T) {
	for _, status := range []Status{StatusRevoked, StatusSuspended, StatusExpired} {
		t.Run(string(status), func(t *testing.T) {
			m, priv, now := testManager(t, edition.CommunityTier)
			snapshot, err := m.entitlementSnapshot(testEntitlement(t, m, priv, status), *now, time.Time{}, *now, UpgradeInfo{Required: true, Available: true, State: "ready", Manifest: "signed-manifest"}, "test-activation")
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Upgrade.Required || snapshot.Upgrade.Available {
				t.Fatal("denied license retained upgrade")
			}
		})
	}
}

func TestConcurrentIdentityCreation(t *testing.T) {
	dir := t.TempDir()
	var group sync.WaitGroup
	identities := make(chan installationIdentity, 12)
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			identity, err := loadOrCreateIdentity(dir)
			if err != nil {
				t.Error(err)
				return
			}
			identities <- identity
		}()
	}
	group.Wait()
	close(identities)
	var installationID string
	for identity := range identities {
		if installationID == "" {
			installationID = identity.InstallationID
		}
		if installationID != identity.InstallationID {
			t.Fatal("concurrent managers created distinct identities")
		}
	}
}
