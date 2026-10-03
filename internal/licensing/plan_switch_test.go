package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/divinelabio/aegis/internal/edition"
	"github.com/golang-jwt/jwt/v5"
)

type switchAuthority struct {
	mu                 sync.Mutex
	responses          map[string]apiResponse
	seats              map[string]bool
	deleteFailures     map[string]int
	deleteCalls        map[string]int
	activationFailures map[string]int
	ambiguousDelete    bool
	manager            *RuntimeManager
	t                  *testing.T
}

func newSwitchAuthority(t *testing.T) (*RuntimeManager, *switchAuthority) {
	t.Helper()
	m, signingKey, now := testManager(t, edition.EnterpriseTier)
	a := &switchAuthority{responses: make(map[string]apiResponse), seats: make(map[string]bool), deleteFailures: make(map[string]int), deleteCalls: make(map[string]int), activationFailures: make(map[string]int), manager: m, t: t}
	for _, plan := range []struct {
		key, id string
		tier    edition.BuildTier
	}{
		{"professional-key", "professional-activation", edition.ProfessionalTier},
		{"enterprise-key", "enterprise-activation", edition.EnterpriseTier},
	} {
		a.responses[plan.key] = apiResponse{ActivationID: plan.id, Entitlement: switchEntitlement(t, m, signingKey, plan.id, plan.tier), ServerTime: *now}
	}
	server := httptest.NewServer(http.HandlerFunc(a.serveHTTP))
	t.Cleanup(server.Close)
	m.config.APIURL = server.URL
	m.client, _ = newAPIClient(server.URL)
	if _, err := m.Activate(context.Background(), "professional-key"); err != nil {
		t.Fatal(err)
	}
	return m, a
}

func switchEntitlement(t *testing.T, m *RuntimeManager, key ed25519.PrivateKey, id string, tier edition.BuildTier) string {
	t.Helper()
	claims := &entitlementClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(testEntitlement(t, m, key, StatusActive), claims)
	if err != nil {
		t.Fatal(err)
	}
	claims.ActivationID, claims.Tier, claims.Features = id, tier, edition.FeaturesForTier(tier).Sorted()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"], token.Header["kid"] = entitlementTokenType, "test"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (a *switchAuthority) serveHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.Method == http.MethodDelete {
		id := strings.TrimPrefix(r.URL.Path, "/v1/activations/")
		a.deleteCalls[id]++
		// The old seat can only be released once the replacement is durable.
		if id == "professional-activation" && a.manager.Snapshot().ActivationID == "enterprise-activation" {
			state, err := loadPersistedState(a.manager.config.StateDir)
			if err != nil || state.ActivationID != "enterprise-activation" || state.Entitlement == "" {
				a.t.Error("old seat released before replacement entitlement was durable")
			}
		}
		if a.deleteFailures[id] > 0 {
			a.deleteFailures[id]--
			if a.ambiguousDelete {
				a.seats[id] = false
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"authority_unavailable"}`))
			return
		}
		a.seats[id] = false
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var response apiResponse
	if strings.HasSuffix(r.URL.Path, "/leases") {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/activations/"), "/leases")
		for _, candidate := range a.responses {
			if candidate.ActivationID == id {
				response = candidate
			}
		}
	} else {
		var request activationRequest
		_ = json.NewDecoder(r.Body).Decode(&request)
		response = a.responses[request.LicenseKey]
		if response.ActivationID == "" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"invalid_license_key"}`))
			return
		}
		a.seats[response.ActivationID] = true
		if a.activationFailures[request.LicenseKey] > 0 {
			a.activationFailures[request.LicenseKey]--
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"signing_unavailable"}`))
			return
		}
	}
	_ = json.NewEncoder(w).Encode(response)
}

func assertSwitchState(t *testing.T, m *RuntimeManager, id string, tier edition.BuildTier, pending int) {
	t.Helper()
	snapshot := m.Snapshot()
	state, err := loadPersistedState(m.config.StateDir)
	if err != nil || snapshot.ActivationID != id || snapshot.LicensedTier != tier || snapshot.Status != StatusActive || state.ActivationID != id || len(state.PendingDeactivations) != pending {
		t.Fatalf("incorrect switch state: snapshot=%+v state=%+v error=%v", snapshot, state, err)
	}
}

func TestPlanSwitchReleasesPreviousSeatAfterCommit(t *testing.T) {
	m, a := newSwitchAuthority(t)
	if _, err := m.Activate(context.Background(), "enterprise-key"); err != nil {
		t.Fatal(err)
	}
	assertSwitchState(t, m, "enterprise-activation", edition.EnterpriseTier, 0)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seats["professional-activation"] || !a.seats["enterprise-activation"] || a.deleteCalls["professional-activation"] != 1 {
		t.Fatal("previous seat leaked or new seat released")
	}
}

func TestPlanSwitchPendingReleaseSurvivesRestart(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(map[bool]string{false: "delete-failed", true: "delete-succeeded-response-lost"}[ambiguous], func(t *testing.T) {
			m, a := newSwitchAuthority(t)
			a.mu.Lock()
			a.deleteFailures["professional-activation"], a.ambiguousDelete = 1, ambiguous
			a.mu.Unlock()
			if _, err := m.Activate(context.Background(), "enterprise-key"); err != nil {
				t.Fatal(err)
			}
			assertSwitchState(t, m, "enterprise-activation", edition.EnterpriseTier, 1)
			restarted, err := NewManager(m.config)
			if err != nil {
				t.Fatal(err)
			}
			assertSwitchState(t, restarted, "enterprise-activation", edition.EnterpriseTier, 1)
			if err := restarted.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertSwitchState(t, restarted, "enterprise-activation", edition.EnterpriseTier, 0)
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.seats["professional-activation"] || !a.seats["enterprise-activation"] || a.deleteCalls["enterprise-activation"] != 0 {
				t.Fatal("cleanup retry released the wrong seat")
			}
		})
	}
}

func TestRejectedReplacementCleanupSurvivesRestart(t *testing.T) {
	m, a := newSwitchAuthority(t)
	a.mu.Lock()
	response := a.responses["enterprise-key"]
	response.Entitlement = "invalid-token"
	a.responses["enterprise-key"] = response
	a.deleteFailures["enterprise-activation"] = 1
	a.mu.Unlock()
	if _, err := m.Activate(context.Background(), "enterprise-key"); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	assertSwitchState(t, m, "professional-activation", edition.ProfessionalTier, 1)
	restarted, err := NewManager(m.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSwitchState(t, restarted, "professional-activation", edition.ProfessionalTier, 0)
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.seats["professional-activation"] || a.seats["enterprise-activation"] || a.deleteCalls["professional-activation"] != 0 {
		t.Fatal("failed replacement disturbed current seat")
	}
}

func TestSameKeyRetryNeverReleasesCurrentSeat(t *testing.T) {
	m, a := newSwitchAuthority(t)
	if _, err := m.Activate(context.Background(), "professional-key"); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	response := a.responses["professional-key"]
	response.Entitlement = "invalid-token"
	a.responses["professional-key"] = response
	a.mu.Unlock()
	if _, err := m.Activate(context.Background(), "professional-key"); err == nil {
		t.Fatal("invalid response accepted")
	}
	assertSwitchState(t, m, "professional-activation", edition.ProfessionalTier, 0)
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.seats["professional-activation"] || a.deleteCalls["professional-activation"] != 0 {
		t.Fatal("same-key retry released active seat")
	}
}

func TestAmbiguousReplacementActivationRecoversOnSameKeyRetry(t *testing.T) {
	m, a := newSwitchAuthority(t)
	a.mu.Lock()
	a.activationFailures["enterprise-key"] = 1
	a.mu.Unlock()
	if _, err := m.Activate(context.Background(), "enterprise-key"); err == nil {
		t.Fatal("failed activation response accepted")
	}
	assertSwitchState(t, m, "professional-activation", edition.ProfessionalTier, 0)
	a.mu.Lock()
	if !a.seats["professional-activation"] || a.deleteCalls["professional-activation"] != 0 {
		t.Fatal("old seat released before replacement response validated")
	}
	a.mu.Unlock()
	restarted, err := NewManager(m.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Activate(context.Background(), "enterprise-key"); err != nil {
		t.Fatal(err)
	}
	assertSwitchState(t, restarted, "enterprise-activation", edition.EnterpriseTier, 0)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seats["professional-activation"] || !a.seats["enterprise-activation"] {
		t.Fatal("idempotent activation retry leaked a seat")
	}
}

func TestDeactivationRetainsOlderPendingSeatCleanup(t *testing.T) {
	m, a := newSwitchAuthority(t)
	a.mu.Lock()
	a.deleteFailures["professional-activation"] = 2
	a.mu.Unlock()
	if _, err := m.Activate(context.Background(), "enterprise-key"); err != nil {
		t.Fatal(err)
	}
	if err := m.Deactivate(context.Background()); err == nil {
		t.Fatal("pending old release failure hidden")
	}
	state, err := loadPersistedState(m.config.StateDir)
	if err != nil || state.ActivationID != "" || len(state.PendingDeactivations) != 1 || m.Snapshot().Status != StatusCommunity {
		t.Fatalf("deactivation lost pending cleanup: %+v %v", state, err)
	}
	restarted, err := NewManager(m.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err = loadPersistedState(m.config.StateDir)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil || len(state.PendingDeactivations) != 0 || a.seats["professional-activation"] || a.seats["enterprise-activation"] {
		t.Fatal("older pending seat did not recover after full deactivation")
	}
}

func TestPlanReturnOffersMatchingEditionWithoutVersionDowngrade(t *testing.T) {
	m, signingKey, _ := testManager(t, edition.EnterpriseTier)
	for _, test := range []struct {
		name, version, artifactTier string
		available                   bool
	}{
		{"same-version-professional", "1.0.2", "professional", true},
		{"older-professional-release", "1.0.1", "professional", false},
		{"wrong-enterprise-artifact", "1.0.2", "enterprise", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			upgrade, err := m.upgradeFromResponse(apiResponse{TargetTier: "professional", TargetVersion: test.version, ArtifactStatus: "available", ArtifactManifest: testArtifact(t, m, signingKey, test.artifactTier, test.version)})
			if err != nil || !upgrade.Required || upgrade.Available != test.available || upgrade.TargetTier != edition.ProfessionalTier {
				t.Fatalf("wrong plan return readiness: %+v %v", upgrade, err)
			}
		})
	}
}

func TestPlanSwitchBackClampsFeaturesBeforeBinaryReplacement(t *testing.T) {
	m, a := newSwitchAuthority(t)
	if _, err := m.Activate(context.Background(), "enterprise-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Activate(context.Background(), "professional-key"); err != nil {
		t.Fatal(err)
	}
	assertSwitchState(t, m, "professional-activation", edition.ProfessionalTier, 0)
	if m.Snapshot().BuildTier != edition.EnterpriseTier || m.Snapshot().EffectiveTier != edition.ProfessionalTier {
		t.Fatal("plan return did not retain a usable professional entitlement on the enterprise binary")
	}
	professional := edition.FeaturesForTier(edition.ProfessionalTier)
	for feature := range edition.FeaturesForTier(edition.EnterpriseTier) {
		if !professional.Has(feature) && m.Has(feature) {
			t.Fatalf("enterprise capability remained enabled after plan return: %s", feature)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seats["enterprise-activation"] || !a.seats["professional-activation"] || a.deleteCalls["enterprise-activation"] != 1 {
		t.Fatal("return to professional leaked the enterprise seat")
	}
}

func TestPersistedEntitlementSurvivesCompiledEditionAndVersionChange(t *testing.T) {
	for _, paidTier := range []edition.BuildTier{edition.ProfessionalTier, edition.EnterpriseTier} {
		t.Run(string(paidTier), func(t *testing.T) {
			m, signingKey, now := testManager(t, edition.CommunityTier)
			response := apiResponse{
				ActivationID: "upgrade-activation", Entitlement: switchEntitlement(t, m, signingKey, "upgrade-activation", paidTier),
				ServerTime: *now, TargetTier: string(paidTier), TargetVersion: "1.0.3", ArtifactStatus: "available",
				ArtifactManifest: testArtifact(t, m, signingKey, string(paidTier), "1.0.3"),
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			m.config.APIURL = server.URL
			m.client, _ = newAPIClient(server.URL)
			if _, err := m.Activate(context.Background(), "paid-key"); err != nil {
				t.Fatal(err)
			}
			if m.Snapshot().Status != StatusUpgradeRequired || !m.Snapshot().Upgrade.Available {
				t.Fatal("community activation did not produce a ready paid release")
			}
			upgradedConfig := m.config
			upgradedConfig.Version, upgradedConfig.CompiledTier, upgradedConfig.CompiledFeatures = "1.0.3", paidTier, edition.FeaturesForTier(paidTier)
			upgraded, err := NewManager(upgradedConfig)
			if err != nil {
				t.Fatal(err)
			}
			snapshot := upgraded.Snapshot()
			if snapshot.Status != StatusActive || snapshot.BuildTier != paidTier || snapshot.LicensedTier != paidTier || snapshot.EffectiveTier != paidTier || snapshot.ActivationID != response.ActivationID {
				t.Fatalf("upgraded binary failed to restore its valid paid entitlement before network refresh: %+v", snapshot)
			}
			if m.identity.InstallationID != upgraded.identity.InstallationID || m.identity.RuntimeID != upgraded.identity.RuntimeID || !m.identity.PublicKey.Equal(upgraded.identity.PublicKey) {
				t.Fatal("binary edition/version change changed installation identity")
			}
			if err := upgraded.Refresh(context.Background()); err != nil || upgraded.Snapshot().EffectiveTier != paidTier {
				t.Fatalf("upgraded identity failed entitlement refresh: %v", err)
			}
		})
	}
}
