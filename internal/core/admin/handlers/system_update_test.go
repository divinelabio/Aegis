package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/divinelabio/aegis/internal/edition"
	"github.com/divinelabio/aegis/internal/licensing"
)

func TestUpdateApplyRejectsSafeMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		recorder := httptest.NewRecorder()
		(&Handler{}).HandleSystemUpdateApply(recorder, httptest.NewRequest(method, "/api/system/update/apply", nil))
		if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodPost {
			t.Fatal("update mutation accepted a safe method")
		}
	}
}

type updateTestLicense struct {
	snapshot   licensing.Snapshot
	refreshErr error
}

func (m *updateTestLicense) Snapshot() licensing.Snapshot { return m.snapshot }
func (m *updateTestLicense) Has(edition.FeatureID) bool   { return false }
func (m *updateTestLicense) Activate(context.Context, string) (licensing.ActivationResult, error) {
	return licensing.ActivationResult{}, nil
}
func (m *updateTestLicense) Refresh(context.Context) error        { return m.refreshErr }
func (m *updateTestLicense) Deactivate(context.Context) error     { return nil }
func (m *updateTestLicense) Subscribe() <-chan licensing.Snapshot { return nil }

type updateTestTransport func(*http.Request) (*http.Response, error)

func (f updateTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testUpdateCheck(t *testing.T, h *Handler, url string) UpdateStatusResponse {
	t.Helper()
	w := httptest.NewRecorder()
	h.HandleSystemUpdateCheck(w, httptest.NewRequest(http.MethodGet, url, nil))
	var response UpdateStatusResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	return response
}

func TestCommercialEditionStatusAndRefreshFailure(t *testing.T) {
	InvalidateUpdateCache()
	m := &updateTestLicense{snapshot: licensing.Snapshot{BuildTier: edition.CommunityTier, ActivationID: "activated", Status: licensing.StatusUpgradeRequired, Upgrade: licensing.UpgradeInfo{Required: true, Available: true, TargetTier: edition.ProfessionalTier, TargetVersion: Version}}}
	response := testUpdateCheck(t, &Handler{License: m}, "/api/system/update/check")
	if !response.IsTierUpgrade || !response.UpdateAvailable || response.Channel != "professional" || response.CurrentChannel != "community" {
		t.Fatalf("edition upgrade misclassified: %+v", response)
	}
	m.snapshot.Upgrade = licensing.UpgradeInfo{}
	m.snapshot.Status = licensing.StatusActive
	m.refreshErr = errors.New("authority offline")
	response = testUpdateCheck(t, &Handler{License: m}, "/api/system/update/check?force=true")
	if !strings.Contains(response.Error, "authority offline") || response.UpdateAvailable {
		t.Fatalf("refresh failure disguised as up to date: %+v", response)
	}
}

func TestPaidCatalogUnavailableIsNotReportedUpToDate(t *testing.T) {
	for _, reason := range []string{"The commercial release catalog is unavailable.", "No compatible commercial release is published."} {
		m := &updateTestLicense{snapshot: licensing.Snapshot{BuildTier: edition.ProfessionalTier, ActivationID: "activated", Status: licensing.StatusActive, Upgrade: licensing.UpgradeInfo{State: "unavailable", Reason: reason}}}
		response := testUpdateCheck(t, &Handler{License: m}, "/api/system/update/check")
		if response.UpdateAvailable || response.IsTierUpgrade || response.Error != reason {
			t.Fatalf("unavailable paid catalog became up to date: %+v", response)
		}
	}
	m := &updateTestLicense{snapshot: licensing.Snapshot{BuildTier: edition.ProfessionalTier, ActivationID: "activated", Status: licensing.StatusActive}}
	response := testUpdateCheck(t, &Handler{License: m}, "/api/system/update/check")
	if response.UpdateAvailable || response.Error != "" {
		t.Fatalf("successful no-update result became an error: %+v", response)
	}
	m.snapshot.LastError = "background refresh could not reach the authority"
	response = testUpdateCheck(t, &Handler{License: m}, "/api/system/update/check")
	if response.UpdateAvailable || !strings.Contains(response.Error, "background refresh") {
		t.Fatalf("background refresh failure became up to date: %+v", response)
	}
}

func TestUpdateCheckReportsMinimumUpdaterWithoutReadiness(t *testing.T) {
	m := &updateTestLicense{snapshot: licensing.Snapshot{BuildTier: edition.ProfessionalTier, ActivationID: "activated", Status: licensing.StatusActive, Upgrade: licensing.UpgradeInfo{Required: true, State: "unavailable", TargetTier: edition.ProfessionalTier, TargetVersion: "1.0.3", MinimumUpdaterVersion: "1.0.4", Reason: "The local aegis-updater needs version 1.0.4 or later. Install the standalone updater, then refresh."}}}
	response := testUpdateCheck(t, &Handler{License: m}, "/api/system/update/check")
	if response.UpdateAvailable || response.Notify || response.IsTierUpgrade || response.LatestVersion != "1.0.3" || response.MinimumUpdaterVersion != "1.0.4" || !strings.Contains(response.Error, "standalone updater") {
		t.Fatalf("minimum updater diagnostic lost from admin check: %+v", response)
	}
}

func TestCommunityCacheCannotReuseCommercialRelease(t *testing.T) {
	InvalidateUpdateCache()
	t.Cleanup(InvalidateUpdateCache)
	cachedUpdateMu.Lock()
	cachedUpdateResp = &UpdateStatusResponse{CurrentVersion: Version, Channel: "professional", UpdateAvailable: true, LatestVersion: "99.0.0"}
	cachedUpdateAt = time.Now()
	cachedUpdateMu.Unlock()
	previous := http.DefaultTransport
	http.DefaultTransport = updateTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"tag_name":"1.0.1"}`))}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = previous })
	response := testUpdateCheck(t, &Handler{}, "/api/system/update/check")
	if response.Channel != "community" || response.LatestVersion == "99.0.0" {
		t.Fatalf("commercial cached target leaked into community: %+v", response)
	}
}

func TestReleaseCatalogFailureIsNotUpToDate(t *testing.T) {
	InvalidateUpdateCache()
	t.Cleanup(InvalidateUpdateCache)
	previous := http.DefaultTransport
	http.DefaultTransport = updateTestTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("network offline") })
	t.Cleanup(func() { http.DefaultTransport = previous })
	response := testUpdateCheck(t, &Handler{}, "/api/system/update/check?force=true")
	if response.Error == "" {
		t.Fatal("failed catalog reported up to date")
	}
	cachedUpdateMu.RLock()
	defer cachedUpdateMu.RUnlock()
	if cachedUpdateResp != nil {
		t.Fatal("failed catalog poisoned success cache")
	}
}

func TestInvalidationStopsOlderCatalogCheckFromRepopulatingCache(t *testing.T) {
	InvalidateUpdateCache()
	t.Cleanup(InvalidateUpdateCache)
	previous := http.DefaultTransport
	http.DefaultTransport = updateTestTransport(func(*http.Request) (*http.Response, error) {
		// Simulate activation invalidating the cache while a catalog request
		// already in flight is still waiting for its network response.
		InvalidateUpdateCache()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"tag_name":"1.0.1"}`))}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = previous })
	_ = testUpdateCheck(t, &Handler{}, "/api/system/update/check")
	cachedUpdateMu.RLock()
	defer cachedUpdateMu.RUnlock()
	if cachedUpdateResp != nil {
		t.Fatal("in-flight check repopulated invalidated update cache")
	}
}

func TestInactiveCommercialBuildIsNotOfferedCommunityOrPendingUpgrade(t *testing.T) {
	for _, snapshot := range []licensing.Snapshot{
		{BuildTier: edition.ProfessionalTier, Status: licensing.StatusCommunity},
		{BuildTier: edition.CommunityTier, ActivationID: "deactivation", Status: licensing.StatusDeactivationPending, Upgrade: licensing.UpgradeInfo{Required: true, Available: true, TargetTier: edition.ProfessionalTier}},
		{BuildTier: edition.CommunityTier, Status: licensing.StatusInvalid, LastError: "stored entitlement is invalid"},
	} {
		response := testUpdateCheck(t, &Handler{License: &updateTestLicense{snapshot: snapshot}}, "/api/system/update/check")
		if response.UpdateAvailable || response.Error == "" {
			t.Fatalf("inactive or invalid licence advertised upgrade: %+v", response)
		}
	}
}

func TestApplyRejectsChangedReleaseAndCallerManifest(t *testing.T) {
	m := &updateTestLicense{snapshot: licensing.Snapshot{ActivationID: "activated", Status: licensing.StatusActive, Upgrade: licensing.UpgradeInfo{Required: true, Available: true, Manifest: "current-manifest", TargetTier: edition.ProfessionalTier, TargetVersion: "1.0.3"}}}
	h := &Handler{License: m, UpdaterSocket: "unused-test-socket"}
	for _, body := range []string{`{"version":"1.0.2","target_tier":"professional"}`, `{"version":"1.0.3","target_tier":"enterprise"}`, `{"manifest":"caller-controlled"}`, `{} {}`} {
		w := httptest.NewRecorder()
		h.HandleSystemUpdateApply(w, httptest.NewRequest(http.MethodPost, "/api/system/update/apply", strings.NewReader(body)))
		if w.Code != http.StatusConflict && w.Code != http.StatusBadRequest {
			t.Fatalf("invalid/stale target reached updater: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestNormalizeSemverRejectsUnknownAndPreservesPrecedence(t *testing.T) {
	for _, value := range []string{"dev", "garbage", ""} {
		if normalizeSemver(value) != "" {
			t.Fatal("invalid version accepted", value)
		}
	}
	if normalizeSemver(" 1.0.2-rc.1+build ") != "v1.0.2-rc.1+build" {
		t.Fatal("valid version not normalized")
	}
}
