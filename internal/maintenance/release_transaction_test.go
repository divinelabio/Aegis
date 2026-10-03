//go:build linux || windows

package maintenance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/divinelabio/aegis/internal/edition"
	"github.com/divinelabio/aegis/internal/licensing"
	"github.com/golang-jwt/jwt/v5"
)

// The fixture is an executable binary, allowing staging to run the same
// build-info handshake used for a real release without invoking a live service.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "--build-info" {
		executable, err := os.Executable()
		if err != nil {
			os.Exit(2)
		}
		data, err := os.ReadFile(filepath.Join(filepath.Dir(executable), "build-info.json"))
		if err != nil {
			os.Exit(2)
		}
		_, _ = os.Stdout.Write(data)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func transactionFixture(t *testing.T) (*ReleaseDaemon, ArtifactManifest, string) {
	t.Helper()
	root := t.TempDir()
	releases := filepath.Join(root, "releases")
	initial := filepath.Join(releases, "initial")
	if err := os.MkdirAll(initial, 0755); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(initial, binaryName("aegis")), binary, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(initial, "build-info.json"), []byte(`{"version":"1.0.2","build_tier":"community"}`), 0644); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "current")
	syntheticSwitch := false
	if err = os.Symlink(initial, current); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		t.Log("Windows symlink privilege unavailable; exercising transaction with a file-backed release switch")
		syntheticSwitch = true
		if err = os.WriteFile(current, []byte(initial), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var archive bytes.Buffer
	compressed := gzip.NewWriter(&archive)
	writer := tar.NewWriter(compressed)
	for name, data := range map[string][]byte{binaryName("aegis"): binary, binaryName("aegisctl"): []byte("fixture-cli"), binaryName("aegis-updater"): []byte("fixture-updater"), "build-info.json": []byte(`{"version":"1.0.2","build_tier":"professional"}`)} {
		if err = writer.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err = writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = compressed.Close(); err != nil {
		t.Fatal(err)
	}
	download := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			w.WriteHeader(403)
			return
		}
		_, _ = w.Write(archive.Bytes())
	}))
	t.Cleanup(download.Close)
	var daemon *ReleaseDaemon
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target, err := daemon.resolveNativeTarget()
		if err != nil {
			w.WriteHeader(503)
			return
		}
		data, err := os.ReadFile(filepath.Join(target, "build-info.json"))
		if err != nil {
			w.WriteHeader(503)
			return
		}
		var info releaseBuildInfo
		_ = json.Unmarshal(data, &info)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "version": info.Version, "build_tier": info.BuildTier, "effective_tier": info.BuildTier})
	}))
	t.Cleanup(health.Close)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	daemon = &ReleaseDaemon{Config: UpdaterConfig{Mode: "native", SocketPath: filepath.Join(root, "updater.sock"), StatePath: filepath.Join(root, "state.json"), ReleasesRoot: releases, CurrentLink: current, HealthURL: health.URL}, Version: "1.0.2", Verifier: ManifestVerifier{Issuer: "https://test.invalid", Audience: "aegis-updater", Keys: map[string]ed25519.PublicKey{"fixture": public}}, restartOverride: func(context.Context) error { return nil }, transport: download.Client().Transport}
	if syntheticSwitch {
		daemon.nativeTargetOverride = func() (string, error) {
			data, err := os.ReadFile(daemon.Config.CurrentLink)
			return string(data), err
		}
		daemon.nativeSwitchOverride = func(target string) error {
			return writeAtomicFile(daemon.Config.CurrentLink, []byte(target), 0600)
		}
	}
	digest := sha256.Sum256(archive.Bytes())
	manifest := ArtifactManifest{RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://test.invalid", Audience: jwt.ClaimStrings{"aegis-updater"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}, Type: artifactManifestType, Edition: edition.ProfessionalTier, Version: "1.0.2", OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH, Format: "tar.gz", URL: download.URL, Digest: "sha256:" + hex.EncodeToString(digest[:])}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, manifest)
	token.Header["typ"], token.Header["kid"] = artifactManifestType, "fixture"
	signed, err := token.SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	return daemon, manifest, signed
}

func TestQueuedSameVersionTierUpgradeSurvivesCallerCancellation(t *testing.T) {
	daemon, _, signed := transactionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	response := daemon.Execute(ctx, UpdaterRequest{Operation: "upgrade", Manifest: signed, Credential: "fixture-token"})
	cancel()
	if !response.OK || response.Status.State != "queued" || response.Status.JobID == "" {
		t.Fatalf("upgrade was not queued: %+v", response)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		status := daemon.Execute(context.Background(), UpdaterRequest{Operation: "status"})
		if status.Status.State == "active" {
			if status.Status.Edition != "professional" || status.Status.Version != "1.0.2" || status.Status.PreviousEdition != "community" {
				t.Fatalf("bad committed state: %+v", status.Status)
			}
			if _, err := os.Stat(filepath.Join(status.Status.PreviousTarget, binaryName("aegis"))); err != nil {
				t.Fatal("initial rollback baseline was removed")
			}
			return
		}
		if status.Status.State == "failed" {
			t.Fatal(status.Status.LastError)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("queued upgrade did not complete")
}

func TestRestartFailureRestoresInitialRelease(t *testing.T) {
	daemon, manifest, _ := transactionFixture(t)
	initial, err := daemon.resolveNativeTarget()
	if err != nil {
		t.Fatal(err)
	}
	restarts := 0
	daemon.restartOverride = func(context.Context) error {
		restarts++
		if restarts == 1 {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	if err = daemon.apply(context.Background(), manifest, "fixture-token"); err == nil {
		t.Fatal("restart failure was hidden")
	}
	restored, err := daemon.resolveNativeTarget()
	if err != nil || restored != initial {
		t.Fatal("working initial release was not restored")
	}
	state, err := daemon.loadState()
	if err != nil || state.State != "rolled_back" || state.Edition != "community" {
		t.Fatalf("bad rollback journal: %+v %v", state, err)
	}
}

func TestFailedRollbackKeepsRecoveryIntent(t *testing.T) {
	daemon, manifest, _ := transactionFixture(t)
	initial, _ := daemon.resolveNativeTarget()
	daemon.restartOverride = func(context.Context) error { return io.ErrUnexpectedEOF }
	applyErr := daemon.apply(context.Background(), manifest, "fixture-token")
	if applyErr == nil {
		t.Fatal("restart failures were hidden")
	}
	daemon.failure(applyErr)
	state, err := daemon.loadState()
	if err != nil || state.State != "rolling_back" || state.CurrentTarget != initial || state.LastError == "" {
		t.Fatalf("recovery intent was lost: %+v %v", state, err)
	}
	if response := daemon.Execute(context.Background(), UpdaterRequest{Operation: "rollback"}); response.OK {
		t.Fatal("another job was allowed to overwrite unresolved recovery intent")
	}
	daemon.restartOverride = func(context.Context) error { return nil }
	if err = daemon.recoverInterrupted(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _ = daemon.loadState()
	actual, _ := daemon.resolveNativeTarget()
	if actual != initial || state.CurrentTarget != initial || state.Edition != "community" || state.State != "failed" {
		t.Fatalf("baseline recovery failed: %+v", state)
	}
}

func TestRollbackIntentIsPersistedBeforeLinkSwitch(t *testing.T) {
	daemon, manifest, _ := transactionFixture(t)
	if err := daemon.apply(context.Background(), manifest, "fixture-token"); err != nil {
		t.Fatal(err)
	}
	installed, _ := daemon.loadState()
	workingLink := daemon.Config.CurrentLink
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("block link creation"), 0600); err != nil {
		t.Fatal(err)
	}
	daemon.Config.CurrentLink = filepath.Join(blocked, "current")
	if err := daemon.rollback(context.Background()); err == nil {
		t.Fatal("impossible link switch succeeded")
	}
	intent, _ := daemon.loadState()
	if intent.State != "rolling_back" || intent.CurrentTarget != installed.PreviousTarget || intent.PreviousTarget != installed.CurrentTarget {
		t.Fatalf("rollback did not persist the intended baseline: %+v", intent)
	}
	daemon.Config.CurrentLink = workingLink
	if err := daemon.recoverInterrupted(context.Background()); err != nil {
		t.Fatal(err)
	}
	actual, _ := daemon.resolveNativeTarget()
	if actual != installed.PreviousTarget {
		t.Fatal("rollback recovery did not complete the previously persisted switch")
	}
}

func TestCrashAfterUpgradeSwitchRestoresBaselineAndCandidateIdentity(t *testing.T) {
	daemon, manifest, _ := transactionFixture(t)
	initial, _ := daemon.resolveNativeTarget()
	candidate, err := daemon.prepareNative(context.Background(), manifest, "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	state := UpdaterState{State: "switching", CurrentTarget: initial, PreviousTarget: initial, Edition: "community", PreviousEdition: "community", Version: "1.0.2", PreviousVersion: "1.0.2", CandidateTarget: candidate, CandidateEdition: "professional", CandidateVersion: "1.0.2"}
	if err = daemon.saveState(state); err != nil {
		t.Fatal(err)
	}
	if err = daemon.switchTarget(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err = daemon.recoverInterrupted(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _ = daemon.loadState()
	actual, _ := daemon.resolveNativeTarget()
	if actual != initial || state.CurrentTarget != initial || state.PreviousTarget != candidate || state.PreviousEdition != "professional" {
		t.Fatalf("interrupted switch recovery lost identity: %+v", state)
	}
}

func TestSignedBuildMetadataMustMatchDownloadedBinary(t *testing.T) {
	daemon, manifest, _ := transactionFixture(t)
	manifest.Version = "1.0.2+different-build"
	if _, err := daemon.prepareNative(context.Background(), manifest, "fixture-token"); err == nil {
		t.Fatal("semver precedence equality was used instead of signed release identity")
	}
}

func TestStoppingDaemonWaitsForOwnedJobAndRejectsNewJobs(t *testing.T) {
	daemon, _, signed := transactionFixture(t)
	response := daemon.Execute(context.Background(), UpdaterRequest{Operation: "upgrade", Manifest: signed, Credential: "fixture-token"})
	if !response.OK {
		t.Fatal(response.Error)
	}
	daemon.stopJobs()
	daemon.mu.Lock()
	running := daemon.running
	daemon.mu.Unlock()
	if running {
		t.Fatal("daemon released its job before cancellation/cleanup completed")
	}
	if response = daemon.Execute(context.Background(), UpdaterRequest{Operation: "upgrade", Manifest: signed}); response.OK {
		t.Fatal("stopping daemon accepted another job")
	}
	state, err := daemon.loadState()
	if err != nil || state.State != "failed" || state.LastError == "" {
		t.Fatalf("canceled job was not finalized: %+v %v", state, err)
	}
}

func TestStaleJournalCannotRejectActualInstalledVersion(t *testing.T) {
	daemon, _, signed := transactionFixture(t)
	if err := daemon.saveState(UpdaterState{State: "active", Version: "9.0.0", Edition: "professional"}); err != nil {
		t.Fatal(err)
	}
	response := daemon.Execute(context.Background(), UpdaterRequest{Operation: "upgrade", Manifest: signed, Credential: "fixture-token"})
	if !response.OK || response.Status.State != "queued" || response.Status.Version != "1.0.2" || response.Status.Edition != "community" {
		t.Fatalf("stale journal caused false downgrade rejection: %+v", response)
	}
	daemon.stopJobs()
}

func signFixtureManifest(t *testing.T, daemon *ReleaseDaemon, manifest ArtifactManifest, key ed25519.PrivateKey) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, manifest)
	token.Header["typ"], token.Header["kid"] = artifactManifestType, "fixture"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestMalformedSignedManifestConstraintsAreRejected(t *testing.T) {
	daemon, manifest, _ := transactionFixture(t)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	daemon.Verifier.Keys = map[string]ed25519.PublicKey{"fixture": public}
	for _, minimum := range []string{"invalid", "1.0.0/../../", "1.0.0 "} {
		manifest.MinimumUpdaterVersion = minimum
		if _, err := daemon.Verifier.Verify(signFixtureManifest(t, daemon, manifest, private)); err == nil {
			t.Fatalf("malformed minimum updater version %q was accepted", minimum)
		}
	}
	manifest.MinimumUpdaterVersion = ""
	manifest.Format, manifest.URL = "oci", ""
	manifest.Image = "registry.invalid/aegis@sha256:wrong/" + manifest.Digest
	if _, err := daemon.Verifier.Verify(signFixtureManifest(t, daemon, manifest, private)); err == nil {
		t.Fatal("OCI image with an inexact digest suffix was accepted")
	}
	manifest.Image = "registry.invalid/aegis@" + manifest.Digest
	if _, err := daemon.Verifier.Verify(signFixtureManifest(t, daemon, manifest, private)); err != nil {
		t.Fatalf("valid digest-pinned image was rejected: %v", err)
	}
}

func TestArtifactTrustGenerationSurvivesRestart(t *testing.T) {
	daemon, manifest, _ := transactionFixture(t)
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	makeKeySet := func(version int) string {
		payload, err := json.Marshal(licensing.KeySetPayload{Version: version, Keys: map[string]licensing.CertifiedKey{"fixture": {Algorithm: "Ed25519", Purpose: licensing.KeyPurposeArtifact, PublicKey: base64.RawStdEncoding.EncodeToString(public), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}}})
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := json.Marshal(licensing.SignedKeySet{Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(rootPrivate, payload))})
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawStdEncoding.EncodeToString(envelope)
	}
	daemon.Verifier.RootPublicKey = base64.RawStdEncoding.EncodeToString(rootPublic)
	keySet := makeKeySet(2)
	daemon.Verifier.SignedKeySet = keySet
	response := daemon.Execute(context.Background(), UpdaterRequest{Operation: "upgrade", Manifest: "malformed"})
	state, _ := daemon.loadState()
	if response.OK || state.KeySetVersion != 0 {
		t.Fatal("invalid manifest advanced the persisted trust generation")
	}
	signed := signFixtureManifest(t, daemon, manifest, private)
	response = daemon.Execute(context.Background(), UpdaterRequest{Operation: "upgrade", Manifest: signed, Credential: "fixture-token"})
	if !response.OK {
		t.Fatal(response.Error)
	}
	daemon.stopJobs()
	state, _ = daemon.loadState()
	if state.KeySetVersion != 2 || state.SignedKeySet != keySet {
		t.Fatal("verified trust certificate was not persisted")
	}
	restarted := &ReleaseDaemon{Config: daemon.Config, Verifier: daemon.Verifier, Version: daemon.Version, restartOverride: daemon.restartOverride, transport: daemon.transport, nativeTargetOverride: daemon.nativeTargetOverride, nativeSwitchOverride: daemon.nativeSwitchOverride}
	restarted.Verifier.Keys = nil        // Mimic a binary with no embedded rotated key.
	restarted.Verifier.SignedKeySet = "" // Persisted trust must work independently.
	response = restarted.Execute(context.Background(), UpdaterRequest{Operation: "upgrade", Manifest: signed, Credential: "fixture-token"})
	if !response.OK {
		t.Fatalf("restart lost certified artifact trust: %s", response.Error)
	}
	restarted.stopJobs()
	older := &ReleaseDaemon{Config: daemon.Config, Verifier: daemon.Verifier, Version: daemon.Version}
	response = older.Execute(context.Background(), UpdaterRequest{Operation: "upgrade", Manifest: signed, SignedKeySet: makeKeySet(1)})
	if response.OK {
		t.Fatal("restarted daemon accepted a certified trust downgrade")
	}
}
