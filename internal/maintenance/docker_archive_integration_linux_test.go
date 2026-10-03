//go:build linux

package maintenance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/divinelabio/aegis/internal/edition"
	"github.com/golang-jwt/jwt/v5"
)

// This opt-in check uses a separate daemon with networking disabled. Never run
// qualification against a machine's default Docker socket or production stack.
func TestIntegrationRealDockerArchive(t *testing.T) {
	archive := os.Getenv("AEGIS_TEST_DOCKER_ARCHIVE")
	if archive == "" {
		t.Skip("real Docker archive qualification not configured")
	}
	if os.Getenv("DOCKER_HOST") != "unix:///tmp/aegis-docker-repair/docker.sock" {
		t.Fatal("qualification requires the isolated Docker test daemon")
	}
	data, err := os.ReadFile(archive + ".metadata.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Digest  string `json:"digest"`
		Image   string `json:"image"`
		Edition string `json:"edition"`
		Version string `json:"version"`
	}
	if err = json.Unmarshal(data, &metadata); err != nil || metadata.Edition != "professional" || metadata.Version == "" {
		t.Fatal("Professional release metadata required")
	}
	mirror := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-download" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.ServeFile(w, r, archive)
	}))
	defer mirror.Close()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := &ReleaseDaemon{
		Config:    UpdaterConfig{ReleasesRoot: t.TempDir(), ContainerRuntime: "/tmp/aegis-docker-repair/bin/docker"},
		Verifier:  ManifestVerifier{Issuer: "https://docker-fixture.invalid", Audience: "aegis-updater", Keys: map[string]ed25519.PublicKey{"fixture": public}},
		transport: mirror.Client().Transport,
	}
	manifest := ArtifactManifest{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://docker-fixture.invalid", Audience: jwt.ClaimStrings{"aegis-updater"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
		Type:             artifactManifestType, Edition: edition.ProfessionalTier, Version: metadata.Version,
		OperatingSystem: "linux", Architecture: "amd64", Format: "docker.tar.gz",
		Digest: metadata.Digest, Image: metadata.Image, URL: mirror.URL + "/" + filepath.Base(archive),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, manifest)
	token.Header["typ"], token.Header["kid"] = artifactManifestType, "fixture"
	signed, err := token.SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := d.Verifier.Verify(signed)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err = d.prepareDocker(ctx, verified, ""); err == nil {
		t.Fatal("paid archive downloaded without its credential")
	}
	corrupt := verified
	corrupt.Digest = "sha256:" + strings.Repeat("0", 64)
	if _, err = d.prepareDocker(ctx, corrupt, "fixture-download"); err == nil {
		t.Fatal("archive digest mismatch accepted")
	}
	image, err := d.prepareDocker(ctx, verified, "fixture-download")
	if err != nil || image != metadata.Image {
		t.Fatalf("actual Docker download/load/identity qualification failed: %v", err)
	}
	wrongEdition := verified
	wrongEdition.Edition = edition.EnterpriseTier
	if _, err = d.prepareDocker(ctx, wrongEdition, "fixture-download"); err == nil {
		t.Fatal("actual Docker binary with the wrong compiled edition accepted")
	}
}
