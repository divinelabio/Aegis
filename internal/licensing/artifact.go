package licensing

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/divinelabio/aegis/internal/edition"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/mod/semver"
)

var artifactImagePattern = regexp.MustCompile(`^[a-zA-Z0-9._:/@-]{1,512}$`)

// Inspect the authenticated release identity before advertising an installable
// upgrade. The updater independently verifies the full manifest and archive.
func (m *RuntimeManager) verifyUpgradeArtifact(upgrade UpgradeInfo) (time.Time, error) {
	keys := m.config.TrustedKeys
	if m.config.RootPublicKey != "" {
		var err error
		keys, err = CertifiedTrustedKeys(m.config.RootPublicKey, m.config.SignedKeySet, KeyPurposeArtifact, m.config.Clock())
		if err != nil {
			return time.Time{}, err
		}
	}
	var claims struct {
		jwt.RegisteredClaims
		Type                  string            `json:"typ"`
		Edition               edition.BuildTier `json:"edition"`
		Version               string            `json:"version"`
		OperatingSystem       string            `json:"os"`
		Architecture          string            `json:"architecture"`
		Format                string            `json:"format"`
		MinimumUpdaterVersion string            `json:"minimum_updater_version"`
		Digest                string            `json:"digest"`
		URL                   string            `json:"url"`
		Image                 string            `json:"image"`
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}), jwt.WithIssuer(m.config.Issuer), jwt.WithAudience("aegis-updater"), jwt.WithExpirationRequired(), jwt.WithTimeFunc(m.config.Clock), jwt.WithLeeway(time.Minute))
	_, err := parser.ParseWithClaims(upgrade.Manifest, &claims, func(token *jwt.Token) (any, error) {
		if token.Header["typ"] != "aegis-artifact-manifest+jwt" {
			return nil, errors.New("unexpected artifact token type")
		}
		key, ok := keys[fmt.Sprint(token.Header["kid"])]
		if !ok {
			return nil, errors.New("artifact uses an untrusted signing key")
		}
		return key, nil
	})
	if err != nil {
		return time.Time{}, err
	}
	if claims.ExpiresAt == nil || !m.config.Clock().Before(claims.ExpiresAt.Time) {
		return time.Time{}, errors.New("artifact manifest expired")
	}
	if claims.Type != "aegis-artifact-manifest+jwt" || (claims.Edition != edition.ProfessionalTier && claims.Edition != edition.EnterpriseTier) || claims.Edition != upgrade.TargetTier ||
		!semver.IsValid(normalizeVersion(claims.Version)) || normalizeVersion(claims.Version) != normalizeVersion(upgrade.TargetVersion) ||
		claims.OperatingSystem != platformName() || claims.Architecture != architectureName() || claims.Format != m.config.ArtifactFormat {
		return time.Time{}, errors.New("signed artifact does not match the advertised edition, version, or platform")
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(claims.Digest, "sha256:"))
	if !strings.HasPrefix(claims.Digest, "sha256:") || err != nil || len(digest) != 32 {
		return time.Time{}, errors.New("artifact digest is invalid")
	}
	if claims.Format == "docker.tar.gz" {
		location, err := url.Parse(claims.URL)
		imageDigest, imageErr := hex.DecodeString(strings.TrimPrefix(claims.Image, "sha256:"))
		if err != nil || location.Scheme != "https" || location.Host == "" || location.User != nil || !strings.HasPrefix(claims.Image, "sha256:") || imageErr != nil || len(imageDigest) != 32 || claims.OperatingSystem != "linux" {
			return time.Time{}, errors.New("Docker archive identity or location is invalid")
		}
	} else if claims.Format == "oci" {
		image, digestPin, pinned := strings.Cut(claims.Image, "@")
		if claims.OperatingSystem != "linux" || claims.URL != "" || !pinned || image == "" || digestPin != claims.Digest || !artifactImagePattern.MatchString(claims.Image) {
			return time.Time{}, errors.New("OCI artifact reference is invalid")
		}
	} else {
		location, err := url.Parse(claims.URL)
		platformFormat := claims.OperatingSystem == "linux" && claims.Format == "tar.gz" || claims.OperatingSystem == "windows" && claims.Format == "zip"
		if !platformFormat || err != nil || location.Scheme != "https" || location.Host == "" || location.User != nil || claims.Image != "" {
			return time.Time{}, errors.New("artifact location is invalid")
		}
	}
	if claims.MinimumUpdaterVersion != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		updaterVersion := m.updaterVersion(ctx)
		cancel()
		if !semver.IsValid(normalizeVersion(updaterVersion)) || !semver.IsValid(normalizeVersion(claims.MinimumUpdaterVersion)) || semver.Compare(normalizeVersion(updaterVersion), normalizeVersion(claims.MinimumUpdaterVersion)) < 0 {
			return time.Time{}, errors.New("upgrade the local updater before installing this release")
		}
	}
	return claims.ExpiresAt.Time, nil
}
