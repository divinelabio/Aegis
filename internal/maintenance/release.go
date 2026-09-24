package maintenance

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/edition"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/mod/semver"
)

const artifactManifestType = "aegis-artifact-manifest+jwt"

var (
	versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$`)
	imagePattern   = regexp.MustCompile(`^[a-zA-Z0-9._:/@-]{1,512}$`)
)

type ArtifactManifest struct {
	jwt.RegisteredClaims
	Type                  string            `json:"typ"`
	Edition               edition.BuildTier `json:"edition"`
	Version               string            `json:"version"`
	OperatingSystem       string            `json:"os"`
	Architecture          string            `json:"architecture"`
	Format                string            `json:"format"`
	URL                   string            `json:"url,omitempty"`
	Digest                string            `json:"digest"`
	Image                 string            `json:"image,omitempty"`
	MinimumUpdaterVersion string            `json:"minimum_updater_version,omitempty"`
}

type ManifestVerifier struct {
	Issuer   string
	Audience string
	Keys     map[string]ed25519.PublicKey
	Clock    func() time.Time
}

func (v ManifestVerifier) Verify(raw string) (ArtifactManifest, error) {
	if v.Clock == nil {
		v.Clock = time.Now
	}
	claims := ArtifactManifest{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}), jwt.WithoutClaimsValidation())
	token, err := parser.ParseWithClaims(raw, &claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodEdDSA || token.Header["typ"] != artifactManifestType {
			return nil, errors.New("artifact manifest has an unexpected algorithm or type")
		}
		key, ok := v.Keys[fmt.Sprint(token.Header["kid"])]
		if !ok {
			return nil, errors.New("artifact manifest uses an untrusted signing key")
		}
		return key, nil
	})
	if err != nil || !token.Valid {
		return ArtifactManifest{}, fmt.Errorf("verify artifact manifest: %w", err)
	}
	if claims.Type != artifactManifestType || claims.Issuer != v.Issuer || !audienceContains(claims.Audience, v.Audience) {
		return ArtifactManifest{}, errors.New("artifact manifest identity is invalid")
	}
	now := v.Clock().UTC()
	if claims.ExpiresAt == nil || now.After(claims.ExpiresAt.Time) || claims.NotBefore != nil && now.Add(time.Minute).Before(claims.NotBefore.Time) {
		return ArtifactManifest{}, errors.New("artifact manifest is outside its validity period")
	}
	if claims.Edition != edition.ProfessionalTier && claims.Edition != edition.EnterpriseTier {
		return ArtifactManifest{}, errors.New("artifact manifest edition is invalid")
	}
	if !versionPattern.MatchString(claims.Version) || !semver.IsValid(normalizeVersion(claims.Version)) || claims.OperatingSystem != runtime.GOOS || claims.Architecture != runtime.GOARCH {
		return ArtifactManifest{}, errors.New("artifact manifest does not match this host")
	}
	if !validSHA256(claims.Digest) {
		return ArtifactManifest{}, errors.New("artifact digest is invalid")
	}
	switch claims.Format {
	case "tar.gz":
		parsed, err := url.Parse(claims.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || claims.Image != "" {
			return ArtifactManifest{}, errors.New("native artifact location is invalid")
		}
	case "oci":
		if claims.URL != "" || !imagePattern.MatchString(claims.Image) || !strings.Contains(claims.Image, "@sha256:") || !strings.HasSuffix(claims.Image, claims.Digest) {
			return ArtifactManifest{}, errors.New("OCI artifact reference is invalid")
		}
	default:
		return ArtifactManifest{}, errors.New("artifact format is unsupported")
	}
	return claims, nil
}

func normalizeVersion(value string) string {
	if strings.HasPrefix(value, "v") {
		return value
	}
	return "v" + value
}

func validSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}

func audienceContains(values jwt.ClaimStrings, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
