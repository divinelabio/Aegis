package licensing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/divinelab-io/aegis/internal/edition"
	"github.com/golang-jwt/jwt/v5"
)

const entitlementTokenType = "aegis-license+jwt"

type entitlementClaims struct {
	jwt.RegisteredClaims
	Type                      string              `json:"typ"`
	LicenseID                 string              `json:"license_id"`
	ActivationID              string              `json:"activation_id"`
	InstallationPublicKeyHash string              `json:"installation_public_key_hash"`
	Tier                      edition.BuildTier   `json:"tier"`
	Features                  []edition.FeatureID `json:"features"`
	OfflineUntil              *jwt.NumericDate    `json:"offline_until"`
	SubscriptionEnd           *jwt.NumericDate    `json:"subscription_end,omitempty"`
	LicenseStatus             Status              `json:"license_status,omitempty"`
}

type verifier struct {
	issuer   string
	audience string
	keys     map[string]ed25519.PublicKey
	clock    func() time.Time
}

func (v verifier) verify(raw, installationHash string) (*entitlementClaims, error) {
	if raw == "" {
		return nil, errors.New("empty entitlement")
	}
	claims := &entitlementClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}), jwt.WithoutClaimsValidation())
	token, err := parser.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("unexpected entitlement algorithm %q", token.Method.Alg())
		}
		if typ, _ := token.Header["typ"].(string); typ != entitlementTokenType {
			return nil, fmt.Errorf("unexpected entitlement token type %q", typ)
		}
		kid, _ := token.Header["kid"].(string)
		key, ok := v.keys[kid]
		if !ok {
			return nil, fmt.Errorf("untrusted entitlement signing key %q", kid)
		}
		return key, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("verify entitlement signature: %w", err)
	}
	if claims.Type != entitlementTokenType {
		return nil, fmt.Errorf("invalid entitlement claim type %q", claims.Type)
	}
	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("invalid entitlement issuer %q", claims.Issuer)
	}
	audiences, err := claims.GetAudience()
	if err != nil || !containsAudience(audiences, v.audience) {
		return nil, errors.New("invalid entitlement audience")
	}
	if claims.LicenseID == "" || claims.ActivationID == "" || claims.Subject == "" || claims.ID == "" {
		return nil, errors.New("entitlement is missing required identifiers")
	}
	if claims.InstallationPublicKeyHash != installationHash {
		return nil, errors.New("entitlement belongs to another installation")
	}
	if !claims.Tier.Valid() {
		return nil, fmt.Errorf("invalid entitled tier %q", claims.Tier)
	}
	if !claims.LicenseStatus.validEntitlementStatus() {
		return nil, fmt.Errorf("invalid licence status %q", claims.LicenseStatus)
	}
	allowed := edition.FeaturesForTier(claims.Tier)
	// Aegis editions are complete, cumulative plans. Accepting an arbitrary
	// subset here would make the per-section tier gates disagree with a signed
	// entitlement that claims the same tier, creating an unsupported licensing
	// model and an enforcement ambiguity. Add-ons must use a distinct entitlement
	// type with their own runtime gates instead.
	if len(claims.Features) != len(allowed) {
		return nil, fmt.Errorf("entitlement features do not match tier %q", claims.Tier)
	}
	seen := make(edition.FeatureSet, len(claims.Features))
	for _, feature := range claims.Features {
		if !allowed.Has(feature) {
			return nil, fmt.Errorf("feature %q is invalid for tier %q", feature, claims.Tier)
		}
		if seen.Has(feature) {
			return nil, fmt.Errorf("entitlement repeats feature %q", feature)
		}
		seen[feature] = struct{}{}
	}
	if len(seen) != len(allowed) {
		return nil, fmt.Errorf("entitlement features do not match tier %q", claims.Tier)
	}
	now := v.clock().UTC()
	if claims.NotBefore != nil && now.Add(2*time.Minute).Before(claims.NotBefore.Time) {
		return nil, errors.New("entitlement is not active yet")
	}
	if claims.IssuedAt != nil && claims.IssuedAt.Time.After(now.Add(2*time.Minute)) {
		return nil, errors.New("entitlement issue time is in the future")
	}
	if claims.ExpiresAt == nil || claims.OfflineUntil == nil {
		return nil, errors.New("entitlement expiration is missing")
	}
	if claims.OfflineUntil.Time.Before(claims.ExpiresAt.Time) {
		return nil, errors.New("offline grace ends before lease expiration")
	}
	return claims, nil
}

func publicKeyHash(key ed25519.PublicKey) string {
	digest := sha256.Sum256(key)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func containsAudience(values jwt.ClaimStrings, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
