package licensing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	KeyPurposeLease    = "lease"
	KeyPurposeArtifact = "artifact"
)

type CertifiedKey struct {
	Algorithm string    `json:"algorithm"`
	Purpose   string    `json:"purpose"`
	PublicKey string    `json:"public_key"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

type KeySetPayload struct {
	Version int                     `json:"version"`
	Keys    map[string]CertifiedKey `json:"keys"`
}

type SignedKeySet struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// CertifiedTrustedKeys verifies an exact key-set payload with Aegis' offline
// root key. API responses are never allowed to introduce signing keys.
func CertifiedTrustedKeys(rootPublicKey, encodedEnvelope, purpose string, now time.Time) (map[string]ed25519.PublicKey, error) {
	root, err := base64.RawStdEncoding.DecodeString(rootPublicKey)
	if err != nil || len(root) != ed25519.PublicKeySize {
		return nil, errors.New("invalid embedded licence root public key")
	}
	envelopeJSON, err := base64.RawStdEncoding.DecodeString(encodedEnvelope)
	if err != nil {
		return nil, errors.New("invalid embedded signed key set encoding")
	}
	var envelope SignedKeySet
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return nil, fmt.Errorf("decode signed key set: %w", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, errors.New("invalid signed key set payload")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("invalid signed key set signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(root), payload, signature) {
		return nil, errors.New("signed key set is not certified by the Aegis root")
	}
	var keySet KeySetPayload
	if err := json.Unmarshal(payload, &keySet); err != nil {
		return nil, fmt.Errorf("decode certified key set: %w", err)
	}
	if keySet.Version < 1 || len(keySet.Keys) == 0 {
		return nil, errors.New("certified key set is empty or unversioned")
	}
	trusted := make(map[string]ed25519.PublicKey)
	for id, key := range keySet.Keys {
		if id == "" || key.Algorithm != "Ed25519" {
			return nil, fmt.Errorf("invalid certified key %q", id)
		}
		if key.Purpose != KeyPurposeLease && key.Purpose != KeyPurposeArtifact {
			return nil, fmt.Errorf("invalid certified key purpose %q", key.Purpose)
		}
		decoded, err := base64.RawStdEncoding.DecodeString(key.PublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid certified public key %q", id)
		}
		if now.Before(key.NotBefore) || !now.Before(key.NotAfter) {
			continue
		}
		if key.Purpose == purpose {
			trusted[id] = ed25519.PublicKey(decoded)
		}
	}
	if len(trusted) == 0 {
		return nil, fmt.Errorf("no currently valid %s signing keys", purpose)
	}
	return trusted, nil
}
