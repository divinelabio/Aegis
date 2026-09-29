package licensing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/uuid"
)

type installationIdentity struct {
	InstallationID string
	RuntimeID      string
	PublicKey      ed25519.PublicKey
	PrivateKey     ed25519.PrivateKey
}

type identityFile struct {
	InstallationID       string `json:"installation_id"`
	PublicKey            string `json:"public_key"`
	PrivateKey           string `json:"private_key"`
	PrivateKeyProtection string `json:"private_key_protection,omitempty"`
}

type persistedState struct {
	ActivationID   string    `json:"activation_id,omitempty"`
	Entitlement    string    `json:"entitlement,omitempty"`
	LastServerTime time.Time `json:"last_server_time,omitempty"`
	LastObservedAt time.Time `json:"last_observed_at,omitempty"`
	LastRefresh    time.Time `json:"last_refresh,omitempty"`
}

func loadOrCreateIdentity(dir string) (installationIdentity, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return installationIdentity{}, err
	}
	if err := securePrivatePath(dir); err != nil {
		return installationIdentity{}, fmt.Errorf("secure licensing state directory: %w", err)
	}
	path := filepath.Join(dir, "identity.json")
	data, err := os.ReadFile(path)
	if err == nil {
		if err := securePrivatePath(path); err != nil {
			return installationIdentity{}, fmt.Errorf("secure installation identity: %w", err)
		}
		var stored identityFile
		if err := json.Unmarshal(data, &stored); err != nil {
			return installationIdentity{}, fmt.Errorf("decode installation identity: %w", err)
		}
		if _, err := uuid.Parse(stored.InstallationID); err != nil {
			return installationIdentity{}, fmt.Errorf("invalid stored installation ID")
		}
		pub, err := base64.RawStdEncoding.DecodeString(stored.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return installationIdentity{}, fmt.Errorf("invalid stored installation public key")
		}
		priv, migrate, err := unprotectInstallationPrivateKey(stored.PrivateKey, stored.PrivateKeyProtection)
		if err != nil || len(priv) != ed25519.PrivateKeySize {
			return installationIdentity{}, fmt.Errorf("invalid stored installation private key")
		}
		if migrate {
			protected, protection, err := protectInstallationPrivateKey(priv)
			if err != nil {
				return installationIdentity{}, fmt.Errorf("protect stored installation private key: %w", err)
			}
			stored.PrivateKey = protected
			stored.PrivateKeyProtection = protection
			if err := writeJSONAtomic(path, stored, 0o600); err != nil {
				return installationIdentity{}, fmt.Errorf("migrate installation private key protection: %w", err)
			}
		}
		return installationIdentity{
			InstallationID: stored.InstallationID,
			RuntimeID:      uuid.NewString(),
			PublicKey:      ed25519.PublicKey(pub),
			PrivateKey:     ed25519.PrivateKey(priv),
		}, nil
	}
	if !os.IsNotExist(err) {
		return installationIdentity{}, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return installationIdentity{}, err
	}
	protected, protection, err := protectInstallationPrivateKey(priv)
	if err != nil {
		return installationIdentity{}, fmt.Errorf("protect installation private key: %w", err)
	}
	stored := identityFile{
		InstallationID:       uuid.NewString(),
		PublicKey:            base64.RawStdEncoding.EncodeToString(pub),
		PrivateKey:           protected,
		PrivateKeyProtection: protection,
	}
	if err := writeJSONAtomic(path, stored, 0o600); err != nil {
		return installationIdentity{}, err
	}
	return installationIdentity{
		InstallationID: stored.InstallationID,
		RuntimeID:      uuid.NewString(),
		PublicKey:      pub,
		PrivateKey:     priv,
	}, nil
}

func loadPersistedState(dir string) (persistedState, error) {
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if os.IsNotExist(err) {
		return persistedState{}, nil
	}
	if err != nil {
		return persistedState{}, err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedState{}, err
	}
	return state, nil
}

func savePersistedState(dir string, state persistedState) error {
	return writeJSONAtomic(filepath.Join(dir, "state.json"), state, 0o600)
}

func clearPersistedState(dir string) error {
	err := os.Remove(filepath.Join(dir, "state.json"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".aegis-state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return securePrivatePath(path)
}

func platformName() string     { return runtime.GOOS }
func architectureName() string { return runtime.GOARCH }
