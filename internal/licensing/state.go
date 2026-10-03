package licensing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	ActivationID   string        `json:"activation_id,omitempty"`
	Entitlement    string        `json:"entitlement,omitempty"`
	LastServerTime time.Time     `json:"last_server_time,omitempty"`
	LastObservedAt time.Time     `json:"last_observed_at,omitempty"`
	LastRefresh    time.Time     `json:"last_refresh,omitempty"`
	Upgrade        storedUpgrade `json:"upgrade,omitempty"`
	SignedKeySet   string        `json:"signed_key_set,omitempty"`
	// Seats superseded by a committed activation or rejected during validation.
	// Keep their IDs until an idempotent authority DELETE has succeeded.
	PendingDeactivations []string `json:"pending_deactivations,omitempty"`
}

// Persist only release metadata. Short-lived download credentials are refreshed
// immediately before installation and never saved to disk.
type storedUpgrade struct {
	ArtifactStatus        string `json:"artifact_status,omitempty"`
	MinimumUpdaterVersion string `json:"minimum_updater_version,omitempty"`
	TargetTier            string `json:"target_tier,omitempty"`
	TargetVersion         string `json:"target_version,omitempty"`
	Manifest              string `json:"manifest,omitempty"`
}

var identityMu sync.Mutex

func stableRuntimeID(installationID string) string {
	hostname, _ := os.Hostname()
	machine, _ := os.ReadFile("/etc/machine-id")
	if hostMachine, err := os.ReadFile("/etc/aegis/host-machine-id"); err == nil && len(hostMachine) > 0 {
		machine = hostMachine
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(installationID+"/"+hostname+"/"+strings.TrimSpace(string(machine)))).String()
}

func loadOrCreateIdentity(dir string) (installationIdentity, error) {
	identityMu.Lock()
	defer identityMu.Unlock()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return installationIdentity{}, err
	}
	if err := securePrivatePath(dir); err != nil {
		return installationIdentity{}, fmt.Errorf("secure licensing state directory: %w", err)
	}
	// Serialize identity creation across processes as well as goroutines.
	lockPath := filepath.Join(dir, "identity.lock")
	deadline := time.Now().Add(20 * time.Second)
	for {
		lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			lock.Close()
			defer os.Remove(lockPath)
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return installationIdentity{}, err
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > time.Minute {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return installationIdentity{}, errors.New("installation identity is locked by another process")
		}
		time.Sleep(50 * time.Millisecond)
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
			RuntimeID:      stableRuntimeID(stored.InstallationID),
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
		RuntimeID:      stableRuntimeID(stored.InstallationID),
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
