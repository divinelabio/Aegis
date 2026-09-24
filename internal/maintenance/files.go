package maintenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Manifest struct {
	Generation string    `json:"generation"`
	SHA256     string    `json:"sha256"`
	Source     string    `json:"source"`
	UpdatedAt  time.Time `json:"updated_at"`
	Size       int64     `json:"size"`
}

func publish(destination string, data []byte, source string) (Manifest, error) {
	manifest := Manifest{Source: source, UpdatedAt: time.Now().UTC(), Size: int64(len(data))}
	sum := sha256.Sum256(data)
	manifest.SHA256 = hex.EncodeToString(sum[:])
	manifest.Generation = manifest.SHA256
	if current, err := os.ReadFile(destination); err == nil {
		currentSum := sha256.Sum256(current)
		if currentSum == sum {
			return manifest, writeManifest(destination, manifest)
		}
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return manifest, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".aegis-update-*")
	if err != nil {
		return manifest, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return manifest, err
	}
	if err := replaceFile(tmpPath, destination); err != nil {
		return manifest, fmt.Errorf("publish %s: %w", destination, err)
	}
	if err := writeManifest(destination, manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func writeManifest(destination string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestPath := destination + ".manifest.json"
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".aegis-manifest-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return replaceFile(tmpPath, manifestPath)
}

func withLock(destination string, fn func() error) error {
	lockPath := destination + ".update.lock"
	if info, err := os.Stat(lockPath); err == nil && time.Since(info.ModTime()) > time.Hour {
		_ = os.Remove(lockPath)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("another updater is active for %s: %w", destination, err)
	}
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	_ = f.Close()
	defer os.Remove(lockPath)
	return fn()
}
