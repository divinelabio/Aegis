//go:build !windows

package licensing

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// Unix-like platforms rely on the private state directory and file modes set
// by securePrivatePath. Windows uses DPAPI in the platform-specific file.
const privateKeyProtectionFilePermissions = "file_permissions"

func protectInstallationPrivateKey(privateKey ed25519.PrivateKey) (string, string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", "", fmt.Errorf("invalid installation private key")
	}
	return base64.RawStdEncoding.EncodeToString(privateKey), privateKeyProtectionFilePermissions, nil
}

func unprotectInstallationPrivateKey(encoded, protection string) (ed25519.PrivateKey, bool, error) {
	if protection != "" && protection != privateKeyProtectionFilePermissions {
		return nil, false, fmt.Errorf("unsupported installation private key protection %q", protection)
	}
	privateKey, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("invalid installation private key")
	}
	return ed25519.PrivateKey(privateKey), protection == "", nil
}
