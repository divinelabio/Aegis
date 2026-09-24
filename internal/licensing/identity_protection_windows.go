//go:build windows

package licensing

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	privateKeyProtectionDPAPI           = "dpapi"
	privateKeyProtectionFilePermissions = "file_permissions"
	cryptProtectUIForbidden             = 0x1
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32            = windows.NewLazySystemDLL("crypt32.dll")
	cryptProtectData   = crypt32.NewProc("CryptProtectData")
	cryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	localFree          = kernel32.NewProc("LocalFree")
)

// protectInstallationPrivateKey uses a current-user DPAPI scope. Reading the
// state file alone is therefore insufficient to sign licence lease requests.
func protectInstallationPrivateKey(privateKey ed25519.PrivateKey) (string, string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", "", fmt.Errorf("invalid installation private key")
	}
	protected, err := cryptProtect(privateKey)
	if err != nil {
		return "", "", err
	}
	return base64.RawStdEncoding.EncodeToString(protected), privateKeyProtectionDPAPI, nil
}

func unprotectInstallationPrivateKey(encoded, protection string) (ed25519.PrivateKey, bool, error) {
	if protection == "" || protection == privateKeyProtectionFilePermissions {
		privateKey, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil || len(privateKey) != ed25519.PrivateKeySize {
			return nil, false, fmt.Errorf("invalid installation private key")
		}
		return ed25519.PrivateKey(privateKey), true, nil
	}
	if protection != privateKeyProtectionDPAPI {
		return nil, false, fmt.Errorf("unsupported installation private key protection %q", protection)
	}
	protected, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false, fmt.Errorf("decode protected installation private key: %w", err)
	}
	privateKey, err := cryptUnprotect(protected)
	if err != nil {
		return nil, false, fmt.Errorf("unprotect installation private key: %w", err)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("invalid unprotected installation private key")
	}
	return ed25519.PrivateKey(privateKey), false, nil
}

func cryptProtect(value []byte) ([]byte, error) {
	input := dataBlob{cbData: uint32(len(value)), pbData: &value[0]}
	var output dataBlob
	result, _, callErr := cryptProtectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0,
		0,
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&output)),
	)
	if result == 0 {
		return nil, fmt.Errorf("DPAPI protect installation private key: %w", callErr)
	}
	defer freeDataBlob(output)
	return append([]byte(nil), unsafe.Slice(output.pbData, int(output.cbData))...), nil
}

func cryptUnprotect(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("empty protected installation private key")
	}
	input := dataBlob{cbData: uint32(len(value)), pbData: &value[0]}
	var output dataBlob
	result, _, callErr := cryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0,
		0,
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&output)),
	)
	if result == 0 {
		return nil, fmt.Errorf("DPAPI unprotect installation private key: %w", callErr)
	}
	defer freeDataBlob(output)
	return append([]byte(nil), unsafe.Slice(output.pbData, int(output.cbData))...), nil
}

func freeDataBlob(blob dataBlob) {
	if blob.pbData != nil {
		_, _, _ = localFree.Call(uintptr(unsafe.Pointer(blob.pbData)))
	}
}
