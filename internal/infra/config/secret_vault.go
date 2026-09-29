package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	ErrSecretResolution = errors.New("secret resolution failed")
	ErrInvalidSecretRef = errors.New("invalid secret reference")
)

const RedactedSecretPlaceholder = "********"

// ResolveSecretReference resolves a secret string by either expanding an env reference
// ("env:VAR_NAME") or returning an error if strict vault policy is violated.
func ResolveSecretReference(ref string, minLength int) (string, error) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return "", fmt.Errorf("%w: secret reference cannot be empty", ErrInvalidSecretRef)
	}

	if strings.HasPrefix(trimmed, "env:") {
		varName := strings.TrimPrefix(trimmed, "env:")
		if !validEnvVarName(varName) {
			return "", fmt.Errorf("%w: invalid environment variable name %q", ErrInvalidSecretRef, varName)
		}
		val, found := os.LookupEnv(varName)
		if !found || strings.TrimSpace(val) == "" {
			return "", fmt.Errorf("%w: environment variable %q is not set", ErrSecretResolution, varName)
		}
		val = strings.TrimSpace(val)
		if minLength > 0 && len(val) < minLength {
			return "", fmt.Errorf("%w: secret in %q must be at least %d characters (got %d)", ErrSecretResolution, varName, minLength, len(val))
		}
		return val, nil
	}

	// For legacy/direct secrets, ensure they meet minimum length requirements
	if minLength > 0 && len(trimmed) < minLength {
		return "", fmt.Errorf("%w: plaintext secret must be at least %d characters", ErrSecretResolution, minLength)
	}
	return trimmed, nil
}

// RedactSecret returns a masked representation of a secret string for safe logging and serialization.
func RedactSecret(secret string) string {
	if secret == "" {
		return ""
	}
	return RedactedSecretPlaceholder
}

func validEnvVarName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	first := name[0]
	if !(first == '_' || (first >= 'A' && first <= 'Z')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !(c == '_' || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
