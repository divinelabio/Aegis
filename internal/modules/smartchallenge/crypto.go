package smartchallenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// secretKey is the internal key used for signing cookies.
// It is generated on startup to ensure previous sessions are invalidated on restart,
// which is a good security practice for an in-memory protection system.
var secretKey atomic.Value

type TokenBinding struct {
	UserAgent     string
	FingerprintID string
	Purpose       string
}

type signedTokenPayload struct {
	Version         int    `json:"v"`
	IP              string `json:"ip"`
	Expiry          int64  `json:"exp"`
	Nonce           string `json:"nonce,omitempty"`
	UserAgentHash   string `json:"ua,omitempty"`
	FingerprintHash string `json:"fp,omitempty"`
	Purpose         string `json:"purpose,omitempty"`
}

var tokenNonceCounter atomic.Uint64

func init() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// Fallback (should never happen)
		key = []byte("aegis-fallback-secret-key-change-me")
	}
	secretKey.Store(key)
}

// SetSecretKey updates the internal key used for signing cookies.
// This should be called with a persistent config-driven key for multi-instance deployments.
func SetSecretKey(key []byte) {
	if len(key) > 0 {
		secretKey.Store(append([]byte(nil), key...))
	}
}

// GenerateSignature creates an HMAC-SHA256 signature for the data
func GenerateSignature(data string) string {
	key, _ := secretKey.Load().([]byte)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func GenerateBoundToken(ip string, ttlSeconds int, binding TokenBinding) string {
	expiry := time.Now().Add(time.Duration(ttlSeconds) * time.Second).Unix()
	payload := signedTokenPayload{
		Version:         3,
		IP:              ip,
		Expiry:          expiry,
		Nonce:           tokenNonce(),
		UserAgentHash:   shortHash(strings.TrimSpace(binding.UserAgent)),
		FingerprintHash: shortHash(strings.TrimSpace(binding.FingerprintID)),
		Purpose:         strings.TrimSpace(binding.Purpose),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		// signedTokenPayload contains only serializable fields. Fail closed rather
		// than issuing the retired pre-structured token format if that invariant
		// ever changes.
		return ""
	}

	payloadString := string(payloadBytes)
	sig := GenerateSignature(payloadString)
	token := fmt.Sprintf("%s|%s", payloadString, sig)
	return base64.URLEncoding.EncodeToString([]byte(token))
}

func tokenNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err == nil {
		return hex.EncodeToString(buf)
	}
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), tokenNonceCounter.Add(1))
}

func VerifyBoundToken(tokenString string, clientIP string, binding TokenBinding) bool {
	// Decode
	data, err := base64.URLEncoding.DecodeString(tokenString)
	if err != nil {
		return false
	}

	// Split payload|signature
	raw := string(data)
	splitAt := strings.LastIndex(raw, "|")
	if splitAt <= 0 || splitAt >= len(raw)-1 {
		return false
	}
	payload := raw[:splitAt]
	signature := raw[splitAt+1:]

	// Verify Signature
	expectedSig := GenerateSignature(payload)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return false
	}

	var structured signedTokenPayload
	if err := json.Unmarshal([]byte(payload), &structured); err != nil {
		return false
	}
	switch structured.Version {
	case 2:
	case 3:
		if !validTokenNonce(structured.Nonce) {
			return false
		}
	default:
		return false
	}
	if structured.IP != clientIP {
		return false
	}
	if time.Now().Unix() > structured.Expiry {
		return false
	}
	if structured.UserAgentHash != "" && structured.UserAgentHash != shortHash(strings.TrimSpace(binding.UserAgent)) {
		return false
	}
	if structured.FingerprintHash != "" && structured.FingerprintHash != shortHash(strings.TrimSpace(binding.FingerprintID)) {
		return false
	}
	if structured.Purpose != "" && strings.TrimSpace(binding.Purpose) != "" && structured.Purpose != strings.TrimSpace(binding.Purpose) {
		return false
	}
	return true
}

func validTokenNonce(value string) bool {
	nonce := strings.TrimSpace(value)
	if len(nonce) == 32 {
		_, err := hex.DecodeString(nonce)
		return err == nil
	}

	parts := strings.Split(nonce, "-")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	if _, err := strconv.ParseInt(parts[0], 10, 64); err != nil {
		return false
	}
	if _, err := strconv.ParseUint(parts[1], 10, 64); err != nil {
		return false
	}
	return true
}

func shortHash(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

// VerifyPoW checks if SHA256(salt + nonce) starts with 'difficulty' number of zeros
func VerifyPoW(salt, nonce string, difficulty int) bool {
	// Construct data
	data := salt + nonce
	hash := sha256.Sum256([]byte(data))
	hashStr := hex.EncodeToString(hash[:])

	// Create prefix
	prefix := strings.Repeat("0", difficulty)

	return strings.HasPrefix(hashStr, prefix)
}
