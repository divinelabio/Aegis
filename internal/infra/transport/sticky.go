package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// StickySessionManager creates opaque, authenticated target identifiers. A
// cookie never contains the Origin URL, even in encoded form.
type StickySessionManager struct {
	secretKey []byte
}

func NewStickySessionManager(secret string) *StickySessionManager {
	if secret == "" {
		secretBytes := make([]byte, 32)
		if _, err := rand.Read(secretBytes); err != nil {
			panic(fmt.Sprintf("generate sticky-session secret: %v", err))
		}
		return &StickySessionManager{secretKey: secretBytes}
	}
	return &StickySessionManager{secretKey: []byte(secret)}
}

// StickyCookieName returns a group-scoped default name so two Origin pools on
// the same public host cannot overwrite one another's affinity cookie.
func StickyCookieName(groupName, configured string) string {
	if configured = strings.TrimSpace(configured); configured != "" {
		return configured
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(groupName)))
	return "aegis_sticky_" + base64.RawURLEncoding.EncodeToString(digest[:9])
}

func stickyTargetID(groupName, targetURL string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(groupName) + "\x00" + targetURL))
	return base64.RawURLEncoding.EncodeToString(digest[:18])
}

// GenerateCookieForGroup creates an opaque, signed target identifier.
func (m *StickySessionManager) GenerateCookieForGroup(groupName, targetURL string) string {
	payload := "v1." + stickyTargetID(groupName, targetURL)
	mac := hmac.New(sha256.New, m.secretKey)
	mac.Write([]byte(strings.TrimSpace(groupName)))
	mac.Write([]byte{0})
	mac.Write([]byte(payload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + signature
}

// ValidateCookieForGroup returns the opaque target identifier when the cookie
// authenticates for this exact group.
func (m *StickySessionManager) ValidateCookieForGroup(groupName, value string) string {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != "v1" || parts[1] == "" || parts[2] == "" {
		return ""
	}
	payload := parts[0] + "." + parts[1]
	providedSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, m.secretKey)
	mac.Write([]byte(strings.TrimSpace(groupName)))
	mac.Write([]byte{0})
	mac.Write([]byte(payload))
	if !hmac.Equal(providedSignature, mac.Sum(nil)) {
		return ""
	}
	return parts[1]
}

// GenerateCookie is retained for package compatibility and produces the same
// opaque format in the empty group namespace.
func (m *StickySessionManager) GenerateCookie(targetURL string) string {
	return m.GenerateCookieForGroup("", targetURL)
}

// ValidateCookie validates a compatibility cookie in the empty namespace.
func (m *StickySessionManager) ValidateCookie(value string) string {
	return m.ValidateCookieForGroup("", value)
}

// SelectStickyTarget tries to find a healthy target based on a group-scoped
// affinity cookie.
func (g *UpstreamGroup) SelectStickyTarget(req *http.Request, mgr *StickySessionManager) *Target {
	if !g.Sticky.Enabled || req == nil || mgr == nil {
		return nil
	}

	cookie, err := req.Cookie(StickyCookieName(g.Name, g.Sticky.Cookie))
	if err != nil {
		return nil
	}

	targetID := mgr.ValidateCookieForGroup(g.Name, cookie.Value)
	if targetID == "" {
		return nil
	}

	for _, target := range g.Targets {
		if stickyTargetID(g.Name, target.URL.String()) == targetID {
			if target.healthy.Load() {
				return target
			}
			return nil
		}
	}
	return nil
}

func (g *UpstreamGroup) stickyCookieMatches(req *http.Request, mgr *StickySessionManager, targetURL string) bool {
	if req == nil || mgr == nil {
		return false
	}
	cookie, err := req.Cookie(StickyCookieName(g.Name, g.Sticky.Cookie))
	if err != nil {
		return false
	}
	return mgr.ValidateCookieForGroup(g.Name, cookie.Value) == stickyTargetID(g.Name, targetURL)
}
