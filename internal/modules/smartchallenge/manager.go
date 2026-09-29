package smartchallenge

import (
	"encoding/json"
	"fmt"
	htmlstd "html"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/requestctx"
	"github.com/divinelab-io/aegis/internal/modules/captcha"
	"github.com/divinelab-io/aegis/internal/modules/fingerprint"
)

// Config holds the module configuration
type Config struct {
	Enabled            bool   `json:"enabled" mapstructure:"enabled"`
	Mode               string `json:"mode" mapstructure:"mode"` // "managed", "captcha", "hybrid"
	Preset             string `json:"preset" mapstructure:"preset"`
	InvisibleEnabled   bool   `json:"invisible_enabled" mapstructure:"invisible_enabled"`
	ManagedEnabled     bool   `json:"managed_enabled" mapstructure:"managed_enabled"`
	InteractiveEnabled bool   `json:"interactive_enabled" mapstructure:"interactive_enabled"`
	InteractiveStyle   string `json:"interactive_style" mapstructure:"interactive_style"`
	CaptchaEnabled     bool   `json:"captcha_enabled" mapstructure:"captcha_enabled"`
	EscalationPolicy   string `json:"escalation_policy" mapstructure:"escalation_policy"`
	CooldownSeconds    int    `json:"cooldown_seconds" mapstructure:"cooldown_seconds"`
	MaxFailures        int    `json:"max_failures" mapstructure:"max_failures"`
	FailureAction      string `json:"failure_action" mapstructure:"failure_action"`
	Theme              string `json:"theme" mapstructure:"theme"` // "dark", "light"
	CustomTitle        string `json:"custom_title" mapstructure:"custom_title"`
	CustomMessage      string `json:"custom_message" mapstructure:"custom_message"`
	CookieTTL          int    `json:"cookie_ttl" mapstructure:"cookie_ttl"`         // Seconds
	PoWDifficulty      int    `json:"pow_difficulty" mapstructure:"pow_difficulty"` // e.g. 4
}

const (
	InteractiveStyleHold     = "hold"
	InteractiveStyleClick    = "click"
	InteractiveStyleSlide    = "slide"
	InteractiveStyleSequence = "sequence"
	InteractiveStyleMatch    = "match"
)

// Manager handles the Smart Challenge logic logic
type Manager struct {
	config Config
	mu     sync.RWMutex

	proofMu        sync.Mutex
	consumedProofs map[string]time.Time
	proofOrder     []consumedProof
}

type consumedProof struct {
	key       string
	expiresAt time.Time
}

const (
	challengeSubmissionField = "aegis_challenge_submission"
	challengeSubmissionValue = "1"
	consumedProofLimit       = 8192
	consumedProofTTL         = 10 * time.Minute
)

// SubmissionResult describes the result of a challenge form/API submission.
type SubmissionResult struct {
	Attempted          bool
	Passed             bool
	ChallengeType      string
	Reason             string
	FingerprintID      string
	FingerprintScore   int
	FingerprintReasons []string
}

var (
	instance *Manager
	once     sync.Once
)

// GetManager returns the singleton instance
func GetManager() *Manager {
	once.Do(func() {
		instance = NewManager()
	})
	return instance
}

// NewManager returns an isolated challenge manager. Sections with independent
// configuration ownership should use their own manager instead of mutating the
// process-global compatibility instance.
func NewManager() *Manager {
	return &Manager{
		config: Config{
			Enabled:            true,
			Mode:               "managed",
			Preset:             "balanced",
			InvisibleEnabled:   true,
			ManagedEnabled:     true,
			InteractiveEnabled: true,
			InteractiveStyle:   InteractiveStyleHold,
			CaptchaEnabled:     false,
			EscalationPolicy:   "progressive",
			CooldownSeconds:    1800,
			MaxFailures:        3,
			FailureAction:      "block",
			Theme:              "dark",
			CustomTitle:        "Checking your browser...",
			CustomMessage:      "Please wait a moment while we verify your request.",
			CookieTTL:          3600,
		},
		consumedProofs: make(map[string]time.Time),
	}
}

// UpdateConfig updates the manager configuration
func (m *Manager) UpdateConfig(cfg Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg.applyDefaults()
	m.config = cfg
}

// GetConfig returns the current config
func (m *Manager) GetConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

func (c *Config) applyDefaults() {
	if c.Mode == "" || c.Mode == "js" || c.Mode == "js_challenge" {
		c.Mode = "managed"
	}
	if c.Preset == "" {
		c.Preset = "balanced"
	}
	if c.EscalationPolicy == "" {
		c.EscalationPolicy = "progressive"
	}
	if c.CooldownSeconds <= 0 {
		c.CooldownSeconds = 1800
	}
	if c.FailureAction == "" {
		c.FailureAction = "block"
	}
	if c.MaxFailures <= 0 {
		c.MaxFailures = 3
	}
	if c.CookieTTL <= 0 {
		c.CookieTTL = 3600
	}
	if c.Theme == "" {
		c.Theme = "dark"
	}
	if c.CustomTitle == "" {
		c.CustomTitle = "Checking your browser..."
	}
	if c.CustomMessage == "" {
		c.CustomMessage = "Please wait a moment while we verify your request."
	}
	c.InteractiveStyle = normalizeInteractiveStyle(c.InteractiveStyle)
	if !c.InvisibleEnabled && !c.ManagedEnabled && !c.InteractiveEnabled && !c.CaptchaEnabled {
		c.InvisibleEnabled = true
		c.ManagedEnabled = true
		c.InteractiveEnabled = true
		c.CaptchaEnabled = captchaConfigured()
	}
	if !captchaConfigured() {
		c.CaptchaEnabled = false
		if c.Mode == "captcha" || c.Mode == "hybrid" {
			c.Mode = "managed"
		}
	}
	if !c.InvisibleEnabled && !c.ManagedEnabled && !c.InteractiveEnabled && !c.CaptchaEnabled {
		c.Enabled = false
	}
}

func normalizeInteractiveStyle(style string) string {
	switch style {
	case InteractiveStyleClick, InteractiveStyleSlide, InteractiveStyleSequence, InteractiveStyleMatch:
		return style
	default:
		return InteractiveStyleHold
	}
}

func interactiveTokenPurpose(style string) string {
	style = normalizeInteractiveStyle(style)
	if style == InteractiveStyleHold {
		return "interactive"
	}
	return "interactive:" + style
}

func captchaConfigured() bool {
	cfg := captcha.GetManager().GetConfig()
	return cfg.Enabled && cfg.SiteKey != ""
}

func firstEnabledChallenge(cfg Config, modes ...string) string {
	for _, mode := range modes {
		switch normalizeChallengeMode(mode) {
		case "invisible_challenge":
			if cfg.InvisibleEnabled {
				return "invisible_challenge"
			}
		case "managed_challenge":
			if cfg.ManagedEnabled {
				return "managed_challenge"
			}
		case "interactive_challenge":
			if cfg.InteractiveEnabled {
				return "interactive_challenge"
			}
		case "captcha":
			if cfg.CaptchaEnabled {
				return "captcha"
			}
		}
	}
	return "managed_challenge"
}

// CheckCookie checks if the user has a valid challenge cookie
func (m *Manager) CheckCookie(r *http.Request, clientIP string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.config.Enabled {
		return false
	}

	c, err := r.Cookie("aegis_challenge")
	if err != nil {
		return false
	}

	// Bind clearance to the signed SDK identity when the Bot middleware has
	// supplied one. Requests without SDK evidence remain bound to IP and UA.
	return VerifyBoundToken(c.Value, clientIP, requestBinding(r, trustedFingerprint(r), "cookie"))
}

func trustedFingerprint(r *http.Request) string {
	return r.Header.Get("X-Aegis-Fingerprint")
}

// consumeProof atomically marks a short-lived challenge proof as used. The
// bounded cache prevents a valid proof from being replayed during its token TTL.
func (m *Manager) consumeProof(proof string) bool {
	if proof == "" {
		return false
	}

	now := time.Now()
	key := shortHash(proof)
	m.proofMu.Lock()
	defer m.proofMu.Unlock()

	if m.consumedProofs == nil {
		m.consumedProofs = make(map[string]time.Time)
	}
	if expiresAt, exists := m.consumedProofs[key]; exists && expiresAt.After(now) {
		return false
	}

	for len(m.proofOrder) > 0 {
		oldest := m.proofOrder[0]
		if oldest.expiresAt.After(now) && len(m.consumedProofs) < consumedProofLimit {
			break
		}
		m.proofOrder = m.proofOrder[1:]
		if current, exists := m.consumedProofs[oldest.key]; exists && current.Equal(oldest.expiresAt) {
			delete(m.consumedProofs, oldest.key)
		}
	}

	expiresAt := now.Add(consumedProofTTL)
	m.consumedProofs[key] = expiresAt
	m.proofOrder = append(m.proofOrder, consumedProof{key: key, expiresAt: expiresAt})
	return true
}

// DetermineStrategy calculates the best challenge mode based on the score and global config
func (m *Manager) DetermineStrategy(score int) string {
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()

	mode := cfg.Mode
	if cfg.EscalationPolicy == "fixed" {
		switch mode {
		case "invisible", "invisible_challenge":
			return firstEnabledChallenge(cfg, "invisible_challenge", "managed_challenge")
		case "interactive", "interactive_challenge":
			return firstEnabledChallenge(cfg, "interactive_challenge", "managed_challenge")
		case "captcha":
			return firstEnabledChallenge(cfg, "captcha", "managed_challenge")
		default:
			return firstEnabledChallenge(cfg, "managed_challenge")
		}
	}

	if cfg.Preset == "low_friction" && score < 70 {
		return firstEnabledChallenge(cfg, "invisible_challenge", "managed_challenge", "interactive_challenge", "captcha")
	}
	if cfg.Preset == "containment" && score >= 65 {
		return firstEnabledChallenge(cfg, "interactive_challenge", "captcha", "managed_challenge", "invisible_challenge")
	}

	// Hybrid Logic
	if mode == "hybrid" {
		if score >= 80 {
			return firstEnabledChallenge(cfg, "captcha", "interactive_challenge", "managed_challenge")
		}
		if score >= 60 {
			return firstEnabledChallenge(cfg, "interactive_challenge", "managed_challenge", "captcha")
		}
		if score >= 40 {
			return firstEnabledChallenge(cfg, "managed_challenge", "invisible_challenge")
		}
		return firstEnabledChallenge(cfg, "invisible_challenge", "managed_challenge")
	}

	// Always Captcha
	if mode == "captcha" {
		return firstEnabledChallenge(cfg, "captcha", "interactive_challenge", "managed_challenge")
	}

	// Default / Managed
	if score >= 85 {
		return firstEnabledChallenge(cfg, "captcha", "interactive_challenge", "managed_challenge")
	}
	if score >= 65 {
		return firstEnabledChallenge(cfg, "interactive_challenge", "managed_challenge", "captcha")
	}
	if score >= 45 {
		return firstEnabledChallenge(cfg, "managed_challenge", "invisible_challenge")
	}
	return firstEnabledChallenge(cfg, "invisible_challenge", "managed_challenge")
}

// ServeChallenge renders the challenge page for the specific mode
func (m *Manager) ServeChallenge(w http.ResponseWriter, r *http.Request, mode string) {
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()
	if !cfg.Enabled {
		http.Error(w, "Challenge protection is disabled", http.StatusForbidden)
		return
	}

	mode = normalizeChallengeMode(mode)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeChallengeRequired(w, r, mode)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable) // 503 Service Unavailable (Standard for Interstitials)

	// Content Generation
	var bodyContent string
	clientIP := clientIPFromRequest(r)

	// Mode: Captcha
	if mode == "captcha" {
		// Fallback: If captcha is not configured/enabled, revert to managed/js mode
		capCfg := captcha.GetManager().GetConfig()
		if !capCfg.Enabled || capCfg.ProviderName == "none" || capCfg.SiteKey == "" {
			mode = "managed_challenge"
		}
	}

	switch mode {
	case "captcha":
		widget := captcha.GetManager().RenderWidget()
		bodyContent = fmt.Sprintf(`
            <h1 id="challenge-title">Security Check</h1>
            <p>%s</p>
            <form method="POST" action="%s" class="challenge-form">
                <div class="captcha-widget">%s</div>
                <button type="submit">Verify</button>
				<input type="hidden" name="aegis_challenge_submission" value="1">
                <input type="hidden" name="challenge_type" value="captcha">
            </form>
        `, "Please complete the captcha to verify you are a human.", htmlstd.EscapeString(r.RequestURI), widget)
	case "interactive_challenge":
		style := normalizeInteractiveStyle(cfg.InteractiveStyle)
		issuedToken := GenerateBoundToken(clientIP, 300, requestBinding(r, "", interactiveTokenPurpose(style)))
		bodyContent = renderInteractiveChallengeByStyle(htmlstd.EscapeString(r.RequestURI), issuedToken, style)
	case "invisible_challenge":
		saltToken := GenerateBoundToken(clientIP, 300, requestBinding(r, "", "pow"))
		bodyContent = renderInvisibleChallengeBody(saltToken, challengeProofDifficulty(cfg.PoWDifficulty, mode))
	default:
		title := cfg.CustomTitle
		if title == "" {
			title = "Checking your browser..."
		}

		msg := cfg.CustomMessage
		if msg == "" {
			msg = "Please wait a moment while we verify your request."
		}

		// PoW Setup
		difficulty := cfg.PoWDifficulty
		difficulty = challengeProofDifficulty(difficulty, mode)
		saltToken := GenerateBoundToken(clientIP, 300, requestBinding(r, "", "pow"))

		bodyContent = fmt.Sprintf(`
	        <div class="spinner"></div>
	        <h1 id="challenge-title">%s</h1>
	        <p>%s</p>
	        <div id="status" class="status status-live" role="status" aria-live="polite">Analyzing request</div>
	        <script>
	            (async function() {
	                const salt = "%s";
	                const difficulty = %d;
	                const status = document.getElementById("status");

	                async function solvePoW(salt, diff) {
	                    const encoder = new TextEncoder();
	                    const prefix = "0".repeat(diff);
	                    let nonce = 0;
	                    while(true) {
	                        const str = salt + nonce;
	                        const data = encoder.encode(str);
	                        const hashBuf = await crypto.subtle.digest("SHA-256", data);
	                        // Convert only first few bytes to hex for prefix check (optimization)
	                        const hashArr = Array.from(new Uint8Array(hashBuf));
	                        const hashHex = hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
	                        if (hashHex.startsWith(prefix)) {
	                            return nonce;
	                        }
	                        nonce++;
	                        if (nonce %% 5000 === 0) {
	                             status.innerText = "Verifying your browser";
	                             await new Promise(r => setTimeout(r, 0));
	                        }
	                    }
	                }

	                try {
	                    // 1. Solve PoW
	                    const nonce = await solvePoW(salt, difficulty);

	                    // 2. Collect Signals
						// Injected Fingerprint Collector
						var signalsJSON = %s;

	                    // 3. Send Proof
	                    var form = new FormData();
	                    form.append("aegis_challenge_submission", "1");
	                    form.append("challenge_type", "js_proof");
	                    form.append("signals", signalsJSON);
	                    form.append("pow_salt", salt);
	                    form.append("pow_nonce", nonce);

	                    fetch(window.location.href, {
	                        method: "POST",
	                        body: form
	                    }).then(function(response) {
	                        if (response.redirected) {
	                            window.location.href = response.url;
	                        } else if (response.ok) {
	                            window.location.reload();
	                        } else {
	                             status.innerText = "Verification failed.";
	                             status.classList.add("is-error");
	                        }
	                    });
	                } catch(e) {
	                    status.innerText = "Verification could not be completed.";
	                    status.classList.add("is-error");
	                }
	            })();
	        </script>
	    `, htmlstd.EscapeString(title), htmlstd.EscapeString(msg), saltToken, difficulty, fingerprint.NewCollector(fingerprint.Config{
			CollectCanvas:   true,
			CollectWebGL:    true,
			CollectBehavior: true,
			CheckHeadless:   true,
		}).GenerateScript())
	}

	// Theme styles mirror the Aegis operator surfaces: flat, bordered, and restrained.
	var themeStyle string
	if cfg.Theme == "light" {
		themeStyle = `
			color-scheme: light;
			--page-bg: #f6f7f9;
			--surface: #f6f7f9;
			--surface-muted: #eef1f4;
			--line: #d8dde5;
			--line-soft: #e5e8ed;
			--text: #171b22;
			--text-muted: #606a78;
			--text-dim: #7b8695;
			--primary: #f97316;
			--primary-hover: #ea580c;
			--primary-soft: rgba(249, 115, 22, 0.18);
			--danger: #c2410c;
			--focus-ring: rgba(249, 115, 22, 0.28);
		`
	} else {
		themeStyle = `
			color-scheme: dark;
			--page-bg: #11141a;
			--surface: #11141a;
			--surface-muted: #0d1015;
			--line: #2a3039;
			--line-soft: #20252d;
			--text: #f4f6f8;
			--text-muted: #a2aab6;
			--text-dim: #737d8c;
			--primary: #f97316;
			--primary-hover: #fb923c;
			--primary-soft: rgba(249, 115, 22, 0.2);
			--danger: #f87171;
			--focus-ring: rgba(249, 115, 22, 0.3);
		`
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check | Aegis</title>
    <style>
        :root {
            %s
        }
        * {
            box-sizing: border-box;
        }
        html {
            min-height: 100%%;
            background: var(--page-bg);
        }
        body {
            margin: 0;
            min-height: 100vh;
            min-height: 100svh;
            padding: 24px;
            background: var(--page-bg);
            color: var(--text);
            display: grid;
            place-items: center;
            overflow-x: hidden;
            font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            -webkit-font-smoothing: antialiased;
            text-rendering: optimizeLegibility;
        }
        .challenge-shell {
            width: min(100%%, 520px);
        }
        .container {
            width: 100%%;
            position: relative;
        }
        .challenge-content {
            padding: 36px 32px;
            text-align: center;
        }
        h1 {
            margin: 0 0 10px;
            color: var(--text) !important;
            font-size: 22px;
            font-weight: 700;
            line-height: 1.25;
            letter-spacing: -0.025em;
        }
        p {
            max-width: 390px;
            margin: 0 auto;
            color: var(--text-muted);
            font-size: 14px;
            line-height: 1.55;
        }
        .spinner {
            width: 46px;
            height: 46px;
            margin: 0 auto 26px;
            border: 2px solid var(--primary-soft);
            border-radius: 50%%;
            border-top-color: var(--primary);
            box-shadow: 0 0 0 8px rgba(249, 115, 22, 0.05);
            animation: spin 950ms linear infinite;
        }
        @keyframes spin { 100%% { transform: rotate(360deg); } }
        .status {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            margin-top: 20px;
            color: var(--text-dim);
            font-size: 12px;
            line-height: 1.4;
        }
        .status::before {
            content: "";
            width: 5px;
            height: 5px;
            flex: 0 0 auto;
            border-radius: 50%%;
            background: var(--primary);
        }
        .status.is-error {
            color: var(--danger);
        }
        .status.is-error::before {
            background: var(--danger);
        }
        .status-live:not(.is-error) {
            position: absolute;
            width: 1px;
            height: 1px;
            margin: -1px;
            padding: 0;
            overflow: hidden;
            clip: rect(0 0 0 0);
            clip-path: inset(50%%);
            white-space: nowrap;
        }
        .challenge-form {
            margin-top: 24px;
        }
        .captcha-widget {
            display: flex;
            justify-content: center;
            margin-bottom: 18px;
        }
        button {
            min-height: 42px;
            min-width: 128px;
            padding: 10px 20px !important;
            border: 1px solid var(--primary);
            border-radius: 4px !important;
            background: var(--primary) !important;
            color: white !important;
            font: inherit;
            font-size: 13px;
            font-weight: 700 !important;
            cursor: pointer;
            transition: background-color 140ms ease, border-color 140ms ease, transform 140ms ease;
        }
        button:hover {
            border-color: var(--primary-hover);
            background: var(--primary-hover) !important;
        }
        button:active {
            transform: translateY(1px);
        }
        button:focus-visible {
            outline: 3px solid var(--focus-ring);
            outline-offset: 2px;
        }
        #interactive-hold-button {
            touch-action: none;
            user-select: none;
        }
        .challenge-hold-button {
            display: grid;
            width: min(100%%, 300px);
            min-width: 0;
            min-height: 60px;
            grid-template-columns: 28px minmax(0, 1fr) auto;
            align-items: center;
            gap: 11px;
            padding: 10px 13px !important;
            border: 1px solid var(--line);
            border-radius: 5px !important;
            background: var(--surface-muted) !important;
            color: var(--text) !important;
            text-align: left;
            box-shadow: inset 3px 0 0 transparent;
        }
        .challenge-hold-button:hover,
        .challenge-hold-button.is-pressed {
            border-color: var(--primary);
            background: var(--surface-muted) !important;
            box-shadow: inset 3px 0 0 var(--primary);
        }
        .challenge-hold-button:active {
            transform: none;
        }
        .challenge-hold-mark {
            position: relative;
            display: inline-flex;
            width: 25px;
            height: 25px;
            align-items: center;
            justify-content: center;
            border: 1px solid var(--line);
            border-radius: 4px;
            background: var(--surface);
        }
        .challenge-hold-mark::before,
        .challenge-hold-mark::after {
            content: "";
            position: absolute;
            width: 9px;
            height: 2px;
            border-radius: 999px;
            background: var(--primary);
        }
        .challenge-hold-mark::after {
            width: 2px;
            height: 9px;
        }
        .challenge-hold-copy {
            display: grid;
            min-width: 0;
            gap: 3px;
        }
        .challenge-hold-copy strong {
            overflow: hidden;
            color: inherit;
            font-size: 12px;
            font-weight: 700;
            line-height: 1.2;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .challenge-hold-copy small {
            overflow: hidden;
            color: var(--text-dim);
            font-size: 10px;
            line-height: 1.3;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .challenge-hold-arrow {
            color: var(--primary);
            font-size: 23px;
            font-weight: 400;
            line-height: 1;
        }
        .challenge-click-button {
            display: grid;
            width: min(100%%, 300px);
            min-width: 0;
            min-height: 60px;
            grid-template-columns: 28px minmax(0, 1fr) auto;
            align-items: center;
            gap: 11px;
            padding: 10px 13px !important;
            border: 1px solid var(--line);
            border-radius: 5px !important;
            background: var(--surface-muted) !important;
            color: var(--text) !important;
            text-align: left;
        }
        .challenge-click-button:hover,
        .challenge-click-button.is-complete {
            border-color: var(--primary);
            background: var(--surface-muted) !important;
        }
        .challenge-click-check {
            position: relative;
            display: inline-flex;
            width: 25px;
            height: 25px;
            align-items: center;
            justify-content: center;
            border: 1px solid var(--line);
            border-radius: 3px;
            background: var(--surface);
        }
        .challenge-click-check::before {
            content: "";
            width: 11px;
            height: 6px;
            border-bottom: 2px solid var(--primary);
            border-left: 2px solid var(--primary);
            opacity: 0;
            transform: translateY(-1px) rotate(-45deg) scale(0.7);
            transition: opacity 140ms ease, transform 140ms ease;
        }
        .challenge-click-button.is-complete .challenge-click-check::before {
            opacity: 1;
            transform: translateY(-1px) rotate(-45deg) scale(1);
        }
        .challenge-click-copy {
            display: grid;
            min-width: 0;
            gap: 3px;
        }
        .challenge-click-copy strong {
            color: inherit;
            font-size: 12px;
            font-weight: 700;
            line-height: 1.2;
        }
        .challenge-click-copy small {
            color: var(--text-dim);
            font-size: 10px;
            line-height: 1.3;
        }
        .challenge-click-brand {
            color: var(--text-dim);
            font-size: 9px;
            font-weight: 750;
            letter-spacing: 0.08em;
        }
        .challenge-slide-control {
            position: relative;
            width: min(100%%, 320px);
            height: 58px;
            margin: 0 auto;
            overflow: hidden;
            border: 1px solid var(--line);
            border-radius: 5px;
            background: var(--surface-muted);
            color: var(--text);
            touch-action: none;
            user-select: none;
        }
        .challenge-slide-control:focus-visible {
            outline: 3px solid var(--focus-ring);
            outline-offset: 2px;
        }
        .challenge-slide-control.is-active,
        .challenge-slide-control.is-complete {
            border-color: var(--primary);
        }
        .challenge-slide-fill {
            position: absolute;
            inset: 0 auto 0 0;
            width: 0;
            background: var(--primary-soft);
        }
        .challenge-slide-thumb {
            position: absolute;
            top: 5px;
            left: 5px;
            z-index: 2;
            display: inline-flex;
            width: 46px;
            height: 46px;
            align-items: center;
            justify-content: center;
            border: 1px solid var(--primary);
            border-radius: 4px;
            background: var(--surface);
            color: var(--primary);
            cursor: grab;
            transition: box-shadow 140ms ease;
        }
        .challenge-slide-control.is-active .challenge-slide-thumb {
            cursor: grabbing;
            box-shadow: 0 0 0 3px var(--primary-soft);
        }
        .challenge-slide-thumb svg,
        .challenge-slide-end svg {
            width: 18px;
            height: 18px;
            fill: none;
            stroke: currentColor;
            stroke-linecap: round;
            stroke-linejoin: round;
            stroke-width: 2;
        }
        .challenge-slide-copy {
            position: absolute;
            inset: 0 54px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.01em;
            pointer-events: none;
        }
        .challenge-slide-end {
            position: absolute;
            top: 0;
            right: 13px;
            bottom: 0;
            display: flex;
            align-items: center;
            color: var(--text-dim);
            pointer-events: none;
        }
        .challenge-slide-control.is-complete .challenge-slide-end {
            color: var(--primary);
        }
        .challenge-sequence-control,
        .challenge-match-control {
            width: min(100%%, 310px);
            margin: 0 auto;
            padding: 13px;
            border: 1px solid var(--line);
            border-radius: 5px;
            background: var(--surface-muted);
            text-align: left;
        }
        .challenge-sequence-label,
        .challenge-match-prompt {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 11px;
            color: var(--text-muted);
            font-size: 10px;
            font-weight: 650;
            letter-spacing: 0.02em;
        }
        .challenge-sequence-steps,
        .challenge-match-options {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 8px;
        }
        .challenge-sequence-steps button,
        .challenge-match-options button {
            min-width: 0;
            min-height: 44px;
            padding: 0 !important;
            border: 1px solid var(--line);
            border-radius: 4px !important;
            background: var(--surface) !important;
            color: var(--text-muted) !important;
            font-size: 12px;
            font-weight: 750 !important;
        }
        .challenge-sequence-steps button:hover,
        .challenge-match-options button:hover {
            border-color: var(--primary);
            color: var(--primary) !important;
        }
        .challenge-sequence-steps button.is-complete,
        .challenge-match-options button.is-complete {
            border-color: var(--primary);
            background: var(--primary-soft) !important;
            color: var(--primary) !important;
        }
        .challenge-sequence-steps button.is-wrong,
        .challenge-match-options button.is-wrong {
            border-color: var(--danger);
            color: var(--danger) !important;
        }
        .challenge-match-prompt strong {
            display: inline-flex;
            width: 30px;
            height: 30px;
            align-items: center;
            justify-content: center;
            border: 1px solid var(--primary);
            border-radius: 4px;
            color: var(--primary);
            font-size: 13px;
        }
        .challenge-match-options button {
            font-size: 15px;
        }
        .footer {
            margin-top: 24px;
            color: var(--text-dim);
            font-size: 11px;
            line-height: 1.35;
            text-align: center;
        }
        .footer strong {
            color: var(--text-muted);
            font-weight: 650;
        }
        @media (max-width: 560px) {
            body {
                padding: 14px;
            }
            .challenge-content {
                padding: 32px 20px;
            }
            h1 {
                font-size: 20px;
            }
        }
        @media (prefers-reduced-motion: reduce) {
            .spinner {
                animation-duration: 1.8s;
            }
            button {
                transition: none;
            }
        }
    </style>
</head>
<body>
    <main class="challenge-shell">
        <section class="container" aria-labelledby="challenge-title">
            <div class="challenge-content">
                %s
            </div>
            <footer class="footer">
                DDoS Protection by <strong>Aegis</strong>
            </footer>
        </section>
    </main>
</body>
</html>`, themeStyle, bodyContent)

	fmt.Fprint(w, html)
}

func writeChallengeRequired(w http.ResponseWriter, r *http.Request, mode string) {
	challengeURL := r.URL.RequestURI()
	if challengeURL == "" {
		challengeURL = "/"
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Aegis-Challenge", mode)
	w.WriteHeader(http.StatusPreconditionRequired)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":                  "challenge_required",
		"challenge_type":         mode,
		"challenge_url":          challengeURL,
		"retry_original_request": true,
	})
}

// HandleSubmission checks for challenge response submission
func (m *Manager) HandleSubmission(w http.ResponseWriter, r *http.Request) bool {
	handled, _ := m.HandleSubmissionResult(w, r)
	return handled
}

// HandleSubmissionResult checks a challenge response and returns telemetry context.
func (m *Manager) HandleSubmissionResult(w http.ResponseWriter, r *http.Request) (bool, SubmissionResult) {
	result := SubmissionResult{}
	if r.Method != http.MethodPost {
		return false, result
	}
	m.mu.RLock()
	enabled := m.config.Enabled
	m.mu.RUnlock()
	if !enabled || r.FormValue(challengeSubmissionField) != challengeSubmissionValue {
		return false, result
	}

	challengeType := r.FormValue("challenge_type")
	if challengeType == "" {
		return false, result
	}
	result.Attempted = true
	result.ChallengeType = normalizeChallengeMode(challengeType)

	clientIP := clientIPFromRequest(r)

	isValid := false

	// Case 1: JS Proof
	if challengeType == "js_proof" || result.ChallengeType == "managed_challenge" || result.ChallengeType == "invisible_challenge" {
		salt := r.FormValue("pow_salt")
		nonce := r.FormValue("pow_nonce")
		signals := r.FormValue("signals")

		if salt == "" || nonce == "" || signals == "" {
			result.Reason = "missing proof fields"
		} else {
			// 1. Verify Salt Integrity (It's a signed token bound to IP)
			if VerifyBoundToken(salt, clientIP, requestBinding(r, "", "pow")) {
				m.mu.RLock()
				difficulty := challengeProofDifficulty(m.config.PoWDifficulty, result.ChallengeType)
				m.mu.RUnlock()

				// 2. Verify PoW Solution
				if VerifyPoW(salt, nonce, difficulty) {
					if !m.consumeProof(salt) {
						result.Reason = "proof already used"
					} else {
						// 3. Verify Signals with Fingerprint Analyzer
						analyzer := fingerprint.NewAnalyzer()
						fpResult := analyzer.Analyze(signals, r.UserAgent())
						result.FingerprintID = fpResult.Hash
						result.FingerprintScore = fpResult.Score
						result.FingerprintReasons = append([]string(nil), fpResult.Inconsistencies...)

						// Block if highly suspicious (e.g. headless or consistency mismatch)
						scoreLimit := 80
						if result.ChallengeType == "managed_challenge" {
							scoreLimit = 70
						}
						if fpResult.Score < scoreLimit {
							isValid = true
						} else {
							result.Reason = "fingerprint signals remained suspicious"
						}
					}
				} else {
					result.Reason = "invalid proof of work"
				}
			} else {
				result.Reason = "invalid or expired proof salt"
			}
		}
	}

	if result.ChallengeType == "interactive_challenge" {
		token := r.FormValue("interactive_token")
		holdMillis := r.FormValue("hold_duration")
		signals := r.FormValue("signals")
		style := normalizeInteractiveStyle(r.FormValue("interactive_style"))
		m.mu.RLock()
		expectedStyle := normalizeInteractiveStyle(m.config.InteractiveStyle)
		m.mu.RUnlock()

		if token == "" || holdMillis == "" {
			result.Reason = "missing interaction proof"
		} else if style != expectedStyle {
			result.Reason = "interactive verification method changed"
		} else if !VerifyBoundToken(token, clientIP, requestBinding(r, "", interactiveTokenPurpose(style))) {
			result.Reason = "invalid interaction token"
		} else if !m.consumeProof(token) {
			result.Reason = "proof already used"
		} else {
			duration, err := parseHeldDuration(holdMillis)
			if err != nil {
				result.Reason = "invalid interaction duration"
			} else if duration <= 0 || duration > 30000 {
				result.Reason = "interaction duration outside expected range"
			} else {
				if signals == "" {
					result.Reason = "missing interaction signals"
				} else if reason := validateInteractiveSignals(signals, duration, style); reason != "" {
					result.Reason = reason
				} else {
					analyzer := fingerprint.NewAnalyzer()
					fpResult := analyzer.Analyze(signals, r.UserAgent())
					result.FingerprintID = fpResult.Hash
					if fpResult.Score >= 90 {
						result.Reason = "interactive fingerprint remained suspicious"
					} else {
						isValid = true
					}
				}
			}
		}
	}

	// Case 2: Captcha
	if result.ChallengeType == "captcha" {
		token := r.FormValue("g-recaptcha-response")
		if token == "" {
			token = r.FormValue("cf-turnstile-response")
		}
		if token == "" {
			token = r.FormValue("h-captcha-response")
		}
		if token == "" {
			token = r.FormValue("frc-captcha-response")
		}
		if token == "" {
			token = r.FormValue("mtcaptcha-verifiedtoken")
		}

		if token == "" {
			result.Reason = "missing captcha token"
		} else if captcha.GetManager().VerifyToken(token, clientIP, r.Host) {
			isValid = true
		} else {
			result.Reason = "captcha verification failed"
		}
	}

	if isValid {
		result.Passed = true
		result.Reason = "challenge solved"
		m.mu.RLock()
		ttl := m.config.CookieTTL
		if ttl == 0 {
			ttl = 3600
		}
		m.mu.RUnlock()

		// Bind clearance to the stable, server-verified SDK identity when one is
		// present. The analyzer fingerprint is challenge-local and cannot be
		// reconstructed on the next request, so it must not be used as the
		// clearance verifier input.
		signedToken := GenerateBoundToken(clientIP, ttl, requestBinding(r, trustedFingerprint(r), "cookie"))

		http.SetCookie(w, &http.Cookie{
			Name:     "aegis_challenge",
			Value:    signedToken,
			Path:     "/",
			MaxAge:   ttl,
			HttpOnly: true,
			Secure:   r.TLS != nil, // Set verify if TLS
			SameSite: http.SameSiteLaxMode,
		})

		// Redirect to original URL to clear POST data
		// If it's an AJAX request (fetched), this 303 will be followed by browser or handled by fetch
		http.Redirect(w, r, r.URL.String(), http.StatusSeeOther)
		return true, result
	}

	if result.Reason == "" {
		result.Reason = "challenge verification failed"
	}
	http.Error(w, "Challenge verification failed", http.StatusForbidden)
	return true, result
}

func clientIPFromRequest(r *http.Request) string {
	if clientIP := requestctx.ClientIP(r); clientIP != "" {
		return clientIP
	}
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		return r.RemoteAddr
	}
	return clientIP
}

func requestBinding(r *http.Request, fingerprintID string, purpose string) TokenBinding {
	return TokenBinding{
		UserAgent:     r.UserAgent(),
		FingerprintID: fingerprintID,
		Purpose:       purpose,
	}
}

func normalizeChallengeMode(mode string) string {
	switch mode {
	case "", "js", "js_challenge", "managed", "managed_challenge":
		return "managed_challenge"
	case "invisible", "invisible_challenge":
		return "invisible_challenge"
	case "interactive", "interactive_challenge":
		return "interactive_challenge"
	case "captcha":
		return "captcha"
	default:
		return "managed_challenge"
	}
}

func challengeProofDifficulty(base int, mode string) int {
	if base <= 0 {
		base = 4
	}
	switch normalizeChallengeMode(mode) {
	case "invisible_challenge":
		if base > 2 {
			return 2
		}
		return base
	case "managed_challenge":
		return base
	default:
		return base
	}
}

func parseHeldDuration(value string) (int, error) {
	held, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return held, nil
}

type interactiveSignalPayload struct {
	Interaction interactiveEvidence `json:"interaction"`
}

type interactiveEvidence struct {
	Method            string `json:"method"`
	Completed         bool   `json:"completed"`
	StepCount         int    `json:"step_count"`
	Completion        int    `json:"completion"`
	HoldDuration      int    `json:"hold_duration"`
	EventCount        int    `json:"event_count"`
	EventSpan         int    `json:"event_span"`
	PointerDistance   int    `json:"pointer_distance"`
	PointerType       string `json:"pointer_type"`
	Focused           bool   `json:"focused"`
	StartedVisible    bool   `json:"started_visible"`
	CompletedVisible  bool   `json:"completed_visible"`
	VisibilityChanges int    `json:"visibility_changes"`
}

func validateInteractiveSignals(raw string, submittedDuration int, style string) string {
	var payload interactiveSignalPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return "malformed interaction signals"
	}

	evidence := payload.Interaction
	style = normalizeInteractiveStyle(style)
	evidenceMethod := normalizeInteractiveStyle(evidence.Method)
	if evidenceMethod != style {
		return "interaction method mismatch"
	}
	if evidence.HoldDuration <= 0 {
		return "missing interaction timing"
	}
	if absInt(evidence.HoldDuration-submittedDuration) > 750 {
		return "interaction timing mismatch"
	}
	if !evidence.StartedVisible || !evidence.CompletedVisible || evidence.VisibilityChanges > 0 {
		return "interaction visibility changed"
	}
	if !evidence.Focused {
		return "interaction page was not focused"
	}

	switch style {
	case InteractiveStyleClick:
		if submittedDuration < 250 {
			return "interaction completed too quickly"
		}
		if !evidence.Completed || evidence.EventCount < 2 {
			return "insufficient click evidence"
		}
	case InteractiveStyleSlide:
		if submittedDuration < 400 {
			return "interaction completed too quickly"
		}
		movementComplete := evidence.PointerType == "keyboard" || evidence.PointerDistance >= 100
		if !evidence.Completed || evidence.Completion < 95 || evidence.EventCount < 4 || !movementComplete {
			return "slide was not completed"
		}
	case InteractiveStyleSequence:
		if submittedDuration < 450 {
			return "interaction completed too quickly"
		}
		if !evidence.Completed || evidence.StepCount != 3 || evidence.Completion < 100 || evidence.EventCount < 3 {
			return "sequence was not completed"
		}
	case InteractiveStyleMatch:
		if submittedDuration < 250 {
			return "interaction completed too quickly"
		}
		if !evidence.Completed || evidence.StepCount != 1 || evidence.Completion < 100 || evidence.EventCount < 1 {
			return "symbol match was not completed"
		}
	default:
		if submittedDuration < 1500 || submittedDuration > 12000 {
			return "interaction duration outside expected range"
		}
		if evidence.EventCount < 2 {
			return "insufficient interaction events"
		}
		if evidence.EventSpan < 1000 {
			return "interaction completed too quickly"
		}
		if evidence.PointerType == "mouse" && evidence.PointerDistance == 0 && evidence.EventCount < 4 {
			return "insufficient pointer movement"
		}
	}
	return ""
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
