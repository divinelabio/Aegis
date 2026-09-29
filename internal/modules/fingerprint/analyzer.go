package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxStabilityEntries = 10_000
	stabilityTTL        = 30 * time.Minute
)

type Analyzer struct {
	stability *stabilityState
}

type FingerprintData struct {
	Screen              string          `json:"-"`
	ScreenV3            screenData      `json:"-"`
	Viewport            viewportData    `json:"viewport"`
	Timezone            string          `json:"timezone"`
	Language            string          `json:"language"`
	Lang                string          `json:"lang"`
	Languages           string          `json:"-"`
	LanguagesList       []string        `json:"-"`
	Platform            string          `json:"platform"`
	HardwareConcurrency int             `json:"hardwareConcurrency"`
	Cores               int             `json:"cores"`
	DeviceMemory        interface{}     `json:"deviceMemory"`
	Memory              interface{}     `json:"mem"`
	Vendor              string          `json:"vendor"`
	UserAgent           string          `json:"userAgent"`
	UA                  string          `json:"ua"`
	WebDriver           bool            `json:"webdriver"`
	WebDriverLie        bool            `json:"webdriver_lie"`
	Plugins             string          `json:"-"`
	PluginsLen          int             `json:"plugins_len"`
	PluginsCount        int             `json:"-"`
	CanvasHash          string          `json:"canvas"`
	CanvasHashV3        string          `json:"fp_canvas_hash"`
	WebGLVendor         string          `json:"webgl_vendor"`
	WebGLRenderer       string          `json:"webgl_renderer"`
	WebGLHash           string          `json:"fp_webgl_hash"`
	FontsHash           string          `json:"fp_fonts_hash"`
	Audio               string          `json:"audio"`
	Headless            bool            `json:"-"`
	HeadlessSignals     *RuntimeSignals `json:"-"`
	Touch               bool            `json:"touch"`
	PointerCoarse       bool            `json:"pointer_coarse"`
	CookiesEnabled      *bool           `json:"cookies_enabled"`
	LocalStorageEnabled *bool           `json:"local_storage_enabled"`
	SessionStorage      *bool           `json:"session_storage_enabled"`
	SessionID           string          `json:"session_id"`
	SessionNonce        string          `json:"session_nonce"`
	SDKVersion          string          `json:"sdk_version"`
	Behavior            BehaviorData    `json:"behavior"`
}

type screenData struct {
	W     int `json:"w"`
	H     int `json:"h"`
	Depth int `json:"depth"`
}

type viewportData struct {
	W      int `json:"w"`
	H      int `json:"h"`
	OuterW int `json:"outerW"`
	OuterH int `json:"outerH"`
}

type RuntimeSignals struct {
	WebDriver                bool `json:"webdriver"`
	WebDriverLie             bool `json:"webdriver_lie"`
	ChromeRuntimeMissing     bool `json:"chrome_runtime_missing"`
	NotificationInconsistent bool `json:"notification_inconsistent"`
	PermissionsInconsistent  bool `json:"permissions_inconsistent"`
	OuterWindowZero          bool `json:"outer_window_zero"`
	TouchInconsistent        bool `json:"touch_inconsistent"`
}

type BehaviorData struct {
	HasMouse    bool `json:"has_mouse"`
	HasKeyboard bool `json:"has_keyboard"`
	Events      struct {
		Mouse []Event `json:"mouse"`
		Keys  []Event `json:"keys"`
	} `json:"events"`
	MEntropy float64 `json:"m_entropy"`
	MMoves   int     `json:"m_moves"`
	KFlight  int     `json:"k_flight"`
	KCount   int     `json:"k_count"`
	SDepth   int     `json:"s_depth"`
	Clicks   int     `json:"clicks"`
	Time     int     `json:"time"`
}

type Event struct {
	X int64  `json:"x,omitempty"`
	Y int64  `json:"y,omitempty"`
	K string `json:"k,omitempty"`
	T int64  `json:"t"`
}

type AnalysisResult struct {
	Hash            string
	IdentityVersion string
	Score           int
	BehaviorScore   int
	IsHeadless      bool
	Inconsistencies []string
}

type stabilityRecord struct {
	Screen        string
	Platform      string
	Language      string
	CanvasHash    string
	WebGLHash     string
	FontsHash     string
	WebGLRenderer string
	lastSeen      time.Time
}

type stabilityState struct {
	mu         sync.Mutex
	entries    map[string]stabilityRecord
	maxEntries int
	ttl        time.Duration
}

var defaultStabilityState = newStabilityState(maxStabilityEntries, stabilityTTL)

func newStabilityState(maxEntries int, ttl time.Duration) *stabilityState {
	if maxEntries <= 0 {
		maxEntries = maxStabilityEntries
	}
	if ttl <= 0 {
		ttl = stabilityTTL
	}
	return &stabilityState{entries: make(map[string]stabilityRecord), maxEntries: maxEntries, ttl: ttl}
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{stability: defaultStabilityState}
}

func (a *Analyzer) Analyze(rawJSON string, headersUserAgent string) *AnalysisResult {
	var data FingerprintData
	if err := json.Unmarshal([]byte(rawJSON), &data); err != nil {
		return &AnalysisResult{Score: 100, Inconsistencies: []string{"Malformed JSON"}}
	}
	hydrateExtendedFingerprintData(rawJSON, &data)

	userAgent := firstNonEmpty(data.UserAgent, data.UA, headersUserAgent)
	language := firstNonEmpty(data.Language, data.Lang)
	languages := normalizedLanguages(data)
	screenKey := normalizedScreen(data)
	canvasHash := firstNonEmpty(data.CanvasHashV3, data.CanvasHash)
	webglHash := data.WebGLHash
	fontsHash := data.FontsHash
	headlessSignals := normalizedRuntimeSignals(data)

	runtimeWebDriver := data.WebDriver || headlessSignals.WebDriver
	result := &AnalysisResult{
		Score:           0,
		IdentityVersion: "fpv3",
		Inconsistencies: make([]string, 0),
		IsHeadless:      data.Headless || runtimeWebDriver,
	}

	hashBase := strings.Join([]string{
		"fpv3",
		screenKey,
		data.Platform,
		data.HardwareConcurrencyToString(),
		canvasHash,
		firstNonEmpty(webglHash, data.WebGLRenderer),
		fontsHash,
	}, "|")

	h := sha256.New()
	h.Write([]byte(hashBase))
	result.Hash = "fpv3_" + hex.EncodeToString(h.Sum(nil))

	if jsUA := firstNonEmpty(data.UserAgent, data.UA); jsUA != "" && headersUserAgent != "" && jsUA != headersUserAgent {
		result.Score += 20
		result.Inconsistencies = append(result.Inconsistencies, "User-Agent mismatch (JS vs Header)")
	}

	lowerUA := strings.ToLower(userAgent)
	lowerPlatform := strings.ToLower(data.Platform)
	switch {
	case strings.Contains(lowerUA, "windows") && !strings.Contains(lowerPlatform, "win"):
		result.Score += 30
		result.Inconsistencies = append(result.Inconsistencies, "Platform mismatch (Windows UA but non-Windows JS)")
	case strings.Contains(lowerUA, "mac os") && !strings.Contains(lowerPlatform, "mac"):
		result.Score += 30
		result.Inconsistencies = append(result.Inconsistencies, "Platform mismatch (Mac UA but non-Mac JS)")
	case strings.Contains(lowerUA, "linux") && !strings.Contains(lowerPlatform, "linux"):
		result.Score += 30
		result.Inconsistencies = append(result.Inconsistencies, "Platform mismatch (Linux UA but non-Linux JS)")
	}

	if result.IsHeadless {
		result.Score += 50
		result.Inconsistencies = append(result.Inconsistencies, "Headless browser detected")
	}

	if screenKey == "0x0" || screenKey == "" {
		result.Score += 20
		result.Inconsistencies = append(result.Inconsistencies, "Invalid screen resolution")
	}

	behaviorResult := AnalyzeBehavior(data.Behavior)
	result.BehaviorScore = behaviorResult.OverallScore
	result.Inconsistencies = append(result.Inconsistencies, behaviorResult.Reasons...)
	if behaviorResult.OverallScore < 30 {
		result.Score += 30
	} else if behaviorResult.OverallScore < 50 {
		result.Score += 15
	}

	if pluginsLen(data) == 0 && strings.Contains(lowerUA, "chrome") && !strings.Contains(lowerUA, "mobile") {
		result.Score += 30
		result.Inconsistencies = append(result.Inconsistencies, "Desktop Chrome with 0 plugins likely headless")
	}
	if languages == "" && strings.Contains(lowerUA, "chrome") {
		result.Score += 40
		result.Inconsistencies = append(result.Inconsistencies, "Empty navigator.languages (Headless characteristic)")
	}

	if (runtimeWebDriver && headlessSignals.OuterWindowZero) || strings.HasPrefix(screenKey, "0x0x") || screenKey == "0x0" {
		result.Score += 100
		result.Inconsistencies = append(result.Inconsistencies, "Outer window dimensions are 0 (Headless)")
	}

	if data.Viewport.W > 0 && data.ScreenV3.W > 0 && data.Viewport.W > data.ScreenV3.W+80 {
		result.Score += 16
		result.Inconsistencies = append(result.Inconsistencies, "Viewport exceeds reported screen width")
	}
	if data.Viewport.H > 0 && data.ScreenV3.H > 0 && data.Viewport.H > data.ScreenV3.H+120 {
		result.Score += 16
		result.Inconsistencies = append(result.Inconsistencies, "Viewport exceeds reported screen height")
	}

	if suspiciousRenderer(data.WebGLRenderer) {
		result.Score += 28
		result.Inconsistencies = append(result.Inconsistencies, "Rendering stack matches common headless GPU path")
	}
	if canvasHash == "" || isErrorFingerprint(canvasHash) {
		result.Score += 12
		result.Inconsistencies = append(result.Inconsistencies, "Canvas fingerprint unavailable")
	}
	if fontsHash == "" || isErrorFingerprint(fontsHash) {
		result.Score += 10
		result.Inconsistencies = append(result.Inconsistencies, "Font metrics unavailable")
	}
	if data.Audio == "audio_error" {
		result.Score += 6
		result.Inconsistencies = append(result.Inconsistencies, "Audio fingerprint failed")
	}

	if headlessSignals.ChromeRuntimeMissing && (strings.Contains(lowerUA, "chrome") || strings.Contains(lowerUA, "edg/")) {
		result.Score += 35
		result.Inconsistencies = append(result.Inconsistencies, "Chrome runtime missing for Chromium-family UA")
	}
	if headlessSignals.NotificationInconsistent || headlessSignals.PermissionsInconsistent {
		result.Score += 18
		result.Inconsistencies = append(result.Inconsistencies, "Permission API behavior inconsistent")
	}
	if headlessSignals.TouchInconsistent || (data.Touch && !data.PointerCoarse && !strings.Contains(lowerUA, "mobile")) {
		result.Score += 14
		result.Inconsistencies = append(result.Inconsistencies, "Touch capability inconsistent with pointer profile")
	}
	if boolPtrFalse(data.CookiesEnabled) && boolPtrTrue(data.LocalStorageEnabled) && boolPtrTrue(data.SessionStorage) {
		result.Score += 8
		result.Inconsistencies = append(result.Inconsistencies, "Cookie-disabled browser still reports full storage availability")
	}

	if instability := a.trackFingerprintStability(data, screenKey, language, canvasHash, webglHash, fontsHash, time.Now()); instability != "" {
		result.Score += 22
		result.Inconsistencies = append(result.Inconsistencies, instability)
	}

	if result.Score > 100 {
		result.Score = 100
	}
	return result
}

func (f *FingerprintData) HardwareConcurrencyToString() string {
	if f.Cores > 0 {
		return fmt.Sprintf("%d", f.Cores)
	}
	return fmt.Sprintf("%d", f.HardwareConcurrency)
}

func normalizedScreen(data FingerprintData) string {
	if strings.TrimSpace(data.Screen) != "" {
		return data.Screen
	}
	if data.ScreenV3.W <= 0 && data.ScreenV3.H <= 0 {
		return ""
	}
	return fmt.Sprintf("%dx%dx%d|%dx%d", data.ScreenV3.W, data.ScreenV3.H, data.ScreenV3.Depth, data.Viewport.OuterW, data.Viewport.OuterH)
}

func normalizedLanguages(data FingerprintData) string {
	if strings.TrimSpace(data.Languages) != "" {
		return data.Languages
	}
	if len(data.LanguagesList) == 0 {
		return ""
	}
	return strings.Join(data.LanguagesList, ",")
}

func normalizedRuntimeSignals(data FingerprintData) RuntimeSignals {
	signals := RuntimeSignals{}
	if data.HeadlessSignals != nil {
		signals = *data.HeadlessSignals
	}
	if data.WebDriver {
		signals.WebDriver = true
	}
	if data.WebDriverLie {
		signals.WebDriverLie = true
	}
	return signals
}

func pluginsLen(data FingerprintData) int {
	if data.PluginsCount > 0 {
		return data.PluginsCount
	}
	return data.PluginsLen
}

func suspiciousRenderer(renderer string) bool {
	value := strings.ToLower(strings.TrimSpace(renderer))
	if value == "" {
		return false
	}
	for _, marker := range []string{"swiftshader", "llvmpipe", "software", "mesa offscreen", "angle (google"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func isErrorFingerprint(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "error", "canvas_error", "font_probe_error", "webgl_error", "audio_error", "no_canvas", "no_webgl":
		return true
	default:
		return strings.Contains(value, "error")
	}
}

func (a *Analyzer) trackFingerprintStability(data FingerprintData, screenKey, language, canvasHash, webglHash, fontsHash string, now time.Time) string {
	if a == nil || a.stability == nil {
		return ""
	}
	key := strings.TrimSpace(data.SessionID)
	if nonce := strings.TrimSpace(data.SessionNonce); nonce != "" {
		key = nonce + "\x00" + key
	}
	if key == "" {
		key = firstNonEmpty(canvasHash, webglHash, fontsHash)
	}
	if key == "" {
		return ""
	}

	current := stabilityRecord{
		Screen:        screenKey,
		Platform:      data.Platform,
		Language:      language,
		CanvasHash:    canvasHash,
		WebGLHash:     webglHash,
		FontsHash:     fontsHash,
		WebGLRenderer: data.WebGLRenderer,
		lastSeen:      now,
	}

	state := a.stability
	state.mu.Lock()
	defer state.mu.Unlock()
	for existingKey, record := range state.entries {
		if now.Sub(record.lastSeen) > state.ttl {
			delete(state.entries, existingKey)
		}
	}
	if previous, ok := state.entries[key]; ok {
		var changes []string
		if changedStableValue(previous.Screen, current.Screen) {
			changes = append(changes, "screen")
		}
		if changedStableValue(previous.Platform, current.Platform) {
			changes = append(changes, "platform")
		}
		if changedStableValue(previous.Language, current.Language) {
			changes = append(changes, "language")
		}
		if changedStableValue(previous.CanvasHash, current.CanvasHash) {
			changes = append(changes, "canvas")
		}
		if changedStableValue(previous.WebGLHash, current.WebGLHash) {
			changes = append(changes, "webgl")
		}
		if changedStableValue(previous.FontsHash, current.FontsHash) {
			changes = append(changes, "fonts")
		}
		if changedStableValue(previous.WebGLRenderer, current.WebGLRenderer) {
			changes = append(changes, "renderer")
		}
		state.entries[key] = current
		if len(changes) > 0 {
			return fmt.Sprintf("Fingerprint changed during session (%s)", strings.Join(changes, ", "))
		}
		return ""
	}

	if len(state.entries) >= state.maxEntries {
		oldestKey := ""
		var oldest time.Time
		for existingKey, record := range state.entries {
			if oldestKey == "" || record.lastSeen.Before(oldest) {
				oldestKey = existingKey
				oldest = record.lastSeen
			}
		}
		if oldestKey != "" {
			delete(state.entries, oldestKey)
		}
	}
	state.entries[key] = current
	return ""
}

func changedStableValue(previous, current string) bool {
	previous = strings.TrimSpace(previous)
	current = strings.TrimSpace(current)
	return previous != "" && current != "" && previous != current
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func boolPtrTrue(value *bool) bool {
	return value != nil && *value
}

func boolPtrFalse(value *bool) bool {
	return value != nil && !*value
}

func hydrateExtendedFingerprintData(rawJSON string, data *FingerprintData) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawJSON), &raw); err != nil {
		return
	}

	if value, ok := raw["headless"]; ok {
		var signals RuntimeSignals
		if err := json.Unmarshal(value, &signals); err == nil {
			data.HeadlessSignals = &signals
		} else {
			var headless bool
			if json.Unmarshal(value, &headless) == nil {
				data.Headless = headless
			}
		}
	}

	if value, ok := raw["screen"]; ok {
		var legacy string
		if err := json.Unmarshal(value, &legacy); err == nil {
			data.Screen = legacy
		}
		var screen screenData
		if err := json.Unmarshal(value, &screen); err == nil && (screen.W > 0 || screen.H > 0) {
			data.ScreenV3 = screen
		}
	}

	if value, ok := raw["viewport"]; ok {
		var viewport viewportData
		if err := json.Unmarshal(value, &viewport); err == nil {
			data.Viewport = viewport
		}
	}

	if value, ok := raw["languages"]; ok {
		var legacy string
		if err := json.Unmarshal(value, &legacy); err == nil {
			data.Languages = legacy
		}
		var items []string
		if err := json.Unmarshal(value, &items); err == nil {
			data.LanguagesList = items
		}
	}

	if value, ok := raw["plugins"]; ok {
		var count int
		if err := json.Unmarshal(value, &count); err == nil {
			data.PluginsCount = count
		} else {
			var asString string
			if json.Unmarshal(value, &asString) == nil {
				if parsed, parseErr := strconv.Atoi(strings.TrimSpace(asString)); parseErr == nil {
					data.PluginsCount = parsed
				}
			}
		}
	}
}
