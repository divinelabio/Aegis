package captcha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	captchaVerificationTimeout    = 3 * time.Second
	maxCaptchaVerificationPayload = 64 << 10
)

var captchaVerificationClient = &http.Client{Timeout: captchaVerificationTimeout}

const (
	mtCaptchaVerifyURL = "https://service.mtcaptcha.com/mtcv1/api/checktoken"
	recaptchaV3Action  = "smart_challenge"
)

// --- ReCaptcha V2 ---

type RecaptchaV2Provider struct {
	SiteKey   string
	SecretKey string
}

func (p *RecaptchaV2Provider) Name() string { return "Google ReCaptcha V2" }

func (p *RecaptchaV2Provider) Render() string {
	return fmt.Sprintf(`
        <script src="https://www.google.com/recaptcha/api.js" async defer></script>
        <div class="g-recaptcha" data-sitekey="%s"></div>
    `, html.EscapeString(p.SiteKey))
}

func (p *RecaptchaV2Provider) Verify(token, remoteIP, expectedHostname string) (bool, error) {
	return verifyStandard("https://www.google.com/recaptcha/api/siteverify", p.SecretKey, token, remoteIP, "", expectedHostname)
}

// --- Cloudflare Turnstile ---

type TurnstileProvider struct {
	SiteKey   string
	SecretKey string
}

func (p *TurnstileProvider) Name() string { return "Cloudflare Turnstile" }

func (p *TurnstileProvider) Render() string {
	return fmt.Sprintf(`
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        <div class="cf-turnstile" data-sitekey="%s"></div>
    `, html.EscapeString(p.SiteKey))
}

func (p *TurnstileProvider) Verify(token, remoteIP, expectedHostname string) (bool, error) {
	return verifyStandard("https://challenges.cloudflare.com/turnstile/v0/siteverify", p.SecretKey, token, remoteIP, "", expectedHostname)
}

// --- hCaptcha ---

type HCaptchaProvider struct {
	SiteKey   string
	SecretKey string
}

func (p *HCaptchaProvider) Name() string { return "hCaptcha" }

func (p *HCaptchaProvider) Render() string {
	return fmt.Sprintf(`
        <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
        <div class="h-captcha" data-sitekey="%s"></div>
    `, html.EscapeString(p.SiteKey))
}

func (p *HCaptchaProvider) Verify(token, remoteIP, expectedHostname string) (bool, error) {
	return verifyStandard("https://api.hcaptcha.com/siteverify", p.SecretKey, token, remoteIP, p.SiteKey, expectedHostname)
}

// --- Friendly Captcha ---

const friendlyCaptchaVerifyURL = "https://global.frcapi.com/api/v2/captcha/siteverify"

type FriendlyCaptchaProvider struct {
	SiteKey   string
	APIKey    string
	VerifyURL string
	Client    *http.Client
}

func (p *FriendlyCaptchaProvider) Name() string { return "Friendly Captcha" }

func (p *FriendlyCaptchaProvider) Render() string {
	return fmt.Sprintf(`
        <script type="module" src="https://cdn.jsdelivr.net/npm/@friendlycaptcha/sdk@0.2.0/site.min.js" async defer></script>
        <script nomodule src="https://cdn.jsdelivr.net/npm/@friendlycaptcha/sdk@0.2.0/site.compat.min.js" async defer></script>
        <div class="frc-captcha" data-sitekey="%s"></div>
    `, html.EscapeString(p.SiteKey))
}

func (p *FriendlyCaptchaProvider) Verify(token, _ string, _ string) (bool, error) {
	if token == "" {
		return false, nil
	}

	payload, err := json.Marshal(struct {
		Response string `json:"response"`
		SiteKey  string `json:"sitekey,omitempty"`
	}{
		Response: token,
		SiteKey:  p.SiteKey,
	})
	if err != nil {
		return false, err
	}

	verifyURL := p.VerifyURL
	if verifyURL == "" {
		verifyURL = friendlyCaptchaVerifyURL
	}

	req, err := http.NewRequest(http.MethodPost, verifyURL, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", p.APIKey)

	client := p.Client
	if client == nil {
		client = captchaVerificationClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false, fmt.Errorf("friendly captcha verification returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Success bool `json:"success"`
	}
	if err := decodeCaptchaVerification(resp, &result); err != nil {
		return false, err
	}
	return result.Success, nil
}

// --- MTCaptcha ---

type MTCaptchaProvider struct {
	SiteKey   string // This is usually the SiteKey
	SecretKey string // PrivateKey
	VerifyURL string
	Client    *http.Client
}

func (p *MTCaptchaProvider) Name() string { return "MTCaptcha" }

func (p *MTCaptchaProvider) Render() string {
	return fmt.Sprintf(`
        <script>
            var mtcaptchaConfig = { "sitekey": %s };
            (function(){var mt_service = document.createElement('script');mt_service.async = true;mt_service.src = 'https://service.mtcaptcha.com/mtcv/client/mtcaptcha.min.js';(document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(mt_service);
            var mt_service2 = document.createElement('script');mt_service2.async = true;mt_service2.src = 'https://service.mtcaptcha.com/mtcv/client/mtcaptcha2.min.js';(document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(mt_service2);})();
        </script>
        <div class="mtcaptcha"></div>
	`, javaScriptString(p.SiteKey))
}

func (p *MTCaptchaProvider) Verify(token, _ string, expectedHostname string) (bool, error) {
	if token == "" {
		return false, nil
	}
	verifyURL := p.VerifyURL
	if verifyURL == "" {
		verifyURL = mtCaptchaVerifyURL
	}
	endpoint, err := url.Parse(verifyURL)
	if err != nil {
		return false, err
	}
	query := endpoint.Query()
	query.Set("privatekey", p.SecretKey)
	query.Set("token", token)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return false, err
	}
	client := p.Client
	if client == nil {
		client = captchaVerificationClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Success   bool `json:"success"`
		TokenInfo struct {
			Hostname string `json:"hostname"`
		} `json:"tokeninfo"`
	}
	if err := decodeCaptchaVerification(resp, &result); err != nil {
		return false, err
	}
	return result.Success && hostnameMatches(expectedHostname, result.TokenInfo.Hostname), nil
}

// --- ReCaptcha V3 ---

type RecaptchaV3Provider struct {
	SiteKey        string
	SecretKey      string
	ScoreThreshold float64
	VerifyURL      string
	Client         *http.Client
}

func (p *RecaptchaV3Provider) Name() string { return "Google ReCaptcha V3" }

func (p *RecaptchaV3Provider) Render() string {
	return fmt.Sprintf(`
        <script src="https://www.google.com/recaptcha/api.js?render=%s"></script>
        <input type="hidden" id="g-recaptcha-response" name="g-recaptcha-response">
        <script>
            document.addEventListener('submit', function(event) {
                var form = event.target;
                if (!form || !form.querySelector('#g-recaptcha-response') || form.dataset.recaptchaSubmitting === 'true') return;
                event.preventDefault();
                grecaptcha.ready(function() {
                    grecaptcha.execute(%s, {action: %s}).then(function(token) {
                        var el = form.querySelector('#g-recaptcha-response');
                        if (!el) return;
                        el.value = token;
                        form.dataset.recaptchaSubmitting = 'true';
                        form.submit();
                    });
                });
            });
        </script>
	`, url.QueryEscape(p.SiteKey), javaScriptString(p.SiteKey), javaScriptString(recaptchaV3Action))
}

func (p *RecaptchaV3Provider) Verify(token, remoteIP, expectedHostname string) (bool, error) {
	if token == "" {
		return false, nil
	}
	verifyURL := p.VerifyURL
	if verifyURL == "" {
		verifyURL = "https://www.google.com/recaptcha/api/siteverify"
	}
	client := p.Client
	if client == nil {
		client = captchaVerificationClient
	}
	resp, err := client.PostForm(verifyURL, url.Values{
		"secret":   {p.SecretKey},
		"response": {token},
		"remoteip": {remoteIP},
	})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Success  bool    `json:"success"`
		Score    float64 `json:"score"`
		Action   string  `json:"action"`
		Hostname string  `json:"hostname"`
	}
	if err := decodeCaptchaVerification(resp, &result); err != nil {
		return false, err
	}

	if !result.Success || result.Action != recaptchaV3Action || !hostnameMatches(expectedHostname, result.Hostname) {
		return false, nil
	}

	// Check score
	if result.Score < p.ScoreThreshold {
		return false, nil // Score too low, treat as bot
	}

	return true, nil
}

// --- Helper ---

func verifyStandard(apiURL, secret, token, ip, expectedSiteKey, expectedHostname string) (bool, error) {
	if token == "" {
		return false, nil
	}

	values := url.Values{
		"secret":   {secret},
		"response": {token},
		"remoteip": {ip},
	}
	if expectedSiteKey != "" {
		values.Set("sitekey", expectedSiteKey)
	}
	resp, err := captchaVerificationClient.PostForm(apiURL, values)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Success  bool   `json:"success"`
		Hostname string `json:"hostname"`
	}
	if err := decodeCaptchaVerification(resp, &result); err != nil {
		return false, err
	}
	return result.Success && hostnameMatches(expectedHostname, result.Hostname), nil
}

func hostnameMatches(expectedHostname, actualHostname string) bool {
	expectedHostname = normalizeHostname(expectedHostname)
	if expectedHostname == "" {
		return true
	}
	return expectedHostname == normalizeHostname(actualHostname)
}

func normalizeHostname(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return strings.Trim(value, "[]")
}

func decodeCaptchaVerification(response *http.Response, target interface{}) error {
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("captcha verification returned HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, maxCaptchaVerificationPayload)).Decode(target)
}

// javaScriptString returns a JSON string literal, which is safe to embed in an
// HTML script block. encoding/json escapes '<', '>' and '&' to prevent a site
// key from terminating the script element.
func javaScriptString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
