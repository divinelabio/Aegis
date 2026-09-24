package rules

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRateLimitRate   = 60
	defaultRateLimitBurst  = 10
	defaultRateLimitWindow = time.Minute
	maxRateLimitRate       = 1_000_000
	maxRateLimitWindow     = 24 * time.Hour
)

// RateLimitActionConfig is the validated token-bucket configuration attached
// to a unified security rule. Rate is the number of tokens refilled per
// window; Burst is the bucket capacity.
type RateLimitActionConfig struct {
	Rate   int
	Burst  int
	Window time.Duration
}

// ParseRateLimitActionParams applies the rule-editor defaults and rejects
// values that could create an unusable or unbounded limiter.
func ParseRateLimitActionParams(params map[string]string) (RateLimitActionConfig, error) {
	config := RateLimitActionConfig{
		Rate:   defaultRateLimitRate,
		Burst:  defaultRateLimitBurst,
		Window: defaultRateLimitWindow,
	}
	if len(params) == 0 {
		return config, nil
	}
	var err error
	if raw := strings.TrimSpace(params["rate"]); raw != "" {
		if config.Rate, err = strconv.Atoi(raw); err != nil || config.Rate < 1 || config.Rate > maxRateLimitRate {
			return RateLimitActionConfig{}, fmt.Errorf("rate must be an integer from 1 to %d", maxRateLimitRate)
		}
	}
	if raw := strings.TrimSpace(params["burst"]); raw != "" {
		if config.Burst, err = strconv.Atoi(raw); err != nil || config.Burst < 1 || config.Burst > maxRateLimitRate {
			return RateLimitActionConfig{}, fmt.Errorf("burst must be an integer from 1 to %d", maxRateLimitRate)
		}
	}
	if raw := strings.TrimSpace(params["window"]); raw != "" {
		if config.Window, err = time.ParseDuration(raw); err != nil || config.Window < time.Second || config.Window > maxRateLimitWindow {
			return RateLimitActionConfig{}, fmt.Errorf("window must be a duration from 1s to %s", maxRateLimitWindow)
		}
	}
	return config, nil
}

// ValidateRedirectTarget permits only local absolute-path redirects. Bot rules
// run at the edge and must not turn an operator mistake into an open redirect.
func ValidateRedirectTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	parsed, err := url.ParseRequestURI(target)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.HasPrefix(target, "/\\") {
		return fmt.Errorf("redirect location must be a local absolute path")
	}
	return nil
}
