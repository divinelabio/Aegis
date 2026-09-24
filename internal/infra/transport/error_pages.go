package transport

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/divinelab-io/aegis/internal/infra/config"
)

// WriteConfiguredErrorPage writes an operator-authored error document only for
// browser document requests. Public APIs keep their native error responses so
// enabling a branded page cannot silently turn JSON failures into HTML.
func WriteConfiguredErrorPage(w http.ResponseWriter, r *http.Request, status int) bool {
	return writeConfiguredErrorPage(w, r, status, config.GetGlobalConfig())
}

func writeConfiguredErrorPage(w http.ResponseWriter, r *http.Request, status int, cfg *config.Config) bool {
	page, ok := configuredErrorPage(cfg, status)
	if !ok || !acceptsHTMLDocument(r) {
		return false
	}
	retryAfter := w.Header().Get("Retry-After")
	setConfiguredErrorHeaders(w.Header(), retryAfter)
	w.WriteHeader(status)
	if r == nil || r.Method != http.MethodHead {
		_, _ = io.WriteString(w, page)
	}
	return true
}

// ReplaceConfiguredErrorResponse substitutes upstream error HTML responses (404, 502, 503, 504).
// It executes after an upstream error response exists, so normal
// proxy responses do not incur buffering or configuration lookups.
func ReplaceConfiguredErrorResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		return replaceConfiguredErrorResponse(resp, config.GetGlobalConfig())
	default:
		return false
	}
}

func replaceConfiguredErrorResponse(resp *http.Response, cfg *config.Config) bool {
	if resp == nil || resp.Request == nil {
		return false
	}
	page, ok := configuredErrorPage(cfg, resp.StatusCode)
	if !ok || !acceptsHTMLDocument(resp.Request) {
		return false
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	retryAfter := resp.Header.Get("Retry-After")
	setConfiguredErrorHeaders(resp.Header, retryAfter)
	if resp.Request.Method == http.MethodHead {
		resp.Body = http.NoBody
		resp.ContentLength = 0
		return true
	}
	resp.Header.Set("Content-Length", strconv.Itoa(len(page)))
	resp.ContentLength = int64(len(page))
	resp.Body = io.NopCloser(strings.NewReader(page))
	return true
}

func configuredErrorPage(cfg *config.Config, status int) (string, bool) {
	if cfg == nil || !cfg.Modules.ErrorPages.Enabled {
		return "", false
	}
	var page string
	switch status {
	case http.StatusForbidden, http.StatusUnauthorized, http.StatusTooManyRequests:
		page = cfg.Modules.ErrorPages.Page403
	case http.StatusNotFound:
		page = cfg.Modules.ErrorPages.Page404
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		page = cfg.Modules.ErrorPages.Page503
	default:
		return "", false
	}
	return page, strings.TrimSpace(page) != ""
}

func acceptsHTMLDocument(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

func setConfiguredErrorHeaders(headers http.Header, retryAfter string) {
	for key := range headers {
		headers.Del(key)
	}
	headers.Set("Content-Type", "text/html; charset=utf-8")
	headers.Set("Cache-Control", "no-store")
	headers.Set("X-Content-Type-Options", "nosniff")
	if retryAfter != "" {
		headers.Set("Retry-After", retryAfter)
	}
}
