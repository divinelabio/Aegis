// Package operatorcli contains the transport shared by the local aegisctl
// command. It intentionally uses the protected Admin API for runtime
// operations, retaining the server's RBAC, edition, CSRF, audit, validation,
// and transactional-reload behavior.
package operatorcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxErrorBody = 8 << 10

// Credentials are intentionally supplied by the caller so the CLI never
// retains credential data outside the lifetime of a command invocation.
type Credentials struct {
	Username string
	Password string
	MFACode  string
}

// Client is an authenticated Admin API client.
type Client struct {
	baseURL   *url.URL
	http      *http.Client
	csrfToken string
}

// NewClient accepts HTTP only for a loopback Admin API. A remote control plane
// must use HTTPS so operator credentials and session cookies are protected.
func NewClient(rawURL string, timeout time.Duration) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("parse admin URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("admin URL must use http or https")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("admin URL must contain only a scheme, host, and optional base path")
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("a non-loopback admin URL must use HTTPS")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{baseURL: parsed, http: &http.Client{Jar: jar, Timeout: timeout}}, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Authenticate establishes an Admin API session and loads the CSRF token.
func (c *Client) Authenticate(ctx context.Context, credentials Credentials) error {
	if strings.TrimSpace(credentials.Username) == "" || credentials.Password == "" {
		return errors.New("administrator username and password are required")
	}
	response, err := c.JSON(ctx, http.MethodPost, "/api/login", map[string]any{
		"username":    credentials.Username,
		"password":    credentials.Password,
		"remember_me": false,
	})
	if err != nil {
		return err
	}
	var login struct {
		Status    string `json:"status"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response, &login); err != nil {
		return fmt.Errorf("decode login response: %w", err)
	}
	if login.Status == "mfa_required" {
		if strings.TrimSpace(credentials.MFACode) == "" {
			return errors.New("MFA code is required; provide AEGISCTL_MFA_CODE, --mfa-file, or --mfa-stdin")
		}
		if _, err := c.JSON(ctx, http.MethodPost, "/api/login/mfa", map[string]string{"code": strings.TrimSpace(credentials.MFACode)}); err != nil {
			return err
		}
		response, err = c.Request(ctx, http.MethodGet, "/api/verify_session", nil, "")
		if err != nil {
			return err
		}
		if err := json.Unmarshal(response, &login); err != nil {
			return fmt.Errorf("decode MFA session response: %w", err)
		}
	}
	if login.Status != "ok" && login.Status != "active" {
		return fmt.Errorf("administrator login did not complete (status %q)", login.Status)
	}
	if login.CSRFToken == "" {
		return errors.New("administrator session did not return a CSRF token")
	}
	c.csrfToken = login.CSRFToken
	return nil
}

// JSON encodes a JSON request body and returns the response bytes.
func (c *Client) JSON(ctx context.Context, method, path string, value any) ([]byte, error) {
	var body io.Reader
	if value != nil {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	return c.Request(ctx, method, path, body, "application/json")
}

// Request makes an authenticated API request. State-changing requests must be
// issued after Authenticate so the server can enforce CSRF protection.
func (c *Client) Request(ctx context.Context, method, path string, body io.Reader, contentType string) ([]byte, error) {
	requestURL, err := c.resolve(path)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	loginRequest := path == "/api/login" || path == "/api/login/mfa"
	if method != http.MethodGet && method != http.MethodHead && !loginRequest {
		if c.csrfToken == "" {
			return nil, errors.New("authenticate before making a state-changing request")
		}
		request.Header.Set("X-CSRF-Token", c.csrfToken)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if readErr != nil {
		return nil, readErr
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		message := strings.TrimSpace(string(data))
		if len(message) > maxErrorBody {
			message = message[:maxErrorBody] + "..."
		}
		if message == "" {
			message = response.Status
		}
		return nil, fmt.Errorf("admin API %s %s: %s", method, path, message)
	}
	return data, nil
}

// UploadFile uploads a single bounded file using the form field expected by
// the Admin API. The server remains authoritative for content validation.
func (c *Client) UploadFile(ctx context.Context, path, field, filePath string, fields map[string]string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return nil, err
		}
	}
	part, err := writer.CreateFormFile(field, file.Name())
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(part, io.LimitReader(file, 32<<20)); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return c.Request(ctx, http.MethodPost, path, &buffer, writer.FormDataContentType())
}

// UploadCertificate sends a certificate and its private key as the Admin API
// expects. It is deliberately separate from UploadFile to prevent accidental
// field-name mistakes for sensitive material.
func (c *Client) UploadCertificate(ctx context.Context, certPath, keyPath, domain string) ([]byte, error) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	if err := writer.WriteField("domain", domain); err != nil {
		return nil, err
	}
	for field, path := range map[string]string{"certificate": certPath, "key": keyPath} {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		part, createErr := writer.CreateFormFile(field, file.Name())
		if createErr == nil {
			_, createErr = io.Copy(part, io.LimitReader(file, 2<<20))
		}
		closeErr := file.Close()
		if createErr != nil {
			return nil, createErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return c.Request(ctx, http.MethodPost, "/api/certificates", &buffer, writer.FormDataContentType())
}

func (c *Client) resolve(path string) (string, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "", errors.New("API path must begin with one slash")
	}
	relative, err := url.Parse(path)
	if err != nil || relative.IsAbs() || relative.Host != "" {
		return "", errors.New("API path is invalid")
	}
	base := *c.baseURL
	base.Path = strings.TrimRight(base.Path, "/") + relative.Path
	base.RawQuery = relative.RawQuery
	return base.String(), nil
}
