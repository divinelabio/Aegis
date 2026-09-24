package licensing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type apiClient struct {
	baseURL string
	http    *http.Client
}

type activationRequest struct {
	LicenseKey     string `json:"license_key"`
	InstallationID string `json:"installation_id"`
	PublicKey      string `json:"public_key"`
	Platform       string `json:"platform"`
	Architecture   string `json:"architecture"`
	Version        string `json:"version"`
	Nonce          string `json:"nonce"`
}

type signedPayload struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type leaseRequest struct {
	ActivationID   string `json:"activation_id"`
	InstallationID string `json:"installation_id"`
	RuntimeID      string `json:"runtime_id"`
	Version        string `json:"version"`
	Timestamp      int64  `json:"timestamp"`
	Nonce          string `json:"nonce"`
}

type apiResponse struct {
	ActivationID       string    `json:"activation_id"`
	Entitlement        string    `json:"entitlement"`
	ServerTime         time.Time `json:"server_time"`
	TargetTier         string    `json:"target_tier,omitempty"`
	TargetVersion      string    `json:"target_version,omitempty"`
	ArtifactManifest   string    `json:"artifact_manifest,omitempty"`
	ArtifactCredential string    `json:"artifact_credential,omitempty"`
}

func newAPIClient(rawURL string) (*apiClient, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, errors.New("licence API URL is not configured")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return nil, errors.New("licence API URL is invalid")
	}
	isLocal := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLocal) {
		return nil, errors.New("licence API URL must be an absolute HTTPS URL (or HTTP for localhost)")
	}
	return &apiClient{
		baseURL: strings.TrimRight(parsed.String(), "/"),
		http:    &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (c *apiClient) activate(ctx context.Context, request activationRequest) (apiResponse, error) {
	var response apiResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/activations", request, &response); err != nil {
		return apiResponse{}, err
	}
	return response, nil
}

func (c *apiClient) refresh(ctx context.Context, activationID string, request leaseRequest, privateKey ed25519.PrivateKey) (apiResponse, error) {
	envelope, err := signPayload(request, privateKey)
	if err != nil {
		return apiResponse{}, err
	}
	var response apiResponse
	path := "/v1/activations/" + url.PathEscape(activationID) + "/leases"
	if err := c.doJSON(ctx, http.MethodPost, path, envelope, &response); err != nil {
		return apiResponse{}, err
	}
	return response, nil
}

func (c *apiClient) deactivate(ctx context.Context, activationID string, request leaseRequest, privateKey ed25519.PrivateKey) error {
	envelope, err := signPayload(request, privateKey)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, "/v1/activations/"+url.PathEscape(activationID), envelope, nil)
}

func (c *apiClient) doJSON(ctx context.Context, method, path string, requestBody any, responseBody any) error {
	body, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 2<<20)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message, _ := io.ReadAll(limited)
		return fmt.Errorf("licence API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(message)))
	}
	if responseBody == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(limited).Decode(responseBody); err != nil {
		return fmt.Errorf("decode licence API response: %w", err)
	}
	return nil
}

func signPayload(value any, privateKey ed25519.PrivateKey) (signedPayload, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return signedPayload{}, err
	}
	signature := ed25519.Sign(privateKey, payload)
	return signedPayload{
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

func randomNonce() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
