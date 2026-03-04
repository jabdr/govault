// Package api implements the HTTP client for the Bitwarden/Vaultwarden API.
// It handles authentication, token management, and all API endpoint calls.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
)

// Client is the HTTP client for the Bitwarden/Vaultwarden API.
type Client struct {
	baseURL      string
	httpClient   *http.Client
	accessToken  string
	refreshToken string
	logger       *slog.Logger
	mu           sync.RWMutex
	reauthFunc   func() error // callback for re-authentication
}

// NewClient creates a new API client for the given server URL.
func NewClient(baseURL string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{},
		logger:     logger,
	}
}

// SetTokens sets the access and refresh tokens after login.
func (c *Client) SetTokens(accessToken, refreshToken string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken = accessToken
	c.refreshToken = refreshToken
}

// GetTokens returns the current access and refresh tokens.
func (c *Client) GetTokens() (accessToken, refreshToken string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessToken, c.refreshToken
}

// SetReauthFunc sets a callback that the client will invoke when an API
// call receives an HTTP 401 Unauthorized response. The callback should
// attempt to re-authenticate (e.g. via refresh token or full re-login)
// so that the request can be retried with a valid access token.
func (c *Client) SetReauthFunc(fn func() error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reauthFunc = fn
}

// SetInsecureSkipVerify configures TLS for the client.
// It always enforces TLS 1.2 as minimum and optionally disables certificate verification.
func (c *Client) SetInsecureSkipVerify(skip bool) {
	c.httpClient.Transport = NewTLSTransport(skip)
}

// BaseURL returns the configured base URL.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// doRequest performs an authenticated HTTP request with JSON body/response.
func (c *Client) doRequest(method, path string, body any, result any) error {
	return c.doRequestRaw(method, path, "application/json", body, result)
}

func (c *Client) doRequestRaw(method, path, contentType string, body any, result any) error {
	err := c.doRequestOnce(method, path, contentType, body, result)
	if err == nil {
		return nil
	}

	// If we got a 401 and have a reauth callback, try to re-authenticate and retry
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.StatusCode != 401 {
		return err
	}

	c.mu.RLock()
	reauth := c.reauthFunc
	c.mu.RUnlock()

	if reauth == nil {
		return err
	}

	c.logger.Info("received 401, attempting re-authentication")
	if reauthErr := reauth(); reauthErr != nil {
		return fmt.Errorf("api: re-authentication failed: %w (original: %w)", reauthErr, err)
	}

	// Retry the original request
	return c.doRequestOnce(method, path, contentType, body, result)
}

// doRequestOnce performs a single HTTP request without retry.
func (c *Client) doRequestOnce(method, path, contentType string, body any, result any) error {
	url := c.baseURL + path

	var bodyReader io.Reader
	var reqBodyBytes []byte

	if body != nil {
		switch v := body.(type) {
		case string:
			bodyReader = strings.NewReader(v)
			reqBodyBytes = []byte(v)
		case []byte:
			bodyReader = bytes.NewReader(v)
			reqBodyBytes = v
		case io.Reader:
			bodyReader = v
		default:
			var err error
			reqBodyBytes, err = json.Marshal(body)
			if err != nil {
				return fmt.Errorf("api: marshal request body: %w", err)
			}
			bodyReader = bytes.NewReader(reqBodyBytes)
		}
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("api: create request: %w", err)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")

	c.mu.RLock()
	token := c.accessToken
	c.mu.RUnlock()

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	c.logger.Debug("API request", "method", method, "url", url)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("api: do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("api: read response body: %w", err)
	}

	c.logger.Debug("API response", "status", resp.StatusCode, "size", len(respBody))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == 422 && reqBodyBytes != nil {
			c.logger.Error("HTTP 422 Unprocessable Entity", "requestPayload", string(reqBodyBytes))
		}
		return &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("api: unmarshal response: %w", err)
		}
	}

	return nil
}

// doFormRequest sends a form-encoded POST request.
func (c *Client) doFormRequest(path, formData string, result any) error {
	return c.doRequestRaw(http.MethodPost, path, "application/x-www-form-urlencoded", formData, result)
}

// APIError represents a non-2xx response from the API.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api: HTTP %d: %s", e.StatusCode, e.Body)
}
