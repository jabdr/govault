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

// BaseURL returns the configured base URL.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// doRequest performs an authenticated HTTP request with JSON body/response.
func (c *Client) doRequest(method, path string, body any, result any) error {
	return c.doRequestRaw(method, path, "application/json", body, result)
}

func (c *Client) doRequestRaw(method, path, contentType string, body any, result any) error {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			bodyReader = strings.NewReader(v)
		case []byte:
			bodyReader = bytes.NewReader(v)
		case io.Reader:
			bodyReader = v
		default:
			jsonData, err := json.Marshal(body)
			if err != nil {
				return fmt.Errorf("api: marshal request body: %w", err)
			}
			bodyReader = bytes.NewReader(jsonData)
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
