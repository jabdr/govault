package api

import (
	"fmt"
	"net/http"
	"net/url"
)

// PreloginRequest is the request body for POST /identity/accounts/prelogin.
type PreloginRequest struct {
	Email string `json:"email"`
}

// PreloginResponse contains the KDF parameters for a user.
type PreloginResponse struct {
	Kdf            int  `json:"kdf"`
	KdfIterations  int  `json:"kdfIterations"`
	KdfMemory      *int `json:"kdfMemory"`
	KdfParallelism *int `json:"kdfParallelism"`
}

// Prelogin fetches the KDF parameters for the given email address.
func (c *Client) Prelogin(email string) (*PreloginResponse, error) {
	c.logger.Info("prelogin", "email", email)
	var resp PreloginResponse
	err := c.doRequest(http.MethodPost, "/identity/accounts/prelogin", PreloginRequest{Email: email}, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: prelogin: %w", err)
	}
	return &resp, nil
}

// LoginResponse contains the tokens and keys returned after authentication.
type LoginResponse struct {
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	TokenType      string `json:"token_type"`
	ExpiresIn      int    `json:"expires_in"`
	Key            string `json:"Key"`
	PrivateKey     string `json:"PrivateKey"`
	Kdf            int    `json:"Kdf"`
	KdfIterations  int    `json:"KdfIterations"`
	KdfMemory      *int   `json:"KdfMemory"`
	KdfParallelism *int   `json:"KdfParallelism"`
}

// Login authenticates with the server using email and master password hash.
func (c *Client) Login(email, passwordHash, deviceIdentifier string) (*LoginResponse, error) {
	c.logger.Info("login", "email", email)

	form := url.Values{
		"grant_type":       {"password"},
		"username":         {email},
		"password":         {passwordHash},
		"scope":            {"api offline_access"},
		"client_id":        {"web"},
		"deviceType":       {"9"},
		"deviceIdentifier": {deviceIdentifier},
		"deviceName":       {"govault"},
	}

	var resp LoginResponse
	err := c.doFormRequest("/identity/connect/token", form.Encode(), &resp)
	if err != nil {
		return nil, fmt.Errorf("api: login: %w", err)
	}

	c.SetTokens(resp.AccessToken, resp.RefreshToken)
	return &resp, nil
}

// RefreshAccessToken refreshes the access token using the refresh token.
func (c *Client) RefreshAccessToken() error {
	c.mu.RLock()
	rt := c.refreshToken
	c.mu.RUnlock()

	if rt == "" {
		return fmt.Errorf("api: no refresh token available")
	}

	c.logger.Info("refreshing access token")

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"web"},
	}

	var resp LoginResponse
	err := c.doFormRequest("/identity/connect/token", form.Encode(), &resp)
	if err != nil {
		return fmt.Errorf("api: refresh token: %w", err)
	}

	c.SetTokens(resp.AccessToken, resp.RefreshToken)
	return nil
}
