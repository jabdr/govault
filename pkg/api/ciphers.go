package api

import (
	"fmt"
	"net/http"
)

// GetCiphers returns all ciphers from the vault.
func (c *Client) GetCiphers() ([]map[string]any, error) {
	c.logger.Info("getting ciphers")
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	err := c.doRequest(http.MethodGet, "/api/ciphers", nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: get ciphers: %w", err)
	}
	return resp.Data, nil
}

// GetCipher returns a single cipher by ID.
func (c *Client) GetCipher(id string) (map[string]any, error) {
	c.logger.Info("getting cipher", "id", id)
	var resp map[string]any
	err := c.doRequest(http.MethodGet, "/api/ciphers/"+id, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: get cipher: %w", err)
	}
	return resp, nil
}

// CreateCipher creates a new cipher.
func (c *Client) CreateCipher(data map[string]any) (map[string]any, error) {
	c.logger.Info("creating cipher")
	var resp map[string]any
	err := c.doRequest(http.MethodPost, "/api/ciphers", data, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: create cipher: %w", err)
	}
	return resp, nil
}

// UpdateCipher updates an existing cipher.
func (c *Client) UpdateCipher(id string, data map[string]any) (map[string]any, error) {
	c.logger.Info("updating cipher", "id", id)
	var resp map[string]any
	err := c.doRequest(http.MethodPut, "/api/ciphers/"+id, data, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: update cipher: %w", err)
	}
	return resp, nil
}

// DeleteCipher deletes a cipher by ID.
func (c *Client) DeleteCipher(id string) error {
	c.logger.Info("deleting cipher", "id", id)
	err := c.doRequest(http.MethodDelete, "/api/ciphers/"+id, nil, nil)
	if err != nil {
		return fmt.Errorf("api: delete cipher: %w", err)
	}
	return nil
}
