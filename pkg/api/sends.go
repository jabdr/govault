package api

import (
	"fmt"
	"net/http"
)

// SendTextData holds the text content of a text Send.
type SendTextData struct {
	Text   string `json:"text"`
	Hidden bool   `json:"hidden"`
}

// SendRequest is the request body for creating or updating a Send.
type SendRequest struct {
	Type           int            `json:"type"`
	Key            string         `json:"key"`
	Password       *string        `json:"password,omitempty"`
	MaxAccessCount *int           `json:"maxAccessCount,omitempty"`
	ExpirationDate *string        `json:"expirationDate,omitempty"`
	DeletionDate   string         `json:"deletionDate"`
	Disabled       bool           `json:"disabled"`
	HideEmail      *bool          `json:"hideEmail,omitempty"`
	Name           string         `json:"name"`
	Notes          *string        `json:"notes,omitempty"`
	Text           *SendTextData  `json:"text,omitempty"`
	File           map[string]any `json:"file,omitempty"`
	FileLength     *int           `json:"fileLength,omitempty"`
}

// SendResponse is the response from Send endpoints.
type SendResponse struct {
	ID             string         `json:"id"`
	AccessID       string         `json:"accessId"`
	Type           int            `json:"type"`
	Name           string         `json:"name"`
	Notes          *string        `json:"notes"`
	Key            string         `json:"key"`
	MaxAccessCount *int           `json:"maxAccessCount"`
	AccessCount    int            `json:"accessCount"`
	Password       *string        `json:"password"`
	Disabled       bool           `json:"disabled"`
	HideEmail      *bool          `json:"hideEmail"`
	ExpirationDate *string        `json:"expirationDate"`
	DeletionDate   string         `json:"deletionDate"`
	RevisionDate   string         `json:"revisionDate"`
	Text           *SendTextData  `json:"text"`
	File           map[string]any `json:"file"`
}

// ListSends returns all sends for the current user.
func (c *Client) ListSends() ([]SendResponse, error) {
	c.logger.Info("listing sends")
	var resp struct {
		Data []SendResponse `json:"data"`
	}
	err := c.doRequest(http.MethodGet, "/api/sends", nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: list sends: %w", err)
	}
	return resp.Data, nil
}

// GetSend returns a single Send by ID.
func (c *Client) GetSend(id string) (*SendResponse, error) {
	c.logger.Info("getting send", "id", id)
	var resp SendResponse
	err := c.doRequest(http.MethodGet, "/api/sends/"+id, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: get send: %w", err)
	}
	return &resp, nil
}

// CreateSend creates a new text Send.
func (c *Client) CreateSend(req *SendRequest) (*SendResponse, error) {
	c.logger.Info("creating send")
	var resp SendResponse
	err := c.doRequest(http.MethodPost, "/api/sends", req, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: create send: %w", err)
	}
	return &resp, nil
}

// UpdateSend updates an existing Send.
func (c *Client) UpdateSend(id string, req *SendRequest) (*SendResponse, error) {
	c.logger.Info("updating send", "id", id)
	var resp SendResponse
	err := c.doRequest(http.MethodPut, "/api/sends/"+id, req, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: update send: %w", err)
	}
	return &resp, nil
}

// DeleteSend deletes a Send.
func (c *Client) DeleteSend(id string) error {
	c.logger.Info("deleting send", "id", id)
	err := c.doRequest(http.MethodDelete, "/api/sends/"+id, nil, nil)
	if err != nil {
		return fmt.Errorf("api: delete send: %w", err)
	}
	return nil
}

// RemoveSendPassword removes the password from a Send.
func (c *Client) RemoveSendPassword(id string) error {
	c.logger.Info("removing send password", "id", id)
	err := c.doRequest(http.MethodPut, "/api/sends/"+id+"/remove-password", nil, nil)
	if err != nil {
		return fmt.Errorf("api: remove send password: %w", err)
	}
	return nil
}

// SendAccessRequest is the request to access a Send.
type SendAccessRequest struct {
	Password *string `json:"password,omitempty"`
}

// SendAccessResponse is the response when accessing a Send.
type SendAccessResponse struct {
	ID   string         `json:"id"`
	Type int            `json:"type"`
	Name string         `json:"name"`
	Text *SendTextData  `json:"text"`
	File map[string]any `json:"file"`
	Key  string         `json:"key"`
}

// AccessSend accesses a Send by its access ID (recipient side).
func (c *Client) AccessSend(accessID string, req *SendAccessRequest) (*SendAccessResponse, error) {
	c.logger.Info("accessing send", "accessID", accessID)
	var resp SendAccessResponse
	err := c.doRequest(http.MethodPost, "/api/sends/access/"+accessID, req, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: access send: %w", err)
	}
	return &resp, nil
}
