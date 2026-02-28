package api

import (
	"fmt"
	"net/http"
)

// FolderResponse represents a folder returned by the API.
type FolderResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	RevisionDate string `json:"revisionDate"`
}

// FolderRequest is the request body for creating or updating a folder.
type FolderRequest struct {
	Name string `json:"name"`
}

// ListFolders returns all folders for the authenticated user.
func (c *Client) ListFolders() ([]FolderResponse, error) {
	c.logger.Info("listing folders")
	var resp struct {
		Data []FolderResponse `json:"data"`
	}
	err := c.doRequest(http.MethodGet, "/api/folders", nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: list folders: %w", err)
	}
	return resp.Data, nil
}

// CreateFolder creates a new folder.
func (c *Client) CreateFolder(req *FolderRequest) (*FolderResponse, error) {
	c.logger.Info("creating folder")
	var resp FolderResponse
	err := c.doRequest(http.MethodPost, "/api/folders", req, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: create folder: %w", err)
	}
	return &resp, nil
}

// UpdateFolder updates a folder's name.
func (c *Client) UpdateFolder(id string, req *FolderRequest) (*FolderResponse, error) {
	c.logger.Info("updating folder", "id", id)
	var resp FolderResponse
	err := c.doRequest(http.MethodPut, "/api/folders/"+id, req, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: update folder: %w", err)
	}
	return &resp, nil
}

// DeleteFolder deletes a folder by ID.
func (c *Client) DeleteFolder(id string) error {
	c.logger.Info("deleting folder", "id", id)
	err := c.doRequest(http.MethodDelete, "/api/folders/"+id, nil, nil)
	if err != nil {
		return fmt.Errorf("api: delete folder: %w", err)
	}
	return nil
}
