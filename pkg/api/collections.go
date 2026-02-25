package api

import (
	"fmt"
	"net/http"
)

// CollectionResponse represents a collection returned by the API.
type CollectionResponse struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	ExternalID     string `json:"externalId,omitempty"`
}

// CreateCollectionRequest is the request body for creating a collection.
type CreateCollectionRequest struct {
	Name       string                  `json:"name"`
	ExternalID string                  `json:"externalId,omitempty"`
	Groups     []CollectionGroupAccess `json:"groups,omitempty"`
	Users      []CollectionUserAccess  `json:"users,omitempty"`
}

// CollectionGroupAccess specifies group access to a collection.
type CollectionGroupAccess struct {
	ID            string `json:"id"`
	ReadOnly      bool   `json:"readOnly"`
	HidePasswords bool   `json:"hidePasswords"`
	Manage        bool   `json:"manage"`
}

// CollectionUserAccess specifies user access to a collection.
type CollectionUserAccess struct {
	ID            string `json:"id"`
	ReadOnly      bool   `json:"readOnly"`
	HidePasswords bool   `json:"hidePasswords"`
	Manage        bool   `json:"manage"`
}

// ListCollections returns all collections for an organization.
func (c *Client) ListCollections(orgID string) ([]CollectionResponse, error) {
	c.logger.Info("listing collections", "orgID", orgID)
	var resp struct {
		Data []CollectionResponse `json:"data"`
	}
	path := fmt.Sprintf("/api/organizations/%s/collections", orgID)
	err := c.doRequest(http.MethodGet, path, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: list collections: %w", err)
	}
	return resp.Data, nil
}

// CreateCollection creates a new collection in an organization.
func (c *Client) CreateCollection(orgID string, req *CreateCollectionRequest) (*CollectionResponse, error) {
	c.logger.Info("creating collection", "orgID", orgID)
	var resp CollectionResponse
	path := fmt.Sprintf("/api/organizations/%s/collections", orgID)
	err := c.doRequest(http.MethodPost, path, req, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: create collection: %w", err)
	}
	return &resp, nil
}

// UpdateCollection updates an existing collection.
func (c *Client) UpdateCollection(orgID, collectionID string, req *CreateCollectionRequest) (*CollectionResponse, error) {
	c.logger.Info("updating collection", "orgID", orgID, "collectionID", collectionID)
	var resp CollectionResponse
	path := fmt.Sprintf("/api/organizations/%s/collections/%s", orgID, collectionID)
	err := c.doRequest(http.MethodPut, path, req, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: update collection: %w", err)
	}
	return &resp, nil
}

// DeleteCollection deletes a collection from an organization.
func (c *Client) DeleteCollection(orgID, collectionID string) error {
	c.logger.Info("deleting collection", "orgID", orgID, "collectionID", collectionID)
	path := fmt.Sprintf("/api/organizations/%s/collections/%s", orgID, collectionID)
	err := c.doRequest(http.MethodDelete, path, nil, nil)
	if err != nil {
		return fmt.Errorf("api: delete collection: %w", err)
	}
	return nil
}

// GetCollectionUsers returns the users with access to a collection.
func (c *Client) GetCollectionUsers(orgID, collectionID string) ([]CollectionUserAccess, error) {
	c.logger.Info("getting collection users", "orgID", orgID, "collectionID", collectionID)
	var resp []CollectionUserAccess
	path := fmt.Sprintf("/api/organizations/%s/collections/%s/users", orgID, collectionID)
	err := c.doRequest(http.MethodGet, path, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: get collection users: %w", err)
	}
	return resp, nil
}
