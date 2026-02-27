package api

import (
	"fmt"
	"net/http"
)

// GroupResponse represents a group returned by the API.
type GroupResponse struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	AccessAll      bool   `json:"accessAll"`
	ExternalID     string `json:"externalId,omitempty"`
}

// GroupRequest is the body for creating/updating a group.
type GroupRequest struct {
	Name        string                `json:"name"`
	AccessAll   bool                  `json:"accessAll"`
	ExternalID  string                `json:"externalId,omitempty"`
	Collections []CollectionSelection `json:"collections"`
}

// ListGroups returns all groups for an organization.
func (c *Client) ListGroups(orgID string) ([]GroupResponse, error) {
	c.logger.Info("listing groups", "orgID", orgID)
	var resp struct {
		Data []GroupResponse `json:"data"`
	}
	path := fmt.Sprintf("/api/organizations/%s/groups", orgID)
	err := c.doRequest(http.MethodGet, path, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: list groups: %w", err)
	}
	return resp.Data, nil
}

// CreateGroup creates a new group.
func (c *Client) CreateGroup(orgID string, req *GroupRequest) (*GroupResponse, error) {
	c.logger.Info("creating group", "orgID", orgID, "name", req.Name)
	var resp GroupResponse
	path := fmt.Sprintf("/api/organizations/%s/groups", orgID)
	err := c.doRequest(http.MethodPost, path, req, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: create group: %w", err)
	}
	return &resp, nil
}

// UpdateGroup updates an existing group.
func (c *Client) UpdateGroup(orgID, groupID string, req *GroupRequest) (*GroupResponse, error) {
	c.logger.Info("updating group", "orgID", orgID, "groupID", groupID)
	var resp GroupResponse
	path := fmt.Sprintf("/api/organizations/%s/groups/%s", orgID, groupID)
	err := c.doRequest(http.MethodPut, path, req, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: update group: %w", err)
	}
	return &resp, nil
}

// DeleteGroup deletes a group.
func (c *Client) DeleteGroup(orgID, groupID string) error {
	c.logger.Info("deleting group", "orgID", orgID, "groupID", groupID)
	path := fmt.Sprintf("/api/organizations/%s/groups/%s", orgID, groupID)
	err := c.doRequest(http.MethodDelete, path, nil, nil)
	if err != nil {
		return fmt.Errorf("api: delete group: %w", err)
	}
	return nil
}
