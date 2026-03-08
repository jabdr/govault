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
	Users       []string              `json:"users"`
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

// ListGroupMembers returns the membership IDs of users in a group.
func (c *Client) ListGroupMembers(orgID, groupID string) ([]string, error) {
	c.logger.Info("listing group members", "orgID", orgID, "groupID", groupID)
	var memberIDs []string
	path := fmt.Sprintf("/api/organizations/%s/groups/%s/users", orgID, groupID)
	err := c.doRequest(http.MethodGet, path, nil, &memberIDs)
	if err != nil {
		return nil, fmt.Errorf("api: list group members: %w", err)
	}
	return memberIDs, nil
}

// SetGroupMembers replaces the full set of members in a group.
func (c *Client) SetGroupMembers(orgID, groupID string, memberIDs []string) error {
	c.logger.Info("setting group members", "orgID", orgID, "groupID", groupID, "count", len(memberIDs))
	path := fmt.Sprintf("/api/organizations/%s/groups/%s/users", orgID, groupID)
	err := c.doRequest(http.MethodPut, path, memberIDs, nil)
	if err != nil {
		return fmt.Errorf("api: set group members: %w", err)
	}
	return nil
}

// RemoveGroupMember removes a single member from a group.
func (c *Client) RemoveGroupMember(orgID, groupID, memberID string) error {
	c.logger.Info("removing group member", "orgID", orgID, "groupID", groupID, "memberID", memberID)
	path := fmt.Sprintf("/api/organizations/%s/groups/%s/delete-user/%s", orgID, groupID, memberID)
	err := c.doRequest(http.MethodPost, path, nil, nil)
	if err != nil {
		return fmt.Errorf("api: remove group member: %w", err)
	}
	return nil
}
