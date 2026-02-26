package api

import (
	"fmt"
	"net/http"
)

// CreateOrgRequest is the request body for POST /api/organizations.
type CreateOrgRequest struct {
	Name           string      `json:"name"`
	BillingEmail   string      `json:"billingEmail"`
	CollectionName string      `json:"collectionName"`
	Key            string      `json:"key"`
	Keys           *OrgKeyData `json:"keys,omitempty"`
	PlanType       int         `json:"planType"`
}

// OrgKeyData holds the org RSA key pair.
type OrgKeyData struct {
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	PublicKey           string `json:"publicKey"`
}

// OrgResponse is the response for organization operations.
type OrgResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CreateOrganization creates a new organization.
func (c *Client) CreateOrganization(req *CreateOrgRequest) (*OrgResponse, error) {
	c.logger.Info("creating organization", "name", req.Name)
	var resp OrgResponse
	err := c.doRequest(http.MethodPost, "/api/organizations", req, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: create organization: %w", err)
	}
	return &resp, nil
}

// GetOrganization returns organization details.
func (c *Client) GetOrganization(orgID string) (*OrgResponse, error) {
	c.logger.Info("getting organization", "orgID", orgID)
	var resp OrgResponse
	err := c.doRequest(http.MethodGet, "/api/organizations/"+orgID, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: get organization: %w", err)
	}
	return &resp, nil
}

// DeleteOrganization deletes an organization.
type DeleteOrgRequest struct {
	MasterPasswordHash string `json:"masterPasswordHash"`
}

func (c *Client) DeleteOrganization(orgID string, req *DeleteOrgRequest) error {
	c.logger.Info("deleting organization", "orgID", orgID)
	err := c.doRequest(http.MethodDelete, "/api/organizations/"+orgID, req, nil)
	if err != nil {
		return fmt.Errorf("api: delete organization: %w", err)
	}
	return nil
}

// InviteRequest is the request body for inviting members to an org.
type InviteRequest struct {
	Emails      []string              `json:"emails"`
	Type        int                   `json:"type"`
	Collections []CollectionSelection `json:"collections,omitempty"`
	AccessAll   bool                  `json:"accessAll"`
	Groups      []string              `json:"groups"`
}

// CollectionSelection specifies access for a collection.
type CollectionSelection struct {
	ID            string `json:"id"`
	ReadOnly      bool   `json:"readOnly"`
	HidePasswords bool   `json:"hidePasswords"`
	Manage        bool   `json:"manage"`
}

// InviteToOrganization invites users to an organization.
func (c *Client) InviteToOrganization(orgID string, req *InviteRequest) error {
	c.logger.Info("inviting to organization", "orgID", orgID, "emails", req.Emails)
	err := c.doRequest(http.MethodPost, "/api/organizations/"+orgID+"/users/invite", req, nil)
	if err != nil {
		return fmt.Errorf("api: invite to org: %w", err)
	}
	return nil
}

// AcceptOrgInviteRequest is the request to accept an org invite.
type AcceptOrgInviteRequest struct {
	Token string `json:"token"`
}

// AcceptOrgInvite accepts an organization invite.
func (c *Client) AcceptOrgInvite(orgID, orgUserID string, req *AcceptOrgInviteRequest) error {
	c.logger.Info("accepting org invite", "orgID", orgID, "orgUserID", orgUserID)
	path := fmt.Sprintf("/api/organizations/%s/users/%s/accept", orgID, orgUserID)
	err := c.doRequest(http.MethodPost, path, req, nil)
	if err != nil {
		return fmt.Errorf("api: accept org invite: %w", err)
	}
	return nil
}

// ConfirmMemberRequest is the request to confirm an org member.
type ConfirmMemberRequest struct {
	Key string `json:"key"`
}

// ConfirmOrgMember confirms a pending organization member.
func (c *Client) ConfirmOrgMember(orgID, memberID string, req *ConfirmMemberRequest) error {
	c.logger.Info("confirming org member", "orgID", orgID, "memberID", memberID)
	path := fmt.Sprintf("/api/organizations/%s/users/%s/confirm", orgID, memberID)
	err := c.doRequest(http.MethodPost, path, req, nil)
	if err != nil {
		return fmt.Errorf("api: confirm org member: %w", err)
	}
	return nil
}

// BulkConfirmData is a single entry in a bulk confirm request.
type BulkConfirmData struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// BulkConfirmRequest is the request for POST /api/organizations/{id}/users/confirm.
type BulkConfirmRequest struct {
	Keys []BulkConfirmData `json:"keys"`
}

// BulkConfirmOrgMembers confirms multiple org members at once.
func (c *Client) BulkConfirmOrgMembers(orgID string, req *BulkConfirmRequest) error {
	c.logger.Info("bulk confirming org members", "orgID", orgID, "count", len(req.Keys))
	path := fmt.Sprintf("/api/organizations/%s/users/confirm", orgID)
	err := c.doRequest(http.MethodPost, path, req, nil)
	if err != nil {
		return fmt.Errorf("api: bulk confirm org members: %w", err)
	}
	return nil
}

// OrgMember represents an organization member.
type OrgMember struct {
	ID     string `json:"id"`
	UserID string `json:"userId"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Type   int    `json:"type"`
	Status int    `json:"status"`
}

// ListOrgMembers returns all members of an organization.
func (c *Client) ListOrgMembers(orgID string) ([]OrgMember, error) {
	c.logger.Info("listing org members", "orgID", orgID)
	var resp struct {
		Data []OrgMember `json:"data"`
	}
	err := c.doRequest(http.MethodGet, "/api/organizations/"+orgID+"/users", nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: list org members: %w", err)
	}
	return resp.Data, nil
}

// RemoveOrgMember removes a member from an organization.
func (c *Client) RemoveOrgMember(orgID, memberID string) error {
	c.logger.Info("removing org member", "orgID", orgID, "memberID", memberID)
	path := fmt.Sprintf("/api/organizations/%s/users/%s", orgID, memberID)
	err := c.doRequest(http.MethodDelete, path, nil, nil)
	if err != nil {
		return fmt.Errorf("api: remove org member: %w", err)
	}
	return nil
}

// PublicKeyResponse is a member's public key response.
type PublicKeyResponse struct {
	ID     string `json:"id"`
	UserID string `json:"userId"`
	Key    string `json:"key"`
}

// BulkPublicKeysRequest is the request to get multiple members' public keys.
type BulkPublicKeysRequest struct {
	IDs []string `json:"ids"`
}

// GetOrgMemberPublicKeys returns the public keys of org members.
func (c *Client) GetOrgMemberPublicKeys(orgID string, memberIDs []string) ([]PublicKeyResponse, error) {
	c.logger.Info("getting member public keys", "orgID", orgID)
	var resp struct {
		Data []PublicKeyResponse `json:"data"`
	}
	req := BulkPublicKeysRequest{IDs: memberIDs}
	path := fmt.Sprintf("/api/organizations/%s/users/public-keys", orgID)
	err := c.doRequest(http.MethodPost, path, req, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: get member public keys: %w", err)
	}
	return resp.Data, nil
}

// GetOrgCiphers returns all organization ciphers.
func (c *Client) GetOrgCiphers(orgID string) ([]map[string]any, error) {
	c.logger.Info("getting org ciphers", "orgID", orgID)
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	err := c.doRequest(http.MethodGet, "/api/ciphers/organization-details?organizationId="+orgID, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: get org ciphers: %w", err)
	}
	return resp.Data, nil
}
