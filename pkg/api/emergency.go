package api

import (
	"fmt"
	"net/http"
)

// Emergency access status constants.
const (
	EmergencyAccessStatusInvited           = 0
	EmergencyAccessStatusAccepted          = 1
	EmergencyAccessStatusConfirmed         = 2
	EmergencyAccessStatusRecoveryInitiated = 3
	EmergencyAccessStatusRecoveryApproved  = 4
)

// Emergency access type constants.
const (
	EmergencyAccessTypeView     = 0
	EmergencyAccessTypeTakeover = 1
)

// EmergencyAccessResponse represents an emergency access grant.
type EmergencyAccessResponse struct {
	ID           string `json:"id"`
	GrantorID    string `json:"grantorId"`
	GranteeID    string `json:"granteeId"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	Type         int    `json:"type"`
	Status       int    `json:"status"`
	WaitTimeDays int    `json:"waitTimeDays"`
	KeyEncrypted string `json:"keyEncrypted"`
	CreationDate string `json:"creationDate"`
	RevisionDate string `json:"revisionDate"`
}

// ListTrustedEmergencyAccess returns emergency access grantees (grantor view).
func (c *Client) ListTrustedEmergencyAccess() ([]EmergencyAccessResponse, error) {
	c.logger.Info("listing trusted emergency access")
	var resp struct {
		Data []EmergencyAccessResponse `json:"data"`
	}
	err := c.doRequest(http.MethodGet, "/api/emergency-access/trusted", nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: list trusted emergency access: %w", err)
	}
	return resp.Data, nil
}

// ListGrantedEmergencyAccess returns emergency access grantors (grantee view).
func (c *Client) ListGrantedEmergencyAccess() ([]EmergencyAccessResponse, error) {
	c.logger.Info("listing granted emergency access")
	var resp struct {
		Data []EmergencyAccessResponse `json:"data"`
	}
	err := c.doRequest(http.MethodGet, "/api/emergency-access/granted", nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: list granted emergency access: %w", err)
	}
	return resp.Data, nil
}

// GetEmergencyAccess returns details of a single emergency access grant.
func (c *Client) GetEmergencyAccess(id string) (*EmergencyAccessResponse, error) {
	c.logger.Info("getting emergency access", "id", id)
	var resp EmergencyAccessResponse
	err := c.doRequest(http.MethodGet, "/api/emergency-access/"+id, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: get emergency access: %w", err)
	}
	return &resp, nil
}

// EmergencyAccessInviteRequest is the request to invite an emergency contact.
type EmergencyAccessInviteRequest struct {
	Email        string `json:"email"`
	Type         int    `json:"type"`
	WaitTimeDays int    `json:"waitTimeDays"`
}

// InviteEmergencyAccess invites a new emergency contact.
func (c *Client) InviteEmergencyAccess(req *EmergencyAccessInviteRequest) error {
	c.logger.Info("inviting emergency access", "email", req.Email)
	err := c.doRequest(http.MethodPost, "/api/emergency-access/invite", req, nil)
	if err != nil {
		return fmt.Errorf("api: invite emergency access: %w", err)
	}
	return nil
}

// ReinviteEmergencyAccess resends the invitation.
func (c *Client) ReinviteEmergencyAccess(id string) error {
	c.logger.Info("reinviting emergency access", "id", id)
	err := c.doRequest(http.MethodPost, "/api/emergency-access/"+id+"/reinvite", nil, nil)
	if err != nil {
		return fmt.Errorf("api: reinvite emergency access: %w", err)
	}
	return nil
}

// EmergencyAccessAcceptRequest is the request to accept an invitation.
type EmergencyAccessAcceptRequest struct {
	Token string `json:"token"`
}

// AcceptEmergencyAccess accepts an emergency access invitation.
func (c *Client) AcceptEmergencyAccess(id string, req *EmergencyAccessAcceptRequest) error {
	c.logger.Info("accepting emergency access", "id", id)
	err := c.doRequest(http.MethodPost, "/api/emergency-access/"+id+"/accept", req, nil)
	if err != nil {
		return fmt.Errorf("api: accept emergency access: %w", err)
	}
	return nil
}

// EmergencyAccessConfirmRequest is the request to confirm a grantee.
type EmergencyAccessConfirmRequest struct {
	Key string `json:"key"`
}

// ConfirmEmergencyAccess confirms an emergency access grantee (grantor sends RSA-encrypted key).
func (c *Client) ConfirmEmergencyAccess(id string, req *EmergencyAccessConfirmRequest) error {
	c.logger.Info("confirming emergency access", "id", id)
	err := c.doRequest(http.MethodPost, "/api/emergency-access/"+id+"/confirm", req, nil)
	if err != nil {
		return fmt.Errorf("api: confirm emergency access: %w", err)
	}
	return nil
}

// UpdateEmergencyAccessRequest is the request to update emergency access settings.
type UpdateEmergencyAccessRequest struct {
	Type         int `json:"type"`
	WaitTimeDays int `json:"waitTimeDays"`
}

// UpdateEmergencyAccess updates an emergency access grant.
func (c *Client) UpdateEmergencyAccess(id string, req *UpdateEmergencyAccessRequest) error {
	c.logger.Info("updating emergency access", "id", id)
	err := c.doRequest(http.MethodPut, "/api/emergency-access/"+id, req, nil)
	if err != nil {
		return fmt.Errorf("api: update emergency access: %w", err)
	}
	return nil
}

// DeleteEmergencyAccess revokes/deletes an emergency access grant.
func (c *Client) DeleteEmergencyAccess(id string) error {
	c.logger.Info("deleting emergency access", "id", id)
	err := c.doRequest(http.MethodDelete, "/api/emergency-access/"+id, nil, nil)
	if err != nil {
		return fmt.Errorf("api: delete emergency access: %w", err)
	}
	return nil
}

// InitiateEmergencyAccess starts the emergency access countdown (grantee).
func (c *Client) InitiateEmergencyAccess(id string) error {
	c.logger.Info("initiating emergency access", "id", id)
	err := c.doRequest(http.MethodPost, "/api/emergency-access/"+id+"/initiate", nil, nil)
	if err != nil {
		return fmt.Errorf("api: initiate emergency access: %w", err)
	}
	return nil
}

// ApproveEmergencyAccess approves an emergency access request (grantor).
func (c *Client) ApproveEmergencyAccess(id string) error {
	c.logger.Info("approving emergency access", "id", id)
	err := c.doRequest(http.MethodPost, "/api/emergency-access/"+id+"/approve", nil, nil)
	if err != nil {
		return fmt.Errorf("api: approve emergency access: %w", err)
	}
	return nil
}

// RejectEmergencyAccess rejects an emergency access request (grantor).
func (c *Client) RejectEmergencyAccess(id string) error {
	c.logger.Info("rejecting emergency access", "id", id)
	err := c.doRequest(http.MethodPost, "/api/emergency-access/"+id+"/reject", nil, nil)
	if err != nil {
		return fmt.Errorf("api: reject emergency access: %w", err)
	}
	return nil
}

// EmergencyAccessViewResponse is the response for viewing a grantor's vault.
type EmergencyAccessViewResponse struct {
	Ciphers      []map[string]any `json:"ciphers"`
	KeyEncrypted string           `json:"keyEncrypted"`
}

// ViewEmergencyAccess retrieves the grantor's vault ciphers (grantee, after approval).
func (c *Client) ViewEmergencyAccess(id string) (*EmergencyAccessViewResponse, error) {
	c.logger.Info("viewing emergency access vault", "id", id)
	var resp EmergencyAccessViewResponse
	err := c.doRequest(http.MethodPost, "/api/emergency-access/"+id+"/view", nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: view emergency access: %w", err)
	}
	return &resp, nil
}

// EmergencyAccessTakeoverResponse contains KDF params and encrypted key for takeover.
type EmergencyAccessTakeoverResponse struct {
	Kdf            int    `json:"kdf"`
	KdfIterations  int    `json:"kdfIterations"`
	KdfMemory      *int   `json:"kdfMemory"`
	KdfParallelism *int   `json:"kdfParallelism"`
	KeyEncrypted   string `json:"keyEncrypted"`
}

// TakeoverEmergencyAccess gets the takeover data (KDF params + encrypted key).
func (c *Client) TakeoverEmergencyAccess(id string) (*EmergencyAccessTakeoverResponse, error) {
	c.logger.Info("taking over emergency access", "id", id)
	var resp EmergencyAccessTakeoverResponse
	err := c.doRequest(http.MethodPost, "/api/emergency-access/"+id+"/takeover", nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: takeover emergency access: %w", err)
	}
	return &resp, nil
}

// EmergencyAccessPasswordRequest is the request to set a new password on takeover.
type EmergencyAccessPasswordRequest struct {
	NewMasterPasswordHash string `json:"newMasterPasswordHash"`
	Key                   string `json:"key"`
}

// SetEmergencyAccessPassword sets a new master password on the grantor account (takeover).
func (c *Client) SetEmergencyAccessPassword(id string, req *EmergencyAccessPasswordRequest) error {
	c.logger.Info("setting emergency access password", "id", id)
	err := c.doRequest(http.MethodPost, "/api/emergency-access/"+id+"/password", req, nil)
	if err != nil {
		return fmt.Errorf("api: set emergency access password: %w", err)
	}
	return nil
}
