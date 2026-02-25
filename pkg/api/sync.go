package api

import (
	"fmt"
	"net/http"
)

// SyncProfile contains profile information from a sync response.
type SyncProfile struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"emailVerified"`
	Premium       bool      `json:"premium"`
	Key           string    `json:"key"`
	PrivateKey    string    `json:"privateKey"`
	SecurityStamp string    `json:"securityStamp"`
	Organizations []SyncOrg `json:"organizations"`
}

// SyncOrg is an organization entry in the sync profile.
type SyncOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

// SyncFolder is a folder entry in a sync response.
type SyncFolder struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	RevisionDate string `json:"revisionDate"`
}

// SyncResponse contains all data returned by a full vault sync.
type SyncResponse struct {
	Profile     SyncProfile      `json:"profile"`
	Ciphers     []map[string]any `json:"ciphers"`
	Folders     []SyncFolder     `json:"folders"`
	Collections []map[string]any `json:"collections"`
	Sends       []map[string]any `json:"sends"`
}

// Sync performs a full vault sync, returning all profile data, ciphers,
// folders, collections, and sends.
func (c *Client) Sync() (*SyncResponse, error) {
	c.logger.Info("syncing vault")
	var resp SyncResponse
	err := c.doRequest(http.MethodGet, "/api/sync", nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("api: sync: %w", err)
	}
	return &resp, nil
}
