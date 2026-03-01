package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// OrgImportMember represents a member entry in the org import request.
type OrgImportMember struct {
	Email      string `json:"email"`
	ExternalID string `json:"externalId"`
	Deleted    bool   `json:"deleted"`
}

// OrgImportGroup represents a group entry in the org import request.
type OrgImportGroup struct {
	Name              string   `json:"name"`
	ExternalID        string   `json:"externalId"`
	MemberExternalIDs []string `json:"memberExternalIds"`
}

// OrgImportRequest is the request body for POST /public/organization/import.
type OrgImportRequest struct {
	Groups            []OrgImportGroup  `json:"groups"`
	Members           []OrgImportMember `json:"members"`
	OverwriteExisting bool              `json:"overwriteExisting"`
}

// PublicClient is the HTTP client for the Bitwarden/Vaultwarden Public API.
// It authenticates via OAuth2 client credentials with scope api.organization.
type PublicClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
	client     *Client // reuse for doRequest
}

// NewPublicClient creates a new Public API client for the given server URL.
func NewPublicClient(baseURL string, logger *slog.Logger) *PublicClient {
	if logger == nil {
		logger = slog.Default()
	}
	c := NewClient(baseURL, logger)
	return &PublicClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: c.httpClient,
		logger:     logger,
		client:     c,
	}
}

// SetInsecureSkipVerify configures TLS for the public API client.
// It always enforces TLS 1.2 as minimum and optionally disables certificate verification.
func (p *PublicClient) SetInsecureSkipVerify(skip bool) {
	t := NewTLSTransport(skip)
	p.httpClient.Transport = t
	p.client.httpClient.Transport = t
}

// Login authenticates with the Public API using organization client credentials.
// The clientID must be in the format "organization.<org_uuid>".
func (p *PublicClient) Login(clientID, clientSecret string) error {
	p.logger.Info("public API login", "client_id", clientID)

	form := url.Values{
		"grant_type":       {"client_credentials"},
		"scope":            {"api.organization"},
		"client_id":        {clientID},
		"client_secret":    {clientSecret},
		"deviceType":       {"9"},
		"deviceIdentifier": {"govault-public"},
		"deviceName":       {"govault"},
	}

	var resp LoginResponse
	err := p.client.doFormRequest("/identity/connect/token", form.Encode(), &resp)
	if err != nil {
		return fmt.Errorf("public: login: %w", err)
	}

	p.client.SetTokens(resp.AccessToken, resp.RefreshToken)
	return nil
}

// Import performs a bulk organization import via POST /public/organization/import.
// This creates user accounts (if they don't exist), invites them into the
// organization, and optionally syncs groups.
func (p *PublicClient) Import(req *OrgImportRequest) error {
	p.logger.Info("public API import",
		"members", len(req.Members),
		"groups", len(req.Groups),
		"overwrite", req.OverwriteExisting,
	)
	if err := p.client.doRequest(http.MethodPost, "/api/public/organization/import", req, nil); err != nil {
		return fmt.Errorf("public: import: %w", err)
	}
	return nil
}

// GetOrgAPIKey retrieves the organization's API key.
// This uses the regular authenticated API (not the public API), so
// the caller must be logged in as an org owner.
func (c *Client) GetOrgAPIKey(orgID, masterPasswordHash string) (string, string, error) {
	c.logger.Info("getting org API key", "orgID", orgID)

	req := map[string]string{
		"masterPasswordHash": masterPasswordHash,
	}
	var resp struct {
		APIKey string `json:"apiKey"`
	}
	path := fmt.Sprintf("/api/organizations/%s/api-key", orgID)
	if err := c.doRequest(http.MethodPost, path, req, &resp); err != nil {
		return "", "", fmt.Errorf("api: get org api key: %w", err)
	}

	clientID := "organization." + orgID
	return clientID, resp.APIKey, nil
}
