package api

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
)

// AdminUser represents a user returned by the Vaultwarden admin API.
type AdminUser struct {
	ID               string              `json:"id"`
	Email            string              `json:"email"`
	Name             string              `json:"name"`
	Enabled          bool                `json:"userEnabled"`
	EmailVerified    bool                `json:"emailVerified"`
	CreatedAt        string              `json:"createdAt"`
	LastActive       string              `json:"lastActive"`
	TwoFactorEnabled bool                `json:"twoFactorEnabled"`
	Organizations    []AdminOrganization `json:"organizations"`
}

// AdminOrganization represents an organization returned by the Vaultwarden admin API.
type AdminOrganization struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	BillingEmail string `json:"billingEmail"`
}

// AdminClient is the HTTP client for the Vaultwarden admin API.
// It uses cookie-based authentication via the /admin endpoint.
type AdminClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
	mu         sync.RWMutex
}

// NewAdminClient creates a new admin API client for the given server URL.
func NewAdminClient(baseURL string, logger *slog.Logger) *AdminClient {
	if logger == nil {
		logger = slog.Default()
	}
	jar, _ := cookiejar.New(nil)
	return &AdminClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Jar: jar,
			// Don't follow redirects automatically; we need to inspect responses
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger: logger,
	}
}

// SetInsecureSkipVerify enables bypassing TLS certificate verification.
func (c *AdminClient) SetInsecureSkipVerify(skip bool) {
	if skip {
		t := http.DefaultTransport.(*http.Transport).Clone()
		if t.TLSClientConfig == nil {
			t.TLSClientConfig = &tls.Config{}
		}
		t.TLSClientConfig.InsecureSkipVerify = true
		c.httpClient.Transport = t
	}
}

// Login authenticates with the admin panel using the admin token.
// Vaultwarden's admin API uses a POST to /admin with the token,
// which sets a session cookie for subsequent requests.
func (c *AdminClient) Login(adminToken string) error {
	formData := "token=" + adminToken
	url := c.baseURL + "/admin"

	c.logger.Debug("Admin login", "url", url)

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(formData))
	if err != nil {
		return fmt.Errorf("admin: create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("admin: login request: %w", err)
	}
	defer resp.Body.Close()

	// A successful login will redirect (303) and a VW_ADMIN cookie will be set
	if resp.StatusCode >= 400 {
		return fmt.Errorf("admin: login failed with status %d", resp.StatusCode)
	}

	c.logger.Debug("Admin login successful", "status", resp.StatusCode)
	return nil
}

// doRequest is the admin-specific JSON request helper.
// It reuses the cookie jar established during Login().
func (c *AdminClient) doRequest(method, path string, body any, result any) error {
	// Reuse the main client.go's doRequestRaw logic via a temporary Client
	// but with the admin cookie jar. We create a lightweight wrapper.
	wrapper := &Client{
		baseURL:    c.baseURL,
		httpClient: c.httpClient,
		logger:     c.logger,
	}
	return wrapper.doRequest(method, path, body, result)
}

// ListUsers returns all users via the admin API.
func (c *AdminClient) ListUsers() ([]AdminUser, error) {
	var users []AdminUser
	if err := c.doRequest(http.MethodGet, "/admin/users", nil, &users); err != nil {
		return nil, fmt.Errorf("admin: list users: %w", err)
	}
	return users, nil
}

// GetUser returns a specific user by ID via the admin API.
func (c *AdminClient) GetUser(userID string) (*AdminUser, error) {
	var user AdminUser
	if err := c.doRequest(http.MethodGet, "/admin/users/"+userID, nil, &user); err != nil {
		return nil, fmt.Errorf("admin: get user: %w", err)
	}
	return &user, nil
}

// InviteUser invites a new user via the admin API.
func (c *AdminClient) InviteUser(email string) error {
	body := map[string]string{"email": email}
	if err := c.doRequest(http.MethodPost, "/admin/invite", body, nil); err != nil {
		return fmt.Errorf("admin: invite user: %w", err)
	}
	return nil
}

// DeleteUser deletes a user via the admin API.
func (c *AdminClient) DeleteUser(userID string) error {
	if err := c.doRequest(http.MethodPost, "/admin/users/"+userID+"/delete", nil, nil); err != nil {
		return fmt.Errorf("admin: delete user: %w", err)
	}
	return nil
}

// DisableUser disables a user via the admin API.
func (c *AdminClient) DisableUser(userID string) error {
	if err := c.doRequest(http.MethodPost, "/admin/users/"+userID+"/disable", nil, nil); err != nil {
		return fmt.Errorf("admin: disable user: %w", err)
	}
	return nil
}

// EnableUser enables a user via the admin API.
func (c *AdminClient) EnableUser(userID string) error {
	if err := c.doRequest(http.MethodPost, "/admin/users/"+userID+"/enable", nil, nil); err != nil {
		return fmt.Errorf("admin: enable user: %w", err)
	}
	return nil
}

// DeauthUser deauthenticates all sessions for a user via the admin API.
func (c *AdminClient) DeauthUser(userID string) error {
	if err := c.doRequest(http.MethodPost, "/admin/users/"+userID+"/deauth", nil, nil); err != nil {
		return fmt.Errorf("admin: deauth user: %w", err)
	}
	return nil
}

// Remove2FA removes two-factor authentication for a user via the admin API.
func (c *AdminClient) Remove2FA(userID string) error {
	if err := c.doRequest(http.MethodPost, "/admin/users/"+userID+"/remove-2fa", nil, nil); err != nil {
		return fmt.Errorf("admin: remove 2fa: %w", err)
	}
	return nil
}

// ResendInvite re-sends the invitation email for a user via the admin API.
func (c *AdminClient) ResendInvite(userID string) error {
	if err := c.doRequest(http.MethodPost, "/admin/users/"+userID+"/invite/resend", nil, nil); err != nil {
		return fmt.Errorf("admin: resend invite: %w", err)
	}
	return nil
}

// ListOrganizations returns all organizations via the admin API.
// Since Vaultwarden doesn't seem to have a dedicated JSON endpoint for organizations,
// we extract them from the user list.
func (c *AdminClient) ListOrganizations() ([]AdminOrganization, error) {
	users, err := c.ListUsers()
	if err != nil {
		return nil, err
	}
	orgMap := make(map[string]AdminOrganization)
	for _, u := range users {
		for _, o := range u.Organizations {
			if _, ok := orgMap[o.ID]; !ok {
				orgMap[o.ID] = o
			}
		}
	}
	orgs := make([]AdminOrganization, 0, len(orgMap))
	for _, o := range orgMap {
		orgs = append(orgs, o)
	}
	return orgs, nil
}

// DeleteOrganization deletes an organization via the admin API.
func (c *AdminClient) DeleteOrganization(orgID string) error {
	if err := c.doRequest(http.MethodPost, "/admin/organizations/"+orgID+"/delete", nil, nil); err != nil {
		return fmt.Errorf("admin: delete organization: %w", err)
	}
	return nil
}
