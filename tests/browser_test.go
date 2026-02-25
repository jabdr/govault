//go:build integration

package tests

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jabdr/govault/pkg/vault"
)

// TestAPIToUI verifies that a cipher created via the Go API client
// is correctly visible and decrypted in the Vaultwarden Web UI.
func TestAPIToUI(t *testing.T) {
	// Skip browser tests if asked
	if os.Getenv("SKIP_BROWSER_TESTS") == "1" {
		t.Skip("SKIP_BROWSER_TESTS is set")
	}

	email := "api2ui@example.com"
	password := "browser-pass-123"

	// 1. Setup server and register user via API
	RegisterTestUser(t, testServer, email, password)

	// 2. Use API client to CreateCipher
	v := APILogin(t, testServer, email, password)

	cipherName := "Secret API Cipher"
	c := vault.NewCipher(vault.CipherTypeLogin, cipherName)
	c.SetLogin("apibot", "apipass")
	err := v.CreateCipher(c)
	require.NoError(t, err, "CreateCipher from API")
	t.Logf("Created cipher via API: %s", c.ID())

	// 3. Spin up Playwright page
	_, _, page := SetupPlaywright(t)

	// 4. Browser Login
	BrowserLogin(t, page, testServer, email, password)

	// Wait for vault to sync (we wait for text "All items")
	// The helper `BrowserLogin` already waits for "All items" to appear.
	// But it might take a second for ciphers to populate.
	time.Sleep(2 * time.Second)

	// 5. Verify the created cipher appears in the Web UI
	exists := BrowserCheckCipherExists(t, page, cipherName)
	assert.True(t, exists, "Expected cipher '%s' to be visible in the Web UI", cipherName)
}

// TestUIToAPI verifies that a cipher created via the Vaultwarden Web UI
// can be synced and successfully decrypted by the Go API client.
func TestUIToAPI(t *testing.T) {
	if os.Getenv("SKIP_BROWSER_TESTS") == "1" {
		t.Skip("SKIP_BROWSER_TESTS is set")
	}

	email := "ui2api@example.com"
	password := "browser-pass-123"

	// 1. Setup server and register user via API (to save time on UI registration)
	RegisterTestUser(t, testServer, email, password)

	// 2. Spin up Playwright page
	_, _, page := SetupPlaywright(t)

	// 3. Browser Login & Create Cipher
	BrowserLogin(t, page, testServer, email, password)

	cipherName := "Secret UI Cipher"
	BrowserCreateCipher(t, page, cipherName, "uibot", "uipass")
	t.Log("Created cipher via UI")

	// Allow server enough time to persist and index the new cipher
	time.Sleep(2 * time.Second)

	// 4. Use API client to Login (which triggers a Sync automatically)
	v := APILogin(t, testServer, email, password)

	// 5. Verify the cipher exists and is decrypted via the API
	ciphers, err := v.ListCiphers()
	require.NoError(t, err, "ListCiphers")

	// Print all found ciphers for debugging
	var foundNames []string
	found := false
	for _, c := range ciphers {
		foundNames = append(foundNames, c.Name())
		if c.Name() == cipherName {
			found = true

			// Verify fields
			if c.Type() == vault.CipherTypeLogin {
				username, pwd, err := c.GetLogin()
				require.NoError(t, err, "GetLogin")
				assert.Equal(t, "uibot", username, "Username mismatch")
				assert.Equal(t, "uipass", pwd, "Password mismatch")
			}
			break
		}
	}
	assert.True(t, found, "Expected to find cipher '%s' via API sync, found: %v", cipherName, foundNames)
}
