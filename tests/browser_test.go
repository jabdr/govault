//go:build integration

package tests

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jabdr/govault/pkg/vault"
)

// TestAPIToUI verifies that a cipher created via the Go API client
// is correctly visible and decrypted in the Vaultwarden Web UI.
func TestAPIToUI(t *testing.T) {
	t.Parallel()
	// Skip browser tests if asked
	if os.Getenv("SKIP_BROWSER_TESTS") == "1" {
		t.Skip("SKIP_BROWSER_TESTS is set")
	}

	email := fmt.Sprintf("api2ui-%d@example.com", time.Now().UnixNano())
	password := "browser-pass-123"

	// 1. Setup server and register user via API
	RegisterTestUser(t, testServer, email, password)

	// 2. Use API client to CreateCipher
	v := APILogin(t, testServer, email, password)

	cipherName := "Secret API Cipher"
	c, _ := vault.NewCipher(vault.CipherTypeLogin, cipherName, v.SymmetricKey())
	c.SetLoginUsername("apibot")
	c.SetLoginPassword("apipass")
	err := v.CreateCipher(c)
	require.NoError(t, err, "CreateCipher from API")
	t.Logf("Created cipher via API: %s", c.ID())

	// 3. Spin up Playwright page
	_, _, page := SetupPlaywright(t)

	// 4. Browser Login
	BrowserLogin(t, page, testServer, email, password)

	// 5. Verify the created cipher appears in the Web UI
	exists := BrowserCheckCipherExists(t, page, cipherName)
	assert.True(t, exists, "Expected cipher '%s' to be visible in the Web UI", cipherName)
}

// TestUIToAPI verifies that a cipher created via the Vaultwarden Web UI
// can be synced and successfully decrypted by the Go API client.
func TestUIToAPI(t *testing.T) {
	t.Parallel()
	if os.Getenv("SKIP_BROWSER_TESTS") == "1" {
		t.Skip("SKIP_BROWSER_TESTS is set")
	}

	email := fmt.Sprintf("ui2api-%d@example.com", time.Now().UnixNano())
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

// TestPasswordRotationBrowser verifies that after a password rotation,
// items created in the browser are still decrytable with the new password in the browser.
func TestPasswordRotationBrowser(t *testing.T) {
	t.Parallel()
	if os.Getenv("SKIP_BROWSER_TESTS") == "1" {
		t.Skip("SKIP_BROWSER_TESTS is set")
	}

	email := fmt.Sprintf("rotate-%d@example.com", time.Now().UnixNano())
	password := "old-pass-123"
	newPassword := "new-pass-456"

	// 1. Setup server and register user
	RegisterTestUser(t, testServer, email, password)
	v := APILogin(t, testServer, email, password)
	VerifyUserEmail(t, v, email)

	// 2. Spin up Playwright page
	_, browser, page := SetupPlaywright(t)

	// 3. Browser Login & Create Ciphers
	BrowserLogin(t, page, testServer, email, password)

	BrowserCreateCipher(t, page, "Rotation Login", "rotuser", "rotpass")
	BrowserCreateSecureNote(t, page, "Rotation Note", "rot secret notes")
	BrowserCreateCard(t, page, "Rotation Card", "John Doe", "1234567890123456")
	t.Log("Created ciphers via UI")

	// Close context to perform a clean login later
	_ = page.Context().Close()

	// 4. Change Password via API client
	err := v.ChangePassword(password, newPassword, 0, 600000, 64, 4)
	require.NoError(t, err, "ChangePassword should succeed")
	t.Log("Rotated password via API")

	// 5. Open new browser context and login with NEW password
	newContext, err := browser.NewContext(playwright.BrowserNewContextOptions{
		IgnoreHttpsErrors: playwright.Bool(true),
	})
	require.NoError(t, err)
	newContext.SetDefaultTimeout(10000)
	defer newContext.Close()

	newPage, err := newContext.NewPage()
	require.NoError(t, err)

	BrowserLogin(t, newPage, testServer, email, newPassword)

	BrowserVerifyCipherData(t, newPage, "Rotation Login", map[string]string{
		"username": "rotuser",
		"password": "rotpass",
	})
	BrowserVerifyCipherData(t, newPage, "Rotation Note", map[string]string{
		"notes": "rot secret notes",
	})
	BrowserVerifyCipherData(t, newPage, "Rotation Card", map[string]string{
		"cardholderName": "John Doe",
		"number":         "1234567890123456",
	})
	t.Log("Verified cipher decryption in UI with new password")
}

func TestSharedCipherRotationBrowser(t *testing.T) {
	t.Parallel()
	if os.Getenv("SKIP_BROWSER_TESTS") == "1" {
		t.Skip("SKIP_BROWSER_TESTS is set")
	}

	email1 := fmt.Sprintf("user1-%d@example.com", time.Now().UnixNano())
	email2 := fmt.Sprintf("user2-%d@example.com", time.Now().UnixNano())
	password := "password123"
	newPassword1 := "rotated-password-123"

	// 1. Register users
	RegisterTestUser(t, testServer, email1, password)
	RegisterTestUser(t, testServer, email2, password)

	// 2. User1 sets up the org and invites User2
	v1 := APILogin(t, testServer, email1, password)
	orgID, err := v1.CreateOrganization("Shared Org", email1, "Shared Collection")
	require.NoError(t, err)

	err = v1.InviteToOrganization(orgID, []string{email2}, 1) // Type 1 = Admin
	require.NoError(t, err)

	// User2 gets token via Mailpit
	token := GetInviteToken(t, email2)
	require.NotEmpty(t, token, "expected invite token")
	t.Logf("Extracted token: %s", token)

	// Need to find orgUserID for User2
	members, err := v1.ListOrgMembers(orgID)
	require.NoError(t, err)

	var orgUserID string
	for _, m := range members {
		if m.Email == email2 {
			orgUserID = m.ID
			break
		}
	}
	require.NotEmpty(t, orgUserID, "User2 not found in org members")

	// 3. User2 accepts the invite
	v2 := APILogin(t, testServer, email2, password)
	err = v2.AcceptOrgInvite(orgID, orgUserID, token)
	require.NoError(t, err)

	// User1 confirms User2
	err = v1.ConfirmMember(orgID, orgUserID)
	require.NoError(t, err)

	// 4. Create Collection and Cipher
	// Note: We already created "Shared Collection" during CreateOrganization
	// Need to fetch collection ID
	colls, err := v1.ListCollections(orgID)
	require.NoError(t, err)
	require.NotEmpty(t, colls, "Expected at least one collection")
	sharedCollID := colls[0].ID

	// Create and share cipher
	sharedCipher, _ := vault.NewCipher(vault.CipherTypeLogin, "Shared Browser Login", v1.SymmetricKey())
	sharedCipher.SetLoginUsername("shareduser")
	sharedCipher.SetLoginPassword("sharedpass")
	err = v1.CreateOrgCipher(orgID, sharedCollID, sharedCipher)
	require.NoError(t, err)

	time.Sleep(10 * time.Second) // wait for sync and db writes

	// 5. Spin up browsers
	_, browser, page2 := SetupPlaywright(t)
	page2.Context().SetDefaultTimeout(15000)

	// Verify User2 can see it
	BrowserLogin(t, page2, testServer, email2, password)

	BrowserVerifyCipherData(t, page2, "Shared Browser Login", map[string]string{
		"username": "shareduser",
		"password": "sharedpass",
	})
	t.Log("User2 verified shared cipher")
	_ = page2.Context().Close()

	t.Log("Opening User1's browser context...")
	newContext1, err := browser.NewContext(playwright.BrowserNewContextOptions{
		IgnoreHttpsErrors: playwright.Bool(true),
	})
	require.NoError(t, err)
	newContext1.SetDefaultTimeout(10000)
	page1, err := newContext1.NewPage()
	require.NoError(t, err)

	BrowserLogin(t, page1, testServer, email1, password)

	BrowserVerifyCipherData(t, page1, "Shared Browser Login", map[string]string{
		"username": "shareduser",
		"password": "sharedpass",
	})
	t.Log("User1 verified shared cipher")
	_ = page1.Context().Close()

	// 6. User1 rotates password
	v1Client := APILogin(t, testServer, email1, password)
	err = v1Client.ChangePassword(password, newPassword1, 0, 600000, 64, 4)
	require.NoError(t, err, "ChangePassword should succeed")
	t.Log("Rotated password for User1 via API")
	time.Sleep(2 * time.Second)

	// 7. Verify User1 can STILL see it after rotation
	t.Log("Opening User1's browser context (after rotation)...")
	newContext1Rotated, err := browser.NewContext(playwright.BrowserNewContextOptions{
		IgnoreHttpsErrors: playwright.Bool(true),
	})
	require.NoError(t, err)
	newContext1Rotated.SetDefaultTimeout(10000)
	page1Rotated, err := newContext1Rotated.NewPage()
	require.NoError(t, err)
	defer newContext1Rotated.Close()

	BrowserLogin(t, page1Rotated, testServer, email1, newPassword1)

	time.Sleep(2 * time.Second)

	BrowserVerifyCipherData(t, page1Rotated, "Shared Browser Login", map[string]string{
		"username": "shareduser",
		"password": "sharedpass",
	})
	t.Log("User1 verified shared cipher AFTER password rotation")
}
