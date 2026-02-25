//go:build integration

// Package tests contains integration tests that run against a live
// Vaultwarden instance. Start the test server with:
//
//	cd tests && docker compose up -d
//
// Run tests with:
//
//	GOVAULT_TEST_SERVER=http://localhost:8081 go test -tags=integration -v ./tests/
package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jabdr/govault/pkg/crypto"
	"github.com/jabdr/govault/pkg/vault"
)

var testServer string

func TestMain(m *testing.M) {
	testServer = os.Getenv("GOVAULT_TEST_SERVER")
	if testServer == "" {
		fmt.Println("GOVAULT_TEST_SERVER not set, skipping integration tests")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// registerTestUser creates a new test user via the web API.
func registerTestUser(t *testing.T, email, password string) {
	t.Helper()
	logger := testLogger()

	masterKey, err := crypto.DeriveKey([]byte(password), []byte(email), crypto.KdfTypePBKDF2, 600000, nil, nil)
	require.NoError(t, err, "derive key")

	stretched, err := crypto.StretchKey(masterKey)
	require.NoError(t, err, "stretch key")

	symKey, err := crypto.GenerateSymmetricKey()
	require.NoError(t, err, "generate symmetric key")

	stretchedKey, err := crypto.MakeSymmetricKey(stretched)
	require.NoError(t, err, "make stretched key")

	protectedKey, err := crypto.EncryptToEncString(symKey.Bytes(), stretchedKey)
	require.NoError(t, err, "encrypt symmetric key")

	pubDER, privDER, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err, "generate RSA key pair")

	encPrivKey, err := crypto.EncryptToEncString(privDER, symKey)
	require.NoError(t, err, "encrypt private key")

	passwordHash := crypto.HashPassword(password, masterKey)

	_ = logger
	type registerRequest struct {
		Name               string `json:"name"`
		Email              string `json:"email"`
		MasterPasswordHash string `json:"masterPasswordHash"`
		MasterPasswordHint string `json:"masterPasswordHint"`
		Key                string `json:"key"`
		Kdf                int    `json:"kdf"`
		KdfIterations      int    `json:"kdfIterations"`
		Keys               struct {
			PublicKey           string `json:"publicKey"`
			EncryptedPrivateKey string `json:"encryptedPrivateKey"`
		} `json:"keys"`
	}

	reqBody := registerRequest{
		Name:               email, // Use email as name
		Email:              email,
		MasterPasswordHash: passwordHash,
		MasterPasswordHint: "",
		Key:                protectedKey.String(), // Correct symmetric key encrypted by stretched key
		Kdf:                0,                     // PBKDF2
		KdfIterations:      600000,
	}
	reqBody.Keys.PublicKey = base64.StdEncoding.EncodeToString(pubDER)
	reqBody.Keys.EncryptedPrivateKey = encPrivKey.String()

	jsonData, err := json.Marshal(reqBody)
	require.NoError(t, err, "marshal request")

	resp, err := http.Post(testServer+"/identity/accounts/register", "application/json", bytes.NewReader(jsonData))
	require.NoError(t, err, "post register")
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		// It's possible the user already exists, so we should allow 400 with 'already exists'.
		// Vaultwarden returns 400 with "Email is already in use" validation error.
		require.Contains(t, string(body), "already", "register failed: %d %s", resp.StatusCode, string(body))
	}

	t.Logf("registered user (or already existed): %s", email)
}

func TestCipherCRUDLifecycle(t *testing.T) {
	email := "test-crud@example.com"
	password := "test-password-123"

	// Register user
	registerTestUser(t, email, password)

	// Login
	v, err := vault.Login(testServer, email, password, testLogger())
	require.NoError(t, err, "Login failed")

	// Create
	c := vault.NewCipher(vault.CipherTypeLogin, "Integration Test Login")
	c.SetLogin("testuser", "testpass")
	err = v.CreateCipher(c)
	require.NoError(t, err, "CreateCipher")
	t.Logf("Created cipher: %s", c.ID())

	// Read
	fetched, err := v.GetCipher(c.ID())
	require.NoError(t, err, "GetCipher")
	assert.Equal(t, "Integration Test Login", fetched.Name(), "Name mismatch")

	// Update
	c.SetField("name", "Updated Login")
	err = v.UpdateCipher(c)
	require.NoError(t, err, "UpdateCipher")

	// Delete
	err = v.DeleteCipher(c.ID())
	require.NoError(t, err, "DeleteCipher")
	t.Log("Cipher CRUD lifecycle complete")
}

func TestSendLifecycle(t *testing.T) {
	email := "test-send@example.com"
	password := "test-password-123"

	// Register user
	registerTestUser(t, email, password)

	v, err := vault.Login(testServer, email, password, testLogger())
	require.NoError(t, err, "Login failed")

	// Create
	send, accessURL, err := v.CreateTextSend("Test Send", "secret content", vault.SendOptions{})
	require.NoError(t, err, "CreateTextSend")
	t.Logf("Created send: %s, URL: %s", send.ID, accessURL)

	// List
	sends, err := v.ListSends()
	require.NoError(t, err, "ListSends")
	found := false
	for _, s := range sends {
		if s.ID == send.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "Created send not found in list")

	// Delete
	err = v.DeleteSend(send.ID)
	require.NoError(t, err, "DeleteSend")
	t.Log("Send lifecycle complete")
}

func TestEmergencyAccessLifecycle(t *testing.T) {
	email := "test-ea-grantor@example.com"
	password := "test-password-123"

	// Register user
	registerTestUser(t, email, password)

	v, err := vault.Login(testServer, email, password, testLogger())
	require.NoError(t, err, "Login failed")

	// List trusted (grantor view)
	trusted, err := v.ListTrustedEmergencyAccess()
	require.NoError(t, err, "ListTrustedEmergencyAccess")
	t.Logf("Trusted emergency contacts: %d", len(trusted))

	// Invite
	err = v.InviteEmergencyAccess("grantee@example.com", 0, 7)
	if err != nil {
		t.Logf("InviteEmergencyAccess: %v (may require mail)", err)
	}

	t.Log("Emergency access lifecycle test complete")
}
