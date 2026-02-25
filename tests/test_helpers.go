//go:build integration

package tests

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/jabdr/govault/pkg/crypto"
	"github.com/jabdr/govault/pkg/vault"
)

var globalTestServer string

func init() {
	// Skip TLS verification for all API tests against local Vaultwarden
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
}

func GetTestServerURL(t *testing.T) string {
	t.Helper()
	if globalTestServer != "" {
		return globalTestServer
	}

	// Fallback to env var or localhost
	envServer := os.Getenv("GOVAULT_TEST_SERVER")
	if envServer != "" {
		return envServer
	}
	return "https://localhost:8443"
}

func SetupTestServer() (string, func()) {
	envServer := os.Getenv("GOVAULT_TEST_SERVER")
	if envServer != "" {
		globalTestServer = envServer
		return envServer, func() {}
	}

	certDir, err := generateTestCerts()
	if err != nil {
		panic(fmt.Sprintf("failed to generate test certs: %v", err))
	}

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "vaultwarden/server:latest",
		ExposedPorts: []string{"80/tcp"},
		Env: map[string]string{
			"I_REALLY_WANT_VOLATILE_STORAGE": "true",
			"ROCKET_TLS":                     `{certs="/ssl/certs.pem",key="/ssl/key.pem"}`,
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      filepath.Join(certDir, "certs.pem"),
				ContainerFilePath: "/ssl/certs.pem",
				FileMode:          0o644,
			},
			{
				HostFilePath:      filepath.Join(certDir, "key.pem"),
				ContainerFilePath: "/ssl/key.pem",
				FileMode:          0o644,
			},
		},
		WaitingFor: wait.ForHTTP("/alive").WithPort("80/tcp").WithTLS(true).WithAllowInsecure(true),
	}

	vaultwarden, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		os.RemoveAll(certDir)
		panic(fmt.Sprintf("failed to start vaultwarden container: %v", err))
	}

	teardown := func() {
		_ = vaultwarden.Terminate(ctx)
		_ = os.RemoveAll(certDir)
	}

	ip, err := vaultwarden.Host(ctx)
	if err != nil {
		teardown()
		panic(fmt.Sprintf("failed to get container host: %v", err))
	}

	port, err := vaultwarden.MappedPort(ctx, "80")
	if err != nil {
		teardown()
		panic(fmt.Sprintf("failed to get container port: %v", err))
	}

	serverURL := fmt.Sprintf("https://%s:%s", ip, port.Port())
	globalTestServer = serverURL

	return serverURL, teardown
}

func GetTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// RegisterTestUser creates a new test user via the web API.
func RegisterTestUser(t *testing.T, serverURL, email, password string) {
	t.Helper()
	logger := GetTestLogger()

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
		Name:               email,
		Email:              email,
		MasterPasswordHash: passwordHash,
		MasterPasswordHint: "",
		Key:                protectedKey.String(),
		Kdf:                0, // PBKDF2
		KdfIterations:      600000,
	}
	reqBody.Keys.PublicKey = base64.StdEncoding.EncodeToString(pubDER)
	reqBody.Keys.EncryptedPrivateKey = encPrivKey.String()

	jsonData, err := json.Marshal(reqBody)
	require.NoError(t, err, "marshal request")

	resp, err := http.Post(serverURL+"/identity/accounts/register", "application/json", bytes.NewReader(jsonData))
	require.NoError(t, err, "post register")
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		require.Contains(t, string(body), "already", "register failed: %d %s", resp.StatusCode, string(body))
	}

	t.Logf("registered user (or already existed): %s", email)
}

// APILogin logs in and returns a configured Vault client.
func APILogin(t *testing.T, serverURL, email, password string) *vault.Vault {
	t.Helper()
	v, err := vault.Login(serverURL, email, password, GetTestLogger())
	require.NoError(t, err, "API login failed")
	return v
}
