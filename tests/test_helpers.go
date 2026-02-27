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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/jabdr/govault/pkg/crypto"
	"github.com/jabdr/govault/pkg/vault"
)

var (
	globalTestServer string
	globalMailpitAPI string
)

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

	mailpitReq := testcontainers.ContainerRequest{
		Image:        "axllent/mailpit:latest",
		ExposedPorts: []string{"1025/tcp", "8025/tcp"},
		WaitingFor:   wait.ForHTTP("/api/v1/messages").WithPort("8025/tcp"),
	}
	mailpit, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: mailpitReq,
		Started:          true,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to start mailpit container: %v", err))
	}

	mailpitIP, err := mailpit.ContainerIP(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to get mailpit ip: %v", err))
	}

	mailpitPort, _ := mailpit.MappedPort(ctx, "8025/tcp")
	mailpitHost, _ := mailpit.Host(ctx)
	globalMailpitAPI = fmt.Sprintf("http://%s:%s/api/v1/messages", mailpitHost, mailpitPort.Port())

	req := testcontainers.ContainerRequest{
		Image:        "vaultwarden/server:latest",
		ExposedPorts: []string{"80/tcp"},
		Env: map[string]string{
			"I_REALLY_WANT_VOLATILE_STORAGE": "true",
			"ROCKET_TLS":                     `{certs="/ssl/certs.pem",key="/ssl/key.pem"}`,
			"LOG_LEVEL":                      "debug",
			"ADMIN_TOKEN":                    "test-admin-token",
			"SMTP_HOST":                      mailpitIP,
			"SMTP_PORT":                      "1025",
			"SMTP_FROM":                      "vaultwarden@test.local",
			"SMTP_SECURITY":                  "off",
			"LOGIN_RATELIMIT_MAX_BURST":      "1000",
			"LOGIN_RATELIMIT_SECONDS":        "1",
			"ADMIN_RATELIMIT_MAX_BURST":      "1000",
			"ADMIN_RATELIMIT_SECONDS":        "1",
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
		_ = mailpit.Terminate(ctx)
		os.RemoveAll(certDir)
		panic(fmt.Sprintf("failed to start vaultwarden container: %v", err))
	}

	teardown := func() {
		_ = vaultwarden.Terminate(ctx)
		_ = mailpit.Terminate(ctx)
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
	v, err := vault.Login(serverURL, email, password, true, GetTestLogger())
	require.NoError(t, err, "API login failed")
	return v
}

// GetInviteToken queries Mailpit for the token sent to the given email address.
func GetInviteToken(t *testing.T, toEmail string) string {
	t.Helper()
	for i := 0; i < 10; i++ {
		resp, err := http.Get(globalMailpitAPI)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var data struct {
				Messages []struct {
					ID string `json:"ID"`
					To []struct {
						Address string `json:"Address"`
					} `json:"To"`
				} `json:"messages"`
			}
			if err := json.Unmarshal(body, &data); err == nil {
				for _, msg := range data.Messages {
					for _, to := range msg.To {
						if to.Address == toEmail {
							// Found message, get full content
							fullMsgURL := strings.Replace(globalMailpitAPI, "/messages", "/message/"+msg.ID, 1)
							msgResp, err := http.Get(fullMsgURL)
							if err == nil {
								msgBody, _ := io.ReadAll(msgResp.Body)
								msgResp.Body.Close()

								var fullMsg struct {
									Text string `json:"Text"`
									HTML string `json:"HTML"`
								}
								if err := json.Unmarshal(msgBody, &fullMsg); err == nil {
									bodyStr := fullMsg.Text
									if bodyStr == "" {
										bodyStr = fullMsg.HTML
									}
									idx := strings.Index(bodyStr, "token=")
									if idx != -1 {
										tokenStr := bodyStr[idx+6:]
										endIdx := strings.IndexAny(tokenStr, "\"\r\n& <")
										if endIdx != -1 {
											tokenStr = tokenStr[:endIdx]
										}
										return tokenStr
									}
								}
							}
						}
					}
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatalf("failed to find invite token for %s", toEmail)
	return ""
}
