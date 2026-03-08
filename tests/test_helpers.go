//go:build integration

package tests

import (
	"context"
	"crypto/tls"
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
			"ORG_GROUPS_ENABLED":             "true",
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

// RegisterTestUser creates a new test user via the vault.Register function.
func RegisterTestUser(t *testing.T, serverURL, email, password string) {
	t.Helper()
	err := vault.Register(
		serverURL,
		email,
		password,
		crypto.KdfTypePBKDF2,
		600000,
		64,
		4,
		true, // insecure
		GetTestLogger(),
	)
	if err != nil {
		// If user already exists, Vaultwarden might return an error, but for tests we often don't care
		// However, we should check if it's a real failure.
		if strings.Contains(err.Error(), "already") {
			t.Logf("user %s already exists", email)
			return
		}
		require.NoError(t, err, "register test user")
	}

	t.Logf("registered user: %s", email)
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

// VerifyUserEmail requests a verification email and completes it via Mailpit.
func VerifyUserEmail(t *testing.T, v *vault.Vault, email string) {
	t.Helper()

	err := v.Client().VerifyEmail()
	require.NoError(t, err, "request verify email")

	var token, userID string
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
					Subject string `json:"Subject"`
				} `json:"messages"`
			}
			if err := json.Unmarshal(body, &data); err == nil {
				for _, msg := range data.Messages {
					for _, to := range msg.To {
						if to.Address == email && strings.Contains(msg.Subject, "Verify") {
							fullMsgURL := strings.Replace(globalMailpitAPI, "/messages", "/message/"+msg.ID, 1)
							msgResp, err := http.Get(fullMsgURL)
							if err == nil {
								msgBody, _ := io.ReadAll(msgResp.Body)
								msgResp.Body.Close()

								var fullMsg struct {
									Text string `json:"Text"`
									HTML string `json:"HTML"`
								}
								_ = json.Unmarshal(msgBody, &fullMsg)

								bodyStr := fullMsg.Text
								if bodyStr == "" {
									bodyStr = fullMsg.HTML
								}

								if idx := strings.Index(bodyStr, "userId="); idx != -1 {
									uidStr := bodyStr[idx+7:]
									endIdx := strings.IndexAny(uidStr, "&\"\r\n <")
									if endIdx != -1 {
										uidStr = uidStr[:endIdx]
									}
									userID = uidStr
								}
								if idx := strings.Index(bodyStr, "token="); idx != -1 {
									tokenStr := bodyStr[idx+6:]
									endIdx := strings.IndexAny(tokenStr, "&\"\r\n <")
									if endIdx != -1 {
										tokenStr = tokenStr[:endIdx]
									}
									token = tokenStr
								}
							}
							break
						}
					}
					if token != "" {
						break
					}
				}
			}
		}
		if token != "" {
			break
		}
		time.Sleep(1 * time.Second)
	}

	require.NotEmpty(t, token, "failed to extract token from verify email")
	require.NotEmpty(t, userID, "failed to extract user ID from verify email")

	err = v.Client().VerifyEmailToken(userID, token)
	require.NoError(t, err, "complete verify email token")
}

// GetEmailChangeToken requests an email change and retrieves the verification
// token from Mailpit. The token is sent to the new email address.
func GetEmailChangeToken(t *testing.T, v *vault.Vault, newEmail string) string {
	t.Helper()

	// Request the email change token
	err := v.RequestEmailChange(newEmail)
	require.NoError(t, err, "request email change token")

	// Poll Mailpit for the token email
	var token string
	for i := 0; i < 10; i++ {
		resp, err := http.Get(globalMailpitAPI)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var data struct {
			Messages []struct {
				ID string `json:"ID"`
				To []struct {
					Address string `json:"Address"`
				} `json:"To"`
				Subject string `json:"Subject"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		for _, msg := range data.Messages {
			for _, to := range msg.To {
				if to.Address == newEmail {
					t.Logf("Found email to %s: subject=%q id=%s", newEmail, msg.Subject, msg.ID)
					fullMsgURL := strings.Replace(globalMailpitAPI, "/messages", "/message/"+msg.ID, 1)
					msgResp, err := http.Get(fullMsgURL)
					if err != nil {
						continue
					}
					msgBody, _ := io.ReadAll(msgResp.Body)
					msgResp.Body.Close()

					var fullMsg struct {
						Text string `json:"Text"`
						HTML string `json:"HTML"`
					}
					_ = json.Unmarshal(msgBody, &fullMsg)

					bodyStr := fullMsg.Text
					if bodyStr == "" {
						bodyStr = fullMsg.HTML
					}
					t.Logf("Email body (first 500 chars): %.500s", bodyStr)

					// Vaultwarden sends a 6-digit code like "code in web vault: 803147"
					if idx := strings.Index(bodyStr, "code in web vault: "); idx != -1 {
						codeStr := bodyStr[idx+len("code in web vault: "):]
						endIdx := strings.IndexAny(codeStr, "\r\n <")
						if endIdx != -1 {
							codeStr = codeStr[:endIdx]
						}
						token = strings.TrimSpace(codeStr)
					}
					// Fallback: try token= URL parameter
					if token == "" {
						if idx := strings.Index(bodyStr, "token="); idx != -1 {
							tokenStr := bodyStr[idx+6:]
							endIdx := strings.IndexAny(tokenStr, "&\"\r\n <")
							if endIdx != -1 {
								tokenStr = tokenStr[:endIdx]
							}
							token = tokenStr
						}
					}
					break
				}
			}
			if token != "" {
				break
			}
		}
		if token != "" {
			break
		}
		time.Sleep(1 * time.Second)
	}

	require.NotEmpty(t, token, "failed to extract token from email change email")
	return token
}
