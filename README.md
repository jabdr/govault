> [!CAUTION]
> This library and cli is currently an experiment. Do not use it.

# GoVault

GoVault is a Go-based Command Line Interface (CLI) client for interacting with Bitwarden and Vaultwarden servers. It fundamentally works by wrapping Bitwarden's complex API and client-side encryption logic into a set of reusable Go packages (`pkg/vault`, `pkg/api`, `pkg/crypto`), and exposing them through an easy-to-use CLI.

## Installation

You can build and install the cli using `go build` or `go install`:

```sh
# Clone and build
git clone https://github.com/jabdr/govault.git
cd govault
go build -o govault ./cmd/govault

# Or simply install via Go
go install github.com/jabdr/govault/cmd/govault@latest
```

## CLI Usage

GoVault requires connecting to a Vaultwarden or Bitwarden server. Authentication details can be passed as flags, or the master password can be supplied securely via the `GOVAULT_PASSWORD` environment variable.

```sh
# Export your main password
export GOVAULT_SERVER="https://vault.example.com"
export GOVAULT_EMAIL="user@example.com"
export GOVAULT_PASSWORD="your-master-password"

# List all ciphers
govault cipher list

# Get details on a specific cipher
govault cipher get <cipher-id>

# Create a new login cipher
govault cipher create --name "My Bank" --login-username "jsmith" --login-password "secure-password"

# Create a text send (Bitwarden Send)
govault send create --name "Secret Note" --text "This is highly confidential information."

# With API Key
govault --client-id "user.xxxx" --client-secret "yyyy" cipher list

# Structured output (json/yaml)
govault -o json cipher list
```

### CLI Commands

- **Cipher Actions:** `govault cipher [list|get|create|update|delete]`
- **Account Management:** `govault account [change-password|change-name|change-email|get-api-key]`
- **Organizations:** `govault org [list|create|members|invite|confirm]`
- **Collections:** `govault collection [list|create|delete]`
- **Groups:** `govault group [list|create|delete]`
- **Sends:** `govault send [list|create|get|delete]`
- **Emergency Access:** `govault emergency [list-trusted|list-granted|invite|confirm|initiate|approve|reject|view|takeover]`
- **Admin (Vaultwarden):** `govault admin user [list|get|invite|reinvite|disable|enable|deauth|remove-2fa|delete]` and `govault admin org [list|delete]`

Add `--verbose` to any command for debug logging or `-o json/yaml` for structured output.

## API Usage Example

In addition to acting as a standalone CLI tool, the `govault/pkg/vault` package can be imported directly into other Go projects to interface seamlessly with Bitwarden. 

```go
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/jabdr/govault/pkg/vault"
)

func main() {
	// Create a debug or standard logger (optional)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	server := "https://vault.example.com"
	email := "user@example.com"
	password := "masterpassword"

	// 1. Login and derive encryption keys (skips TLS verification with 'true')
	v, err := vault.Login(server, email, password, true, logger)
	if err != nil {
		panic(fmt.Errorf("login failed: %w", err))
	}

	// 2. Sync to pull down latest vault data (automatically done during Login)
	// err = v.Sync()

	// 3. Create a new encrypted cipher
	// First initialize a new cipher with the vault's symmetric key
	c, err := vault.NewCipher(vault.CipherTypeLogin, "My New Login", v.SymmetricKey())
	if err != nil {
		panic(err)
	}
	c.SetLoginUsername("myuser")
	c.SetLoginPassword("mypassword")
	
	err = v.CreateCipher(c)
	if err != nil {
		panic(fmt.Errorf("failed to create cipher: %w", err))
	}
	fmt.Printf("Successfully created cipher! ID: %s\n", c.ID())

	// 4. List all existing ciphers
	ciphers, err := v.ListCiphers()
	if err != nil {
		panic(fmt.Errorf("failed to list ciphers: %w", err))
	}
	
	for _, c := range ciphers {
		fmt.Printf("Cipher Name: %s\n", c.Name())
	}
}
```

## Testing

GoVault incorporates integration testing via Playwright to cross-reference Web UI behavior alongside our programmatic behavior.

To run tests (ensure you have Docker installed to run the local Vaultwarden replica alongside Mailpit for testing):

```sh
go test -v -tags=integration ./tests/...
```

## License

GoVault is licensed under the Apache License 2.0. See [LICENSE.md](./LICENSE.md) for full details.
