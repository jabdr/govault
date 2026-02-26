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
export GOVAULT_PASSWORD="your-master-password"

# List all ciphers
govault -server https://vault.example.com -email user@example.com -action list

# Get details on a specific cipher
govault -server https://vault.example.com -email user@example.com -action get -id "cipher-id"

# Create a new login cipher
govault -server https://vault.example.com -email user@example.com -action create \
  -name "My Bank" -username "jsmith" -login-password "secure-password"

# Create a text send (Bitwarden Send)
govault -server https://vault.example.com -email user@example.com -action send-create \
  -name "Secret Note" -text "This is highly confidential information."
```

### Supported CLI Actions

- **Vault Actions:** `list`, `get`, `create`, `update`, `delete`, `change-password`
- **Organizations:** `org-list`, `org-members`, `org-invite`, `org-confirm`
- **Collections:** `collections`, `collection-create`, `collection-delete`
- **Sends:** `sends`, `send-create`, `send-get`, `send-delete`
- **Emergency Access:** `emergency-trusted`, `emergency-granted`, `emergency-invite`, `emergency-confirm`, `emergency-initiate`, `emergency-approve`, `emergency-reject`, `emergency-view`, `emergency-takeover`

Add `-verbose` to any command for debug logging from the inner HTTP and Crypto modules. 

## API Usage Example

In addition to acting as a standalone CLI tool, the `govault/pkg/vault` package can be imported directly into other Go projects to interface seamlessly with Bitwarden. 

Here is a basic example verifying login and generating an encrypted login item in your vault:

```go
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/jabdr/govault/pkg/vault"
)

func main() {
	// Create a debug or standard logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	server := "https://vault.example.com"
	email := "user@example.com"
	password := "masterpassword"

	// 1. Login and derive encryption keys
	v, err := vault.Login(server, email, password, logger)
	if err != nil {
		panic(fmt.Errorf("login failed: %v", err))
	}

	// 2. Sync to pull down current vault data
	err = v.Sync()
	if err != nil {
		panic(fmt.Errorf("sync failed: %v", err))
	}

	// 3. Create a new encrypted cipher
	c := vault.NewCipher(vault.CipherTypeLogin, "My New Login")
	c.SetLogin("myuser", "mypassword")
	
	err = v.CreateCipher(c)
	if err != nil {
		panic(fmt.Errorf("failed to create cipher: %v", err))
	}
	fmt.Printf("Successfully created cipher! ID: %s\n", c.ID())

	// 4. List all existing ciphers
	ciphers, err := v.ListCiphers()
	if err != nil {
		panic(fmt.Errorf("failed to list ciphers: %v", err))
	}
	
	for _, c := range ciphers {
		fmt.Printf("Cipher Name: %s\n", c.Name())
	}
}
```

## Testing

GoVault incorporates integration testing via Playwright to cross-reference Web UI behavior alongside our programmatic behavior.

To run tests (ensure you have Docker installed to run the local Vaultwarden replica alongside Mailpit for testing invites):

```sh
go test -v -tags=integration ./tests/...
```

## License

GoVault is licensed under the Apache License 2.0. See [LICENSE.md](./LICENSE.md) for full details.
