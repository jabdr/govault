# GoVault Implementation Strategy

GoVault is a Go-based Command Line Interface (CLI) client for interacting with Bitwarden and Vaultwarden servers. It fundamentally works by wrapping Bitwarden's complex API and client-side encryption logic into a set of reusable Go packages, presented through a CLI.

## Architecture & Package Structure

The project follows a standard Go project layout with a clear separation of concerns:

- **`cmd/govault/`**: Contains the CLI entry point (`main.go`). It handles flag parsing, configuration (like environment variables), and orchestrates calls to the underlying library. It relies heavily on `pkg/vault`.
- **`pkg/vault/`**: The core application logic. It models Bitwarden entities (Ciphers, Collections, Organizations, Sends, Emergency Access) and provides a high-level API for the CLI to perform actions (like `Login`, `Sync`, `CreateCipher`, etc.). It acts as a bridge between the raw HTTP API and the cryptographic operations.
- **`pkg/api/`**: A dedicated HTTP client (`client.go`) that handles communication with the Bitwarden/Vaultwarden REST API endpoints. It manages authentication tokens (access and refresh tokens) and provides methods for various endpoints (`auth.go`, `sync.go`, `ciphers.go`, etc.).
- **`pkg/crypto/`**: Implements Bitwarden's rigorous client-side, zero-knowledge encryption architecture. This includes:
  - Key derivation (PBKDF2) (`kdf.go`).
  - Symmetric encryption/decryption (AES-CBC-256, AES-GCM) (`aes.go`).
  - Asymmetric encryption (RSA) (`rsa.go`).
  - Encrypted string parsing and formatting (`encstring.go`).
- **`tests/`**: Contains integration tests and browser tests, utilizing Docker Compose for spinning up a Vaultwarden instance to test against locally.

## Interaction Flow

1. **Authentication:** The user provides a server URL, email, and master password. The `vault` package uses the `crypto` package to derive the master key and master password hash. It then calls the `api` package to authenticate and retrieve session tokens and encrypted user keys.
2. **Syncing:** The client typically calls `Sync()` to download the user's encrypted data (ciphers, folders, collections) from the server.
3. **Decryption:** The `vault` package uses the decrypted user key (which is kept in memory) to seamlessly decrypt cipher data on-the-fly when requested by the CLI.
4. **Operations:** When creating or updating items, the `vault` package encrypts the data using the `crypto` package before sending it to the server via the `api` package.

## Key Design Principles

- **Zero-Knowledge Architecture:** Strict adherence to Bitwarden's encryption model ensures the server never sees plain text data. All encryption/decryption happens client-side in `pkg/crypto`.
- **Modularity:** The clear separation between API concerns, cryptography, state management (`vault`), and the CLI (`cmd`) makes the codebase maintainable and potentially allows the `pkg/` directory to be used as an independent library by other Go projects.
- **Stateless CLI:** The CLI does not appear to persist state (like sessions or a local cache) to disk across runs; it relies on re-authenticating and passing the master password (or reading it from `GOVAULT_PASSWORD`) for operations.
- **Dynamic Cipher Representation:** The `vault` package uses `map[string]any` to represent ciphers instead of rigid structs. This allows the client to handle arbitrary and evolving cipher data structures returned by the Bitwarden API without requiring constant updates to Go structs.
- **Testing:** The project utilizes the `stretchr/testify` library for writing robust unit and integration tests, ensuring reliability across the application. Integrating Playwright browser tests is handled via `github.com/playwright-community/playwright-go` (no need to install Playwright via `npx`). Never attempt to add the Bitwarden browser extension to the browser during browser tests.
- **Permissions:** Commands should be executed using standard user privileges. You should never attempt to use `sudo` commands within this project.
- **Git Operations:** Never automatically commit changes in git. Allow the user to manually review and commit their changes unless explicitly instructed otherwise.
- **Documentation Maintenance:** Always update the `README.md` file whenever there are significant changes to the CLI structure (subcommands, flags) or the public API in `pkg/vault`. Ensure examples stay current and functional.
