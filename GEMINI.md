# GoVault Implementation Strategy

GoVault is a Go-based Command Line Interface (CLI) client for interacting with Bitwarden and Vaultwarden servers. It fundamentally works by wrapping Bitwarden's complex API and client-side encryption logic into a set of reusable Go packages, presented through a CLI.

You have access to gopls-mcp tools for semantic code analysis.

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
- **`.local`**: For local development and testing like scripts or dump data.

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
- **Testing:** The project utilizes the `stretchr/testify` library for writing robust unit and integration tests, ensuring reliability across the application. Integrating Playwright browser tests is handled via `github.com/playwright-community/playwright-go` (no need to install Playwright via `npx`). Never attempt to add the Bitwarden browser extension to the browser during browser tests. **Crucially, never write tests that only verify the Web UI.** Integration tests must either focus exclusively on the Go client code, or verify interoperability: testing that items created via the Go client work correctly in the browser, or that items created in the browser are correctly handled by the Go client. **All browser integration tests should log each step explicitly (e.g., logging locator interactions and actions) to aid in debugging.** To use an existing browser instance for tests, set the `CDP_URL` environment variable (e.g., `http://localhost:9222`).
- **Permissions:** Commands should be executed using standard user privileges. You should never attempt to use `sudo` commands within this project.
- **Git Operations:** Never automatically commit changes in git. Allow the user to manually review and commit their changes unless explicitly instructed otherwise.
- **Documentation Maintenance:** Always update the `README.md` file whenever there are significant changes to the CLI structure (subcommands, flags) or the public API in `pkg/vault`. Ensure examples stay current and functional.

# GOPLS-MCP INSTRUCTIONS

## Context
You are an AI programming assistant helping users with Go code. You have access to gopls-mcp tools for semantic code analysis.

## CRITICAL PROHIBITIONS (NEVER DO THIS)
1. NEVER use `go_search` for text content (comments, strings, TODOs). Use `Grep` tool.
2. NEVER use grep/ripgrep for symbol discovery (definitions, references, implementations).
3. NEVER fall back from exclusive capabilities (see Tool Selection Guide).

<!-- Marker: AUTO-GEN-START -->
## Tool Selection Guide

### Code relationships (Exclusive Capabilities - NO FALLBACK)
| Task | Tool |
|------|------|
| Find interface implementations | go_implementation |
| Trace call relationships | go_get_call_hierarchy |
| Find symbol references | go_symbol_references |
| Jump to definition | go_definition |
| Analyze dependencies | go_get_dependency_graph |
| Preview renaming | go_dryrun_rename_symbol |

### Code exploration (Enhanced Capabilities - FALLBACK ALLOWED)
| Task | Tool | Fallback after 3 failures |
|------|------|---------------------------|
| List package symbols | go_list_package_symbols | Glob + Read |
| List module packages | go_list_module_packages | find |
| Analyze workspace | go_analyze_workspace | Manual exploration |
| Quick project overview | go_get_started | Read README + go.mod |
| Search symbols by name | go_search | grep + Read |
| Check compilation | go_build_check | go build |
| Get symbol details | go_get_package_symbol_detail | Read |
| List modules | go_list_modules | Read go.mod |
<!-- Marker: AUTO-GEN-END -->

## Integration Workflow
1. **Classify task type**: Route to Exclusive capabilities, Enhanced capabilities, or Grep tool based on the Tool Selection Guide.
2. **Validate**: Check intent against "Tool-Specific Parameters & Constraints" BEFORE execution.
3. **Construct & Execute**: Extract exact symbol names and file paths, execute the tool.
4. **Format Output**: Present file:line locations, signatures, and documentation cleanly. Do not dump raw JSON.

## Tool-Specific Parameters & Constraints

* **go_search**:
    * FATAL: `query` MUST NOT contain spaces or semantic descriptions.
    * Must be symbol names only (single token). Correct: `query="ParseInt"`.
    * Does NOT search comments or documentation.
* **go_implementation**:
    * Only for interfaces and types. STRICTLY PROHIBITED for functions.
* **go_get_package_symbol_detail**:
    * `symbol_filters` format: `[{name: "Start", receiver: "*Server"}]`.
    * `receiver` requires exact string match (`"*Server"` != `"Server"`).
* **General Parameters**:
    * `symbol_name`: Do not include package prefix (Use `"Start"`, not `"Server.Start"`).
    * `context_file`: Obtain strictly from the current file being analyzed.

## Error Handling & Retry (Self-Correction)
* Check if parameters strictly follow the constraints above.
* Try a shorter/simpler symbol name.
* Re-analyze code context before retrying.

## Fallback Conditions (For Enhanced Capabilities ONLY)
Trigger fallback manually IF AND ONLY IF:
1. 3 consecutive tool failures.
2. Timeout exceeds 30 seconds.
3. Empty result returned when code existence is absolutely certain.
*Note: Retry gopls-mcp tool first on the very next user query even after a previous fallback.*
