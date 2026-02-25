//go:build integration

package tests

// Browser-based tests go here. They use the browser_subagent tool
// to validate functionality against the Vaultwarden web UI.
//
// These tests are intentionally left as stubs — they require the
// browser_subagent tooling and a running Vaultwarden instance with
// accessible web UI at the test server URL.
//
// Example test scenarios:
//
//   - Create a cipher via API → verify it appears in the web vault
//   - Create a Send via API → access it via the Send URL in browser
//   - Invite org member → verify invitation shows in web UI
//   - Emergency access → verify status in web UI
