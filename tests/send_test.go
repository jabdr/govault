//go:build integration

package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPlaywrightCreateSendUIAndDumpURL(t *testing.T) {
	email := "ui-send-url@example.com"
	password := "test-password-123"

	RegisterTestUser(t, testServer, email, password)
	v := APILogin(t, testServer, email, password)
	_ = v

	_, _, page := SetupPlaywright(t)

	// Intercept clipboard
	err := page.Context().GrantPermissions([]string{"clipboard-read", "clipboard-write"})
	require.NoError(t, err)

	BrowserLogin(t, page, testServer, email, password)

	page.Locator("a[href*='/sends']").First().Click()

	page.Locator("button[aria-label='New'], #newItemDropdown").First().Click()

	nameInput := page.Locator("input[formcontrolname='name'], input[aria-label*='Name'], input[name='Name']").First()
	err = nameInput.WaitFor()
	require.NoError(t, err)

	nameInput.Fill("My Send URL")

	page.Locator("textarea[formcontrolname='text']").First().Fill("This is secret text!")
	page.Locator("button:has-text('Save'), button[aria-label='Save']").First().Click()

	// Wait for the new item in the list
	err = page.Locator("text='My Send URL'").First().WaitFor()
	require.NoError(t, err)

	// Close the modal
	page.Locator(`button[bitdialogclose][size="default"]`).First().Click()
	time.Sleep(1 * time.Second)

	// Click it to view it
	page.Locator("text='My Send URL'").First().Click()
	time.Sleep(2 * time.Second)

	// Look for a copy link button
	v2 := page.Locator("button[aria-label='Copy link'], a[aria-label='Copy link']").First()
	_ = v2.Click()
	time.Sleep(1 * time.Second)

	// evaluate clipboard
	clip, err := page.Evaluate(`async () => await navigator.clipboard.readText()`)
	fmt.Printf("CLIPBOARD URL: %v (error: %v)\n", clip, err)
}
