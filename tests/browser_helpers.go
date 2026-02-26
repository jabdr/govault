//go:build integration

package tests

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/require"
)

// SetupPlaywright initializes a Playwright instance, launches a browser, and returns a new page.
func SetupPlaywright(t *testing.T) (*playwright.Playwright, playwright.Browser, playwright.Page) {
	t.Helper()

	// Optionally install playwright browsers if they aren't already installed
	// We do this by calling run.go internally or assuming they are already installed via `go run github.com/playwright-community/playwright-go/cmd/playwright@latest install`.

	err := playwright.Install()
	require.NoError(t, err, "failed to install playwright browsers")

	pw, err := playwright.Run()
	require.NoError(t, err, "could not start playwright")

	// Check if running in CI to determine headless mode
	headless := os.Getenv("CI") == "true"

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(headless),
	})
	require.NoError(t, err, "could not launch browser")

	context, err := browser.NewContext(playwright.BrowserNewContextOptions{
		IgnoreHttpsErrors: playwright.Bool(true),
	})
	require.NoError(t, err, "could not create context")
	context.SetDefaultTimeout(10000)

	page, err := context.NewPage()
	require.NoError(t, err, "could not create page")

	// Set default timeout to 10 seconds instead of the 30 second default
	page.SetDefaultTimeout(10000)

	t.Cleanup(func() {
		_ = context.Close()
		_ = browser.Close()
		_ = pw.Stop()
	})

	return pw, browser, page
}

// BrowserLogin navigates to the Vaultwarden login page and logs in the user.
func BrowserLogin(t *testing.T, page playwright.Page, serverURL, email, password string) {
	t.Helper()

	_, err := page.Goto(serverURL + "/#/login")
	require.NoError(t, err, "failed to navigate to login page")

	// Wait for the email field
	emailInput := page.Locator("input[type='email'], input[id='email'], input[name='Email']").First()
	err = emailInput.WaitFor()
	require.NoError(t, err, "login email input not found")

	err = emailInput.Fill(email)
	require.NoError(t, err, "failed to fill email")

	// Submit email to go to the master password step
	err = emailInput.Press("Enter")
	require.NoError(t, err, "failed to submit email")

	// Wait for master password field
	passwordInput := page.Locator("input[type='password'], input[id='masterPassword'], input[name='MasterPassword']").First()
	err = passwordInput.WaitFor()
	require.NoError(t, err, "login password input not found")

	// Small delay to allow transition animation to finish
	time.Sleep(500 * time.Millisecond)

	err = passwordInput.Fill(password)
	require.NoError(t, err, "failed to fill password")

	time.Sleep(500 * time.Millisecond)

	// Log in
	err = page.Locator("button:has-text('Log in with master password'), button[type='submit']").First().Click()
	require.NoError(t, err, "failed to submit password")

	// Wait to be on the vault page or onboarding page
	postLoginLocator := page.Locator("button:has-text('Add it later'), button[aria-label='Add item'], a[aria-label='Add item'], button:has-text('New item'), a:has-text('New item'), button[aria-label='New'], #newItemDropdown").First()
	err = postLoginLocator.WaitFor(playwright.LocatorWaitForOptions{
		Timeout: playwright.Float(30000), // Maximum 30s timeout for high KDF iterations
	})
	require.NoError(t, err, "failed to reach vault or onboarding after login")

	// If we are on the onboarding page, click 'Add it later'
	addItLaterBtn := page.Locator("button:has-text('Add it later')").First()
	// Attempt to click it if it exists (wait up to 4 seconds)
	_ = addItLaterBtn.Click(playwright.LocatorClickOptions{
		Timeout: playwright.Float(4000),
	})

	skipToWebAppBtn := page.Locator("a:has-text('Skip to web app'), button:has-text('Skip to web app')").First()
	_ = skipToWebAppBtn.Click(playwright.LocatorClickOptions{
		Timeout: playwright.Float(2000),
	})

	// Now wait for vault
	addItemBtn := page.Locator("button[aria-label='Add item'], a[aria-label='Add item'], button:has-text('New item'), a:has-text('New item'), button[aria-label='New'], #newItemDropdown").First()
	err = addItemBtn.WaitFor(playwright.LocatorWaitForOptions{
		Timeout: playwright.Float(30000),
	})
	require.NoError(t, err, "failed to reach vault after onboarding/login")
}

// BrowserCreateCipher creates a new login cipher through the web UI.
func BrowserCreateCipher(t *testing.T, page playwright.Page, name, username, password string) {
	t.Helper()

	// Click "Add item" button - adjust selector based on Bitwarden web UI
	// Usually there's an aria-label="Add item", a button with a plus icon, or #newItemDropdown
	addItemBtn := page.Locator("#newItemDropdown").First()
	err := addItemBtn.WaitFor()
	require.NoError(t, err, "Add item button not found")
	err = addItemBtn.Click()
	require.NoError(t, err, "failed to click add item")

	// If it's a dropdown menu, click the "Login" option
	loginOption := page.Locator("button[role='menuitem']:has-text('Login'), a[role='menuitem']:has-text('Login')").First()
	_ = loginOption.Click(playwright.LocatorClickOptions{
		Timeout: playwright.Float(3000), // Might not exist if the New button directly opens modal (older versions)
	})

	// Wait for the modal/page to create an item
	nameInput := page.Locator("input[formcontrolname='name'], input[id='name'], input[aria-label*='Name'], input[name='Name']").First()
	err = nameInput.WaitFor(playwright.LocatorWaitForOptions{
		Timeout: playwright.Float(10000), // wait 10 seconds for modal
	})
	require.NoError(t, err, "Item name input not found")

	err = nameInput.Fill(name)
	require.NoError(t, err, "failed to fill item name")

	usernameInput := page.Locator("input[formcontrolname='username'], input[id='username'], input[aria-label*='Username']").First()
	err = usernameInput.Fill(username)
	require.NoError(t, err, "failed to fill username")

	passwordInput := page.Locator("input[formcontrolname='password'], input[id='password'], input[aria-label*='Password'], input[type='password']").First()
	err = passwordInput.Fill(password)
	require.NoError(t, err, "failed to fill password")

	// Save
	saveBtn := page.Locator("button:has-text('Save'), button[aria-label='Save']").First()
	err = saveBtn.Click()
	require.NoError(t, err, "failed to click save button")

	// Wait for the modal to disappear or toast to appear
	// Best robust way: wait for the new item to appear in the list
	err = page.Locator(fmt.Sprintf("text=%s", name)).First().WaitFor()
	require.NoError(t, err, "failed to see new item in the list after save")

	closeBtn := page.Locator(`button[bitdialogclose][size="default"]`).First()
	_ = closeBtn.Click(playwright.LocatorClickOptions{Timeout: playwright.Float(2000)})

	// Small delay to ensure DB write finishes
	time.Sleep(1 * time.Second)
}

// BrowserCheckCipherExists verifies that a given cipher name is visible in the vault list.
func BrowserCheckCipherExists(t *testing.T, page playwright.Page, name string) bool {
	t.Helper()

	// First ensure we are on the vault page or refresh list
	// Bitwarden has a search bar or list where we can locate the text
	locator := page.Locator(fmt.Sprintf("text=%s", name)).First()

	// We use a short timeout because if it's not there, we don't want to hang for 30s
	err := locator.WaitFor(playwright.LocatorWaitForOptions{
		Timeout: playwright.Float(3000),
	})

	return err == nil
}

// BrowserCreateSecureNote creates a new secure note cipher through the web UI.
func BrowserCreateSecureNote(t *testing.T, page playwright.Page, name, notes string) {
	t.Helper()

	addItemBtn := page.Locator("#newItemDropdown").First()
	err := addItemBtn.WaitFor()
	require.NoError(t, err, "Add item button not found")
	err = addItemBtn.Click()
	require.NoError(t, err, "failed to click add item")

	typeOption := page.Locator("button[role='menuitem']:has-text('Note'), a[role='menuitem']:has-text('Note')").First()
	_ = typeOption.Click(playwright.LocatorClickOptions{
		Timeout: playwright.Float(3000),
	})

	nameInput := page.Locator("input[formcontrolname='name'], input[id='name'], input[aria-label*='Name'], input[name='Name']").First()
	err = nameInput.WaitFor(playwright.LocatorWaitForOptions{
		Timeout: playwright.Float(10000),
	})
	require.NoError(t, err, "Item name input not found")

	err = nameInput.Fill(name)
	require.NoError(t, err, "failed to fill item name")

	notesInput := page.Locator("textarea[formcontrolname='notes'], textarea[id='notes'], textarea[aria-label*='Notes']").First()
	err = notesInput.Fill(notes)
	require.NoError(t, err, "failed to fill notes")

	saveBtn := page.Locator("button:has-text('Save'), button[aria-label='Save']").First()
	err = saveBtn.Click()
	require.NoError(t, err, "failed to click save button")

	err = page.Locator(fmt.Sprintf("text=%s", name)).First().WaitFor()
	require.NoError(t, err, "failed to see new item in the list after save")

	closeBtn := page.Locator(`button[bitdialogclose][size="default"]`).First()
	_ = closeBtn.Click(playwright.LocatorClickOptions{Timeout: playwright.Float(2000)})

	time.Sleep(1 * time.Second)
}

// BrowserCreateCard creates a new card cipher through the web UI.
func BrowserCreateCard(t *testing.T, page playwright.Page, name, cardholderName, number string) {
	t.Helper()

	addItemBtn := page.Locator("#newItemDropdown").First()
	err := addItemBtn.WaitFor()
	require.NoError(t, err, "Add item button not found")
	err = addItemBtn.Click()
	require.NoError(t, err, "failed to click add item")

	typeOption := page.Locator("button[role='menuitem']:has-text('Card'), a[role='menuitem']:has-text('Card')").First()
	_ = typeOption.Click(playwright.LocatorClickOptions{
		Timeout: playwright.Float(3000),
	})

	nameInput := page.Locator("input[formcontrolname='name'], input[id='name'], input[aria-label*='Name'], input[name='Name']").First()
	err = nameInput.WaitFor(playwright.LocatorWaitForOptions{
		Timeout: playwright.Float(10000),
	})
	require.NoError(t, err, "Item name input not found")

	err = nameInput.Fill(name)
	require.NoError(t, err, "failed to fill item name")

	cardholderInput := page.Locator("input[formcontrolname='cardholderName']").First()
	err = cardholderInput.Fill(cardholderName)
	require.NoError(t, err, "failed to fill cardholderName")

	numberInput := page.Locator("input[formcontrolname='number']").First()
	err = numberInput.Fill(number)
	require.NoError(t, err, "failed to fill number")

	saveBtn := page.Locator("button:has-text('Save'), button[aria-label='Save']").First()
	err = saveBtn.Click()
	require.NoError(t, err, "failed to click save button")

	err = page.Locator(fmt.Sprintf("text=%s", name)).First().WaitFor()
	require.NoError(t, err, "failed to see new item in the list after save")

	closeBtn := page.Locator(`button[bitdialogclose][size="default"]`).First()
	_ = closeBtn.Click(playwright.LocatorClickOptions{Timeout: playwright.Float(2000)})

	time.Sleep(1 * time.Second)
}

// BrowserVerifyCipherData clicks an item, checks its inputs, and closes the modal
func BrowserVerifyCipherData(t *testing.T, page playwright.Page, name string, checks map[string]string) {
	t.Helper()

	item := page.Locator(fmt.Sprintf("text=%s", name)).First()
	err := item.WaitFor()
	require.NoError(t, err, "failed to wait for item to verify")

	err = item.Click()
	require.NoError(t, err, "failed to click item to verify")

	// In newer Bitwarden versions, clicking an item opens it in "View" mode.
	// We need to click "Edit" to see the actual input values.
	editBtn := page.Locator("button:has-text('Edit'), button[aria-label='Edit']").First()
	_ = editBtn.WaitFor(playwright.LocatorWaitForOptions{Timeout: playwright.Float(3000)})
	if count, _ := editBtn.Count(); count > 0 {
		_ = editBtn.Click()
	}

	// Wait for modal to load by waiting for 'name' field
	nameInput := page.Locator("input[formcontrolname='name'], input[name='Name']").First()
	err = nameInput.WaitFor(playwright.LocatorWaitForOptions{Timeout: playwright.Float(10000)})
	require.NoError(t, err, "failed to wait for modal to open")

	for formControlName, expectedVal := range checks {
		var val string
		if formControlName == "notes" {
			locator := page.Locator(fmt.Sprintf("textarea[formcontrolname='%s']", formControlName)).First()
			val, err = locator.InputValue()
		} else {
			locator := page.Locator(fmt.Sprintf("input[formcontrolname='%s']", formControlName)).First()
			val, err = locator.InputValue()
		}
		require.NoError(t, err, "failed to read value for %s", formControlName)
		require.Equal(t, expectedVal, val, "value mismatch for %s", formControlName)
	}

	closeBtn := page.Locator(`button[bitdialogclose][size="default"], button:has-text('Cancel')`).First()
	_ = closeBtn.Click()
	time.Sleep(1 * time.Second)
}
