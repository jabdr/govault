package vault

import (
	"fmt"

	"github.com/jabdr/govault/pkg/crypto"
)

// CipherType constants matching the Bitwarden API.
const (
	CipherTypeLogin      = 1
	CipherTypeSecureNote = 2
	CipherTypeCard       = 3
	CipherTypeIdentity   = 4
)

// Cipher wraps a raw cipher map with typed accessor methods.
// The underlying data is map[string]any to accommodate changes in
// Bitwarden's cipher format without breaking the library.
type Cipher struct {
	data map[string]any
	key  *crypto.SymmetricKey // key used for encrypt/decrypt
}

// NewCipher creates a new empty cipher of the given type and name.
func NewCipher(cipherType int, name string) *Cipher {
	return &Cipher{
		data: map[string]any{
			"type": float64(cipherType),
			"name": name,
		},
	}
}

// NewCipherFromMap wraps an existing raw cipher map.
func NewCipherFromMap(data map[string]any, key *crypto.SymmetricKey) *Cipher {
	return &Cipher{data: data, key: key}
}

// ID returns the cipher's ID.
func (c *Cipher) ID() string {
	id, _ := c.data["id"].(string)
	return id
}

// Type returns the cipher type (1=login, 2=note, 3=card, 4=identity).
func (c *Cipher) Type() int {
	t, _ := c.data["type"].(float64)
	return int(t)
}

// OrganizationID returns the cipher's organization ID or empty string.
func (c *Cipher) OrganizationID() string {
	id, _ := c.data["organizationId"].(string)
	return id
}

// Name returns the decrypted cipher name.
func (c *Cipher) Name() string {
	return c.decryptField("name")
}

// Notes returns the decrypted notes field.
func (c *Cipher) Notes() string {
	return c.decryptField("notes")
}

// GetField returns a field value from the cipher data by key.
// Encrypted string fields are automatically decrypted.
func (c *Cipher) GetField(name string) (any, error) {
	val, ok := c.data[name]
	if !ok {
		return nil, fmt.Errorf("cipher: field %q not found", name)
	}

	// Try to decrypt if it looks like an EncString
	if s, ok := val.(string); ok && c.key != nil {
		enc, err := crypto.ParseEncString(s)
		if err == nil && !enc.IsZero() {
			decrypted, err := enc.Decrypt(c.key)
			if err == nil {
				return string(decrypted), nil
			}
		}
	}
	return val, nil
}

// SetField sets a field value on the cipher data.
func (c *Cipher) SetField(name string, value any) {
	c.data[name] = value
}

// GetLogin returns the decrypted username and password for a login cipher.
func (c *Cipher) GetLogin() (username, password string, err error) {
	login, ok := c.data["login"].(map[string]any)
	if !ok {
		return "", "", fmt.Errorf("cipher: not a login type or no login data")
	}

	if u, ok := login["username"].(string); ok {
		if c.key != nil {
			username = c.decryptString(u)
		} else {
			username = u
		}
	}
	if p, ok := login["password"].(string); ok {
		if c.key != nil {
			password = c.decryptString(p)
		} else {
			password = p
		}
	}
	return username, password, nil
}

// SetLogin sets the username and password on a login cipher (plaintext, encrypted on save).
func (c *Cipher) SetLogin(username, password string) {
	login, ok := c.data["login"].(map[string]any)
	if !ok {
		login = make(map[string]any)
		c.data["login"] = login
	}
	login["username"] = username
	login["password"] = password
}

// Raw returns the underlying data map.
func (c *Cipher) Raw() map[string]any {
	return c.data
}

// Encrypt produces an encrypted cipher map ready for the API.
func (c *Cipher) Encrypt(key *crypto.SymmetricKey) (map[string]any, error) {
	if key == nil {
		return nil, fmt.Errorf("cipher: no encryption key")
	}

	result := make(map[string]any)

	// Copy all non-encrypted fields
	for k, v := range c.data {
		result[k] = v
	}

	// Encrypt name
	if name, ok := c.data["name"].(string); ok {
		enc, err := crypto.EncryptToEncString([]byte(name), key)
		if err != nil {
			return nil, fmt.Errorf("cipher: encrypt name: %w", err)
		}
		result["name"] = enc.String()
	}

	// Encrypt notes
	if notes, ok := c.data["notes"].(string); ok && notes != "" {
		enc, err := crypto.EncryptToEncString([]byte(notes), key)
		if err != nil {
			return nil, fmt.Errorf("cipher: encrypt notes: %w", err)
		}
		result["notes"] = enc.String()
	}

	// Encrypt login fields
	if login, ok := c.data["login"].(map[string]any); ok {
		encLogin := make(map[string]any)
		for k, v := range login {
			encLogin[k] = v
		}
		for _, field := range []string{"username", "password", "totp"} {
			if val, ok := login[field].(string); ok && val != "" {
				enc, err := crypto.EncryptToEncString([]byte(val), key)
				if err != nil {
					return nil, fmt.Errorf("cipher: encrypt login.%s: %w", field, err)
				}
				encLogin[field] = enc.String()
			}
		}
		// Encrypt URIs
		if uris, ok := login["uris"].([]any); ok {
			encURIs := make([]any, len(uris))
			for i, u := range uris {
				if uriMap, ok := u.(map[string]any); ok {
					encURI := make(map[string]any)
					for k, v := range uriMap {
						encURI[k] = v
					}
					if uri, ok := uriMap["uri"].(string); ok && uri != "" {
						enc, err := crypto.EncryptToEncString([]byte(uri), key)
						if err != nil {
							return nil, fmt.Errorf("cipher: encrypt uri: %w", err)
						}
						encURI["uri"] = enc.String()
					}
					encURIs[i] = encURI
				}
			}
			encLogin["uris"] = encURIs
		}
		result["login"] = encLogin
	}

	// Encrypt custom fields
	if fields, ok := c.data["fields"].([]any); ok {
		encFields := make([]any, len(fields))
		for i, f := range fields {
			if fMap, ok := f.(map[string]any); ok {
				encField := make(map[string]any)
				for k, v := range fMap {
					encField[k] = v
				}
				for _, field := range []string{"name", "value"} {
					if val, ok := fMap[field].(string); ok && val != "" {
						enc, err := crypto.EncryptToEncString([]byte(val), key)
						if err != nil {
							return nil, fmt.Errorf("cipher: encrypt field.%s: %w", field, err)
						}
						encField[field] = enc.String()
					}
				}
				encFields[i] = encField
			}
		}
		result["fields"] = encFields
	}

	return result, nil
}

func (c *Cipher) decryptField(name string) string {
	val, ok := c.data[name].(string)
	if !ok || val == "" || c.key == nil {
		return val
	}
	return c.decryptString(val)
}

func (c *Cipher) decryptString(s string) string {
	enc, err := crypto.ParseEncString(s)
	if err != nil {
		return s // Not encrypted, return as-is
	}
	decrypted, err := enc.Decrypt(c.key)
	if err != nil {
		return s // Decryption failed, return as-is
	}
	return string(decrypted)
}
