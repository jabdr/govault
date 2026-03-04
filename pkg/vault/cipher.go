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
	CipherTypeSshKey     = 5
)

// Cipher wraps a raw cipher map with typed accessor methods.
type Cipher struct {
	data map[string]any
	key  *crypto.SymmetricKey // key used for encrypt/decrypt
}

// NewCipher creates a new empty cipher of the given type and name.
// It immediately encrypts the name using the provided key.
func NewCipher(cipherType int, name string, key *crypto.SymmetricKey) (*Cipher, error) {
	c := &Cipher{
		data: map[string]any{
			"type": float64(cipherType),
		},
		key: key,
	}
	err := c.SetName(name)
	if err != nil {
		return nil, err
	}
	return c, nil
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

// Type returns the cipher type (1=login, 2=note, 3=card, 4=identity, 5=ssh key).
func (c *Cipher) Type() int {
	t, _ := c.data["type"].(float64)
	return int(t)
}

// OrganizationID returns the cipher's organization ID or empty string.
func (c *Cipher) OrganizationID() string {
	id, _ := c.data["organizationId"].(string)
	return id
}

// SetOrganizationID assigns the cipher to an organization.
func (c *Cipher) SetOrganizationID(id string) {
	if id == "" {
		delete(c.data, "organizationId")
	} else {
		c.data["organizationId"] = id
	}
}

// CollectionIDs returns the cipher's collection IDs.
func (c *Cipher) CollectionIDs() []string {
	raw, ok := c.data["collectionIds"].([]any)
	if !ok {
		return nil
	}
	ids := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			ids = append(ids, s)
		}
	}
	return ids
}

// SetCollectionIDs assigns the cipher to one or more collections.
func (c *Cipher) SetCollectionIDs(ids []string) {
	if len(ids) == 0 {
		delete(c.data, "collectionIds")
		return
	}
	raw := make([]any, len(ids))
	for i, id := range ids {
		raw[i] = id
	}
	c.data["collectionIds"] = raw
}

// FolderID returns the cipher's folder ID or empty string.
func (c *Cipher) FolderID() string {
	id, _ := c.data["folderId"].(string)
	return id
}

// SetFolderID assigns the cipher to a folder by its ID.
// Pass an empty string to remove the folder assignment.
func (c *Cipher) SetFolderID(id string) error {
	if id == "" {
		delete(c.data, "folderId")
	} else {
		c.data["folderId"] = id
	}
	return nil
}

// Name returns the decrypted cipher name.
func (c *Cipher) Name() string {
	return c.decryptField("name")
}

// SetName sets the cipher's name, encrypting it instantly.
func (c *Cipher) SetName(name string) error {
	encStr, err := encryptIfNotEncrypted(name, c.key)
	if err != nil {
		return err
	}
	c.data["name"] = encStr
	return nil
}

// Notes returns the decrypted notes field.
func (c *Cipher) Notes() string {
	return c.decryptField("notes")
}

// SetNotes sets the cipher's notes, encrypting it instantly.
func (c *Cipher) SetNotes(notes string) error {
	if notes == "" {
		delete(c.data, "notes")
		return nil
	}
	encStr, err := encryptIfNotEncrypted(notes, c.key)
	if err != nil {
		return err
	}
	c.data["notes"] = encStr
	return nil
}

// GetField returns a field value from the cipher data by key.
func (c *Cipher) GetField(name string) (any, error) {
	val, ok := c.data[name]
	if !ok {
		return nil, fmt.Errorf("cipher: field %q not found", name)
	}

	if s, ok := val.(string); ok && c.key != nil {
		return c.decryptString(s), nil
	}
	return val, nil
}

// SetField sets a field value, encrypting if it is a string.
func (c *Cipher) SetField(name string, value any) error {
	if s, ok := value.(string); ok && c.key != nil {
		encStr, err := encryptIfNotEncrypted(s, c.key)
		if err != nil {
			return err
		}
		c.data[name] = encStr
	} else {
		c.data[name] = value
	}
	return nil
}

// getOrCreateLogin is a helper to get or create the login map.
func (c *Cipher) getOrCreateLogin() map[string]any {
	login, ok := c.data["login"].(map[string]any)
	if !ok || login == nil {
		login = make(map[string]any)
		c.data["login"] = login
	}
	return login
}

// GetLogin returns the decrypted username and password for a login cipher.
func (c *Cipher) GetLogin() (username, password string, err error) {
	login, ok := c.data["login"].(map[string]any)
	if !ok {
		return "", "", fmt.Errorf("cipher: not a login type or no login data")
	}

	if u, ok := login["username"].(string); ok {
		username = c.decryptString(u)
	}
	if p, ok := login["password"].(string); ok {
		password = c.decryptString(p)
	}
	return username, password, nil
}

// SetLoginUsername sets the username on a login cipher (encrypts immediately).
func (c *Cipher) SetLoginUsername(username string) error {
	login := c.getOrCreateLogin()
	if username == "" {
		delete(login, "username")
		return nil
	}
	encStr, err := encryptIfNotEncrypted(username, c.key)
	if err != nil {
		return err
	}
	login["username"] = encStr
	return nil
}

// SetLoginPassword sets the password on a login cipher (encrypts immediately).
func (c *Cipher) SetLoginPassword(password string) error {
	login := c.getOrCreateLogin()
	if password == "" {
		delete(login, "password")
		return nil
	}
	encStr, err := encryptIfNotEncrypted(password, c.key)
	if err != nil {
		return err
	}
	login["password"] = encStr
	return nil
}

// GetLoginURLs returns the decrypted URIs for a login cipher.
func (c *Cipher) GetLoginURLs() ([]string, error) {
	login, ok := c.data["login"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("cipher: not a login type or no login data")
	}
	uris, ok := login["uris"].([]any)
	if !ok {
		return nil, nil // Not an error if there are no URLs
	}
	var res []string
	for _, u := range uris {
		if uriMap, ok := u.(map[string]any); ok {
			if uriStr, ok := uriMap["uri"].(string); ok {
				res = append(res, c.decryptString(uriStr))
			}
		}
	}
	return res, nil
}

// SetLoginURLs sets the URIs on a login cipher (encrypts immediately).
func (c *Cipher) SetLoginURLs(urls []string) error {
	login := c.getOrCreateLogin()
	if len(urls) == 0 {
		delete(login, "uris")
		return nil
	}
	var uris []any
	for _, u := range urls {
		encStr, err := encryptIfNotEncrypted(u, c.key)
		if err != nil {
			return err
		}
		uris = append(uris, map[string]any{"uri": encStr, "match": nil})
	}
	login["uris"] = uris
	return nil
}

// AddField appends a custom field to the cipher (encrypts immediately).
func (c *Cipher) AddField(name, value string, fieldType int) error {
	fields, ok := c.data["fields"].([]any)
	if !ok || fields == nil {
		fields = make([]any, 0)
	}
	encName, err := encryptIfNotEncrypted(name, c.key)
	if err != nil {
		return err
	}
	encVal, err := encryptIfNotEncrypted(value, c.key)
	if err != nil {
		return err
	}
	fields = append(fields, map[string]any{
		"name":  encName,
		"value": encVal,
		"type":  fieldType, // 0 = Text, 1 = Hidden, 2 = Boolean
	})
	c.data["fields"] = fields
	return nil
}

// Raw returns the underlying data map.
func (c *Cipher) Raw() map[string]any {
	return c.data
}

// Encrypt simply returns the underlying map, as all data is encrypted on the fly.
// Retained for API compatibility.
func (c *Cipher) Encrypt(key *crypto.SymmetricKey) (map[string]any, error) {
	// Everything is already encrypted using c.key
	// If the key passed is different (e.g. org key), we would need to re-encrypt
	if c.key != nil && key != nil && string(c.key.Bytes()) != string(key.Bytes()) {
		// Needs complete re-encryption. Since we only have the map with the old key,
		// we decrypt values using c.key and re-encrypt with the new key.
		return reencryptData(c.data, c.key, key)
	}
	return c.data, nil
}

func reencryptData(data map[string]any, oldKey, newKey *crypto.SymmetricKey) (map[string]any, error) {
	result := make(map[string]any)
	for k, v := range data {
		switch tv := v.(type) {
		case string:
			// Attempt to decrypt and re-encrypt
			enc, err := crypto.ParseEncString(tv)
			if err == nil {
				dec, err := enc.Decrypt(oldKey)
				if err == nil {
					newEnc, err := encryptIfNotEncrypted(string(dec), newKey)
					if err != nil {
						return nil, err
					}
					result[k] = newEnc
					continue
				}
			}
			result[k] = v // leave as is if not our enc string
		case map[string]any:
			newMap, err := reencryptData(tv, oldKey, newKey)
			if err != nil {
				return nil, err
			}
			result[k] = newMap
		case []any:
			var newList []any
			for _, item := range tv {
				if mapItem, ok := item.(map[string]any); ok {
					newMapItem, err := reencryptData(mapItem, oldKey, newKey)
					if err != nil {
						return nil, err
					}
					newList = append(newList, newMapItem)
				} else if strItem, ok := item.(string); ok {
					enc, err := crypto.ParseEncString(strItem)
					if err == nil {
						dec, err := enc.Decrypt(oldKey)
						if err == nil {
							newEnc, err := encryptIfNotEncrypted(string(dec), newKey)
							if err != nil {
								return nil, err
							}
							newList = append(newList, newEnc)
							continue
						}
					}
					newList = append(newList, strItem)
				} else {
					newList = append(newList, item)
				}
			}
			result[k] = newList
		default:
			result[k] = v
		}
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

func encryptIfNotEncrypted(val string, key *crypto.SymmetricKey) (string, error) {
	if val == "" {
		return "", nil
	}
	if key == nil {
		return "", fmt.Errorf("cannot encrypt without a key")
	}
	_, err := crypto.ParseEncString(val)
	if err == nil {
		// Valid encrypted string, do not double encrypt
		return val, nil
	}
	enc, err := crypto.EncryptToEncString([]byte(val), key)
	if err != nil {
		return "", err
	}
	return enc.String(), nil
}
