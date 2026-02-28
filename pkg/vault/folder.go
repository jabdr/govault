package vault

import (
	"fmt"

	"github.com/jabdr/govault/pkg/api"
	"github.com/jabdr/govault/pkg/crypto"
)

// Folder represents a decrypted vault folder.
type Folder struct {
	ID           string
	Name         string
	RevisionDate string
}

// ListFolders returns all folders with decrypted names.
func (v *Vault) ListFolders() ([]Folder, error) {
	apiFolders, err := v.client.ListFolders()
	if err != nil {
		return nil, fmt.Errorf("vault: list folders: %w", err)
	}

	folders := make([]Folder, 0, len(apiFolders))
	for _, f := range apiFolders {
		folders = append(folders, Folder{
			ID:           f.ID,
			Name:         decryptString(f.Name, v.symKey),
			RevisionDate: f.RevisionDate,
		})
	}
	return folders, nil
}

// CreateFolder creates a new folder with the given name.
func (v *Vault) CreateFolder(name string) (*Folder, error) {
	encName, err := crypto.EncryptToEncString([]byte(name), v.symKey)
	if err != nil {
		return nil, fmt.Errorf("vault: encrypt folder name: %w", err)
	}

	resp, err := v.client.CreateFolder(&api.FolderRequest{Name: encName.String()})
	if err != nil {
		return nil, fmt.Errorf("vault: create folder: %w", err)
	}

	return &Folder{
		ID:           resp.ID,
		Name:         name,
		RevisionDate: resp.RevisionDate,
	}, nil
}

// GetFolder returns a folder by ID.
func (v *Vault) GetFolder(id string) (*Folder, error) {
	folders, err := v.ListFolders()
	if err != nil {
		return nil, err
	}
	for _, f := range folders {
		if f.ID == id {
			return &f, nil
		}
	}
	return nil, fmt.Errorf("vault: folder not found: %s", id)
}

// UpdateFolder renames a folder.
func (v *Vault) UpdateFolder(id, name string) (*Folder, error) {
	encName, err := crypto.EncryptToEncString([]byte(name), v.symKey)
	if err != nil {
		return nil, fmt.Errorf("vault: encrypt folder name: %w", err)
	}

	resp, err := v.client.UpdateFolder(id, &api.FolderRequest{Name: encName.String()})
	if err != nil {
		return nil, fmt.Errorf("vault: update folder: %w", err)
	}

	return &Folder{
		ID:           resp.ID,
		Name:         name,
		RevisionDate: resp.RevisionDate,
	}, nil
}

// DeleteFolder deletes a folder by ID.
func (v *Vault) DeleteFolder(id string) error {
	err := v.client.DeleteFolder(id)
	if err != nil {
		return fmt.Errorf("vault: delete folder: %w", err)
	}
	return nil
}
