package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// outputFormat holds the current output format (text, json, yaml).
var outputFormat string

// HumanReadable is an interface for types that provide a human-readable string.
type HumanReadable interface {
	HumanString() string
}

// HumanTable is an interface for list items that provide a table row.
type HumanTable interface {
	TableHeader() string
	TableRow() string
}

// printOutput serializes data to the selected format and writes to stdout.
func printOutput(data any) {
	switch outputFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(data)
	case "yaml":
		out, err := yaml.Marshal(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: yaml marshal: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(string(out))
	default: // text
		if hr, ok := data.(HumanReadable); ok {
			fmt.Print(hr.HumanString())
		} else {
			fmt.Printf("%v\n", data)
		}
	}
}

// printList serializes a slice of items to the selected format and writes to stdout.
func printList[T any](items []T) {
	switch outputFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(items)
	case "yaml":
		out, err := yaml.Marshal(items)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: yaml marshal: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(string(out))
	default: // text
		if len(items) == 0 {
			return
		}
		// Check if items implement HumanTable for tabwriter output
		if _, ok := any(items[0]).(HumanTable); ok {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, any(items[0]).(HumanTable).TableHeader())
			for _, item := range items {
				fmt.Fprintln(w, any(item).(HumanTable).TableRow())
			}
			_ = w.Flush()
			return
		}
		// Fallback to HumanReadable
		for _, item := range items {
			if hr, ok := any(item).(HumanReadable); ok {
				fmt.Print(hr.HumanString())
			} else {
				fmt.Printf("%v\n", item)
			}
		}
	}
}

// ErrorResult holds an error for structured output.
type ErrorResult struct {
	Error string `json:"error" yaml:"error"`
}

// printError writes an error in the selected output format to stderr.
func printError(err error) {
	result := ErrorResult{Error: err.Error()}
	switch outputFormat {
	case "json":
		enc := json.NewEncoder(os.Stderr)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
	case "yaml":
		out, marshalErr := yaml.Marshal(result)
		if marshalErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		fmt.Fprint(os.Stderr, string(out))
	default:
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
}

// ---------------------------------------------------------------------------
// Result Types
// ---------------------------------------------------------------------------

// MessageResult is used for simple status messages (create, update, delete).
type MessageResult struct {
	Message string `json:"message" yaml:"message"`
	ID      string `json:"id,omitempty" yaml:"id,omitempty"`
	URL     string `json:"url,omitempty" yaml:"url,omitempty"`
}

func (m MessageResult) HumanString() string {
	res := m.Message + "\n"
	if m.URL != "" {
		res += "URL: " + m.URL + "\n"
	}
	return res
}

// CipherResult holds a decrypted cipher for output.
type CipherResult struct {
	ID       string   `json:"id" yaml:"id"`
	Name     string   `json:"name" yaml:"name"`
	Type     string   `json:"type" yaml:"type"`
	Username string   `json:"username,omitempty" yaml:"username,omitempty"`
	Password string   `json:"password,omitempty" yaml:"password,omitempty"`
	URLs     []string `json:"urls,omitempty" yaml:"urls,omitempty"`
	Notes    string   `json:"notes,omitempty" yaml:"notes,omitempty"`
}

func (c CipherResult) TableHeader() string {
	return "ID\tTYPE\tNAME"
}

func (c CipherResult) TableRow() string {
	return fmt.Sprintf("%s\t%s\t%s", c.ID, c.Type, c.Name)
}

func (c CipherResult) HumanString() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "ID:   %s\n", c.ID)
	fmt.Fprintf(&sb, "Name: %s\n", c.Name)
	fmt.Fprintf(&sb, "Type: %s\n", c.Type)
	if c.Username != "" {
		fmt.Fprintf(&sb, "User: %s\n", c.Username)
	}
	if c.Password != "" {
		fmt.Fprintf(&sb, "Pass: %s\n", c.Password)
	}
	if len(c.URLs) > 0 {
		fmt.Fprintf(&sb, "URLs: %s\n", strings.Join(c.URLs, ", "))
	}
	if c.Notes != "" {
		fmt.Fprintf(&sb, "Notes: %s\n", c.Notes)
	}
	return sb.String()
}

// OrgResult holds a basic organization info for output.
type OrgResult struct {
	ID   string `json:"id" yaml:"id"`
	Name string `json:"name" yaml:"name"`
}

func (o OrgResult) TableHeader() string {
	return "ID\tNAME"
}

func (o OrgResult) TableRow() string {
	return fmt.Sprintf("%s\t%s", o.ID, o.Name)
}

// OrgMemberResult holds an organization member for output.
type OrgMemberResult struct {
	ID     string `json:"id" yaml:"id"`
	Email  string `json:"email" yaml:"email"`
	Status int    `json:"status" yaml:"status"`
	Type   int    `json:"type" yaml:"type"`
}

func (m OrgMemberResult) TableHeader() string {
	return "ID\tEMAIL\tSTATUS\tTYPE"
}

func (m OrgMemberResult) TableRow() string {
	return fmt.Sprintf("%s\t%s\t%d\t%d", m.ID, m.Email, m.Status, m.Type)
}

// CollectionResult holds a collection for output.
type CollectionResult struct {
	ID   string `json:"id" yaml:"id"`
	Name string `json:"name" yaml:"name"`
}

func (c CollectionResult) TableHeader() string {
	return "ID\tNAME"
}

func (c CollectionResult) TableRow() string {
	return fmt.Sprintf("%s\t%s", c.ID, c.Name)
}

// GroupResult holds a group for output.
type GroupResult struct {
	ID        string `json:"id" yaml:"id"`
	Name      string `json:"name" yaml:"name"`
	AccessAll bool   `json:"access_all" yaml:"access_all"`
}

func (g GroupResult) TableHeader() string {
	return "ID\tNAME\tACCESS ALL"
}

func (g GroupResult) TableRow() string {
	return fmt.Sprintf("%s\t%s\t%t", g.ID, g.Name, g.AccessAll)
}

// SendResult holds a send for output.
type SendResult struct {
	ID             string `json:"id" yaml:"id"`
	Name           string `json:"name" yaml:"name"`
	Type           string `json:"type,omitempty" yaml:"type,omitempty"`
	FileName       string `json:"file_name,omitempty" yaml:"file_name,omitempty"`
	URL            string `json:"url,omitempty" yaml:"url,omitempty"`
	Text           string `json:"text,omitempty" yaml:"text,omitempty"`
	AccessCount    int    `json:"access_count,omitempty" yaml:"access_count,omitempty"`
	MaxAccessCount *int   `json:"max_access_count,omitempty" yaml:"max_access_count,omitempty"`
}

func (s SendResult) TableHeader() string {
	return "ID\tNAME\tVIEWS"
}

func (s SendResult) TableRow() string {
	maxAC := 0
	if s.MaxAccessCount != nil {
		maxAC = *s.MaxAccessCount
	}
	return fmt.Sprintf("%s\t%s\t%d/%d", s.ID, s.Name, s.AccessCount, maxAC)
}

func (s SendResult) HumanString() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "ID:   %s\n", s.ID)
	if s.Name != "" {
		fmt.Fprintf(&sb, "Name: %s\n", s.Name)
	}
	if s.FileName != "" {
		fmt.Fprintf(&sb, "File: %s\n", s.FileName)
	}
	if s.URL != "" {
		fmt.Fprintf(&sb, "URL:  %s\n", s.URL)
	}
	if s.Text != "" {
		fmt.Fprintf(&sb, "Text: %s\n", s.Text)
	}
	return sb.String()
}

// EmergencyContactResult holds an emergency access contact for output.
type EmergencyContactResult struct {
	ID     string `json:"id" yaml:"id"`
	Email  string `json:"email" yaml:"email"`
	Status int    `json:"status" yaml:"status"`
	Type   int    `json:"type" yaml:"type"`
}

func (e EmergencyContactResult) TableHeader() string {
	return "ID\tEMAIL\tSTATUS\tTYPE"
}

func (e EmergencyContactResult) TableRow() string {
	return fmt.Sprintf("%s\t%s\t%d\t%d", e.ID, e.Email, e.Status, e.Type)
}

// APIKeyResult holds the API key output.
type APIKeyResult struct {
	ClientID     string `json:"client_id" yaml:"client_id"`
	ClientSecret string `json:"client_secret" yaml:"client_secret"`
}

func (a APIKeyResult) HumanString() string {
	return fmt.Sprintf("Client ID: %s\nClient Secret: %s\n", a.ClientID, a.ClientSecret)
}
