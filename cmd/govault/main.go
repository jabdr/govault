// Command govault is a CLI tool for interacting with Bitwarden/Vaultwarden.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jabdr/govault/pkg/api"
	"github.com/jabdr/govault/pkg/vault"
)

func main() {
	var (
		action             string
		server             string
		email              string
		password           string
		id                 string
		orgID              string
		collectionID       string
		name               string
		username           string
		loginPassword      string
		newPassword        string
		inviteEmail        string
		text               string
		accessType         int
		waitDays           int
		verbose            bool
		accessAll          bool
		insecureSkipVerify bool
		clientID           string
		clientSecret       string
		usersAccess        string
		groupsAccess       string
	)

	flag.StringVar(&action, "action", "", "Action: list, get, create, update, delete, change-password, "+
		"org-list, org-members, org-invite, org-confirm, "+
		"collections, collection-create, collection-update, collection-delete, "+
		"groups, group-create, group-update, group-delete, "+
		"sends, send-create, send-get, send-delete, "+
		"emergency-trusted, emergency-granted, emergency-invite, emergency-confirm, "+
		"emergency-initiate, emergency-approve, emergency-reject, emergency-view, emergency-takeover")
	flag.StringVar(&server, "server", "", "Vaultwarden/Bitwarden server URL (or set GOVAULT_SERVER)")
	flag.StringVar(&email, "email", "", "Account email (or set GOVAULT_EMAIL)")
	flag.StringVar(&password, "password", "", "Master password (or set GOVAULT_PASSWORD env)")
	flag.StringVar(&id, "id", "", "Cipher/member/send/emergency-access ID")
	flag.StringVar(&orgID, "org-id", "", "Organization ID")
	flag.StringVar(&collectionID, "collection-id", "", "Collection ID")
	flag.StringVar(&name, "name", "", "Name for cipher/org/collection/send")
	flag.StringVar(&username, "username", "", "Login username")
	flag.StringVar(&loginPassword, "login-password", "", "Login password value")
	flag.StringVar(&newPassword, "new-password", "", "New master password")
	flag.StringVar(&inviteEmail, "invite-email", "", "Email(s) to invite (comma-separated)")
	flag.StringVar(&text, "text", "", "Text content for send")
	flag.IntVar(&accessType, "access-type", 0, "Emergency access type: 0=view, 1=takeover")
	flag.IntVar(&waitDays, "wait-days", 7, "Emergency access wait time in days")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&accessAll, "access-all", false, "Group access all collections")
	flag.BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS verify")
	flag.StringVar(&clientID, "client-id", "", "API Client ID (or set GOVAULT_CLIENT_ID)")
	flag.StringVar(&clientSecret, "client-secret", "", "API Client Secret (or set GOVAULT_CLIENT_SECRET)")
	flag.StringVar(&usersAccess, "users-access", "", "JSON array of user access for collection")
	flag.StringVar(&groupsAccess, "groups-access", "", "JSON array of group access for collection")
	flag.Parse()

	if action == "" {
		flag.Usage()
		os.Exit(1)
	}

	if server == "" {
		server = os.Getenv("GOVAULT_SERVER")
	}
	if email == "" {
		email = os.Getenv("GOVAULT_EMAIL")
	}
	if password == "" {
		password = os.Getenv("GOVAULT_PASSWORD")
	}
	if clientID == "" {
		clientID = os.Getenv("GOVAULT_CLIENT_ID")
	}
	if clientSecret == "" {
		clientSecret = os.Getenv("GOVAULT_CLIENT_SECRET")
	}

	logLevel := slog.LevelInfo
	if verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	if server == "" || email == "" || password == "" {
		fmt.Fprintln(os.Stderr, "Error: -server, -email, and -password (or GOVAULT_PASSWORD) are required")
		os.Exit(1)
	}

	var v *vault.Vault
	var err error
	if clientID != "" && clientSecret != "" {
		v, err = vault.LoginAPIKey(server, clientID, clientSecret, email, password, insecureSkipVerify, logger)
	} else {
		v, err = vault.Login(server, email, password, insecureSkipVerify, logger)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
		os.Exit(1)
	}

	switch action {
	case "list":
		actionList(v)
	case "get":
		actionGet(v, id)
	case "create":
		actionCreate(v, name, username, loginPassword)
	case "update":
		actionUpdate(v, id, name, username, loginPassword)
	case "delete":
		actionDelete(v, id)
	case "change-password":
		actionChangePassword(v, password, newPassword)
	case "org-list":
		actionOrgList(v)
	case "org-members":
		actionOrgMembers(v, orgID)
	case "org-invite":
		actionOrgInvite(v, orgID, inviteEmail)
	case "org-confirm":
		actionOrgConfirm(v, orgID, id)
	case "collections":
		actionCollections(v, orgID)
	case "collection-create":
		actionCollectionCreate(v, orgID, name)
	case "collection-update":
		actionCollectionUpdate(v, orgID, collectionID, usersAccess, groupsAccess)
	case "collection-delete":
		actionCollectionDelete(v, orgID, collectionID)
	case "groups":
		actionGroups(v, orgID)
	case "group-create":
		actionGroupCreate(v, orgID, name, accessAll)
	case "group-update":
		actionGroupUpdate(v, orgID, id, name, accessAll)
	case "group-delete":
		actionGroupDelete(v, orgID, id)
	case "sends":
		actionSends(v)
	case "send-create":
		actionSendCreate(v, name, text)
	case "send-get":
		actionSendGet(v, id)
	case "send-delete":
		actionSendDelete(v, id)
	case "emergency-trusted":
		actionEmergencyTrusted(v)
	case "emergency-granted":
		actionEmergencyGranted(v)
	case "emergency-invite":
		actionEmergencyInvite(v, inviteEmail, accessType, waitDays)
	case "emergency-confirm":
		actionEmergencyConfirm(v, id)
	case "emergency-initiate":
		actionEmergencyInitiate(v, id)
	case "emergency-approve":
		actionEmergencyApprove(v, id)
	case "emergency-reject":
		actionEmergencyReject(v, id)
	case "emergency-view":
		actionEmergencyView(v, id)
	case "emergency-takeover":
		actionEmergencyTakeover(v, id, newPassword)
	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s\n", action)
		os.Exit(1)
	}
}

func actionList(v *vault.Vault) {
	ciphers, err := v.ListCiphers()
	exitOnErr(err)
	for _, c := range ciphers {
		fmt.Printf("%-36s  %-8s  %s\n", c.ID(), cipherTypeName(c.Type()), c.Name())
	}
}

func actionGet(v *vault.Vault, id string) {
	requireFlag(id, "-id")
	c, err := v.GetCipher(id)
	exitOnErr(err)
	fmt.Printf("ID:   %s\n", c.ID())
	fmt.Printf("Name: %s\n", c.Name())
	fmt.Printf("Type: %s\n", cipherTypeName(c.Type()))
	if c.Type() == vault.CipherTypeLogin {
		u, p, _ := c.GetLogin()
		fmt.Printf("User: %s\n", u)
		fmt.Printf("Pass: %s\n", p)
	}
	if notes := c.Notes(); notes != "" {
		fmt.Printf("Notes: %s\n", notes)
	}
}

func actionCreate(v *vault.Vault, name, username, password string) {
	requireFlag(name, "-name")
	c := vault.NewCipher(vault.CipherTypeLogin, name)
	if username != "" || password != "" {
		c.SetLogin(username, password)
	}
	exitOnErr(v.CreateCipher(c))
	fmt.Printf("Created: %s\n", c.ID())
}

func actionUpdate(v *vault.Vault, id, name, username, password string) {
	requireFlag(id, "-id")
	c, err := v.GetCipher(id)
	exitOnErr(err)
	if name != "" {
		c.SetField("name", name)
	}
	if username != "" || password != "" {
		c.SetLogin(username, password)
	}
	exitOnErr(v.UpdateCipher(c))
	fmt.Println("Updated")
}

func actionDelete(v *vault.Vault, id string) {
	requireFlag(id, "-id")
	exitOnErr(v.DeleteCipher(id))
	fmt.Println("Deleted")
}

func actionChangePassword(v *vault.Vault, currentPassword, newPassword string) {
	requireFlag(newPassword, "-new-password")
	exitOnErr(v.ChangePassword(currentPassword, newPassword))
	fmt.Println("Password changed")
}

func actionOrgList(v *vault.Vault) {
	orgs, err := v.ListOrganizations()
	exitOnErr(err)
	for _, o := range orgs {
		fmt.Printf("%-36s  %s\n", o.ID, o.Name)
	}
}

func actionOrgMembers(v *vault.Vault, orgID string) {
	requireFlag(orgID, "-org-id")
	members, err := v.ListOrgMembers(orgID)
	exitOnErr(err)
	for _, m := range members {
		fmt.Printf("%-36s  %-30s  type=%d  status=%d\n", m.ID, m.Email, m.Type, m.Status)
	}
}

func actionOrgInvite(v *vault.Vault, orgID, emails string) {
	requireFlag(orgID, "-org-id")
	requireFlag(emails, "-invite-email")
	emailList := strings.Split(emails, ",")
	exitOnErr(v.InviteToOrganization(orgID, emailList, 2)) // type 2 = User
	fmt.Printf("Invited: %s\n", emails)
}

func actionOrgConfirm(v *vault.Vault, orgID, memberID string) {
	requireFlag(orgID, "-org-id")
	requireFlag(memberID, "-id")
	exitOnErr(v.ConfirmMember(orgID, memberID))
	fmt.Println("Confirmed")
}

func actionCollections(v *vault.Vault, orgID string) {
	requireFlag(orgID, "-org-id")
	cols, err := v.ListCollections(orgID)
	exitOnErr(err)
	for _, c := range cols {
		fmt.Printf("%-36s  %s\n", c.ID, c.Name)
	}
}

func actionCollectionCreate(v *vault.Vault, orgID, name string) {
	requireFlag(orgID, "-org-id")
	requireFlag(name, "-name")
	col, err := v.CreateCollection(orgID, name)
	exitOnErr(err)
	fmt.Printf("Created: %s\n", col.ID)
}

func actionCollectionUpdate(v *vault.Vault, orgID, collectionIDOrName, reqUsers, reqGroups string) {
	requireFlag(orgID, "-org-id")
	requireFlag(collectionIDOrName, "-collection-id or Name")

	cols, err := v.ListCollections(orgID)
	exitOnErr(err)

	collectionID := collectionIDOrName
	for _, c := range cols {
		if c.Name == collectionIDOrName {
			collectionID = c.ID
			break
		}
	}

	var parsedUsers []map[string]interface{}
	var parsedGroups []map[string]interface{}

	if reqUsers != "" {
		if err := json.Unmarshal([]byte(reqUsers), &parsedUsers); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing --users-access JSON: %v\n", err)
			os.Exit(1)
		}
	}
	if reqGroups != "" {
		if err := json.Unmarshal([]byte(reqGroups), &parsedGroups); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing --groups-access JSON: %v\n", err)
			os.Exit(1)
		}
	}

	members, err := v.ListOrgMembers(orgID)
	exitOnErr(err)
	memberMap := make(map[string]string) // email -> id
	for _, m := range members {
		memberMap[m.Email] = m.ID
	}

	groups, _ := v.ListGroups(orgID)    // Might fail if groups not supported, ignore err
	groupMap := make(map[string]string) // name -> id
	for _, g := range groups {
		groupMap[g.Name] = g.ID
	}

	var users []api.CollectionUserAccess
	var groupsAccess []api.CollectionGroupAccess

	for _, pu := range parsedUsers {
		id := pu["id"].(string)
		if email, ok := pu["email"].(string); ok && email != "" {
			if matchedID, found := memberMap[email]; found {
				id = matchedID
			}
		} else if emailOrID, ok := pu["id"].(string); ok {
			if matchedID, found := memberMap[emailOrID]; found {
				id = matchedID
			}
		}

		ro, _ := pu["readOnly"].(bool)
		hp, _ := pu["hidePasswords"].(bool)
		mng, _ := pu["manage"].(bool)
		users = append(users, api.CollectionUserAccess{
			ID:            id,
			ReadOnly:      ro,
			HidePasswords: hp,
			Manage:        mng,
		})
	}

	for _, pg := range parsedGroups {
		id := pg["id"].(string)
		if name, ok := pg["name"].(string); ok && name != "" {
			if matchedID, found := groupMap[name]; found {
				id = matchedID
			}
		} else if nameOrID, ok := pg["id"].(string); ok {
			if matchedID, found := groupMap[nameOrID]; found {
				id = matchedID
			}
		}

		ro, _ := pg["readOnly"].(bool)
		hp, _ := pg["hidePasswords"].(bool)
		mng, _ := pg["manage"].(bool)
		groupsAccess = append(groupsAccess, api.CollectionGroupAccess{
			ID:            id,
			ReadOnly:      ro,
			HidePasswords: hp,
			Manage:        mng,
		})
	}

	err = v.UpdateCollectionPermissions(orgID, collectionID, groupsAccess, users)
	exitOnErr(err)
	fmt.Printf("Collection permissions updated for %s\n", collectionID)
}

func actionGroups(v *vault.Vault, orgID string) {
	requireFlag(orgID, "-org-id")

	groups, err := v.ListGroups(orgID)
	exitOnErr(err)

	if len(groups) == 0 {
		fmt.Println("No groups found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tACCESS ALL")
	for _, g := range groups {
		fmt.Fprintf(w, "%s\t%s\t%t\n", g.ID, g.Name, g.AccessAll)
	}
	w.Flush()
}

func actionGroupCreate(v *vault.Vault, orgID, name string, accessAll bool) {
	requireFlag(orgID, "-org-id")
	requireFlag(name, "-name")

	grp, err := v.CreateGroup(orgID, name, accessAll)
	exitOnErr(err)
	fmt.Printf("Created Group: %s (ID: %s)\n", grp.Name, grp.ID)
}

func actionGroupUpdate(v *vault.Vault, orgID, idOrName, name string, accessAll bool) {
	requireFlag(orgID, "-org-id")
	requireFlag(idOrName, "-id or Name")
	requireFlag(name, "-name")

	groups, err := v.ListGroups(orgID)
	exitOnErr(err)

	groupID := idOrName
	for _, g := range groups {
		if g.Name == idOrName {
			groupID = g.ID
			break
		}
	}

	err = v.UpdateGroup(orgID, groupID, name, accessAll)
	exitOnErr(err)
	fmt.Printf("Updated Group: %s\n", groupID)
}

func actionGroupDelete(v *vault.Vault, orgID, idOrName string) {
	requireFlag(orgID, "-org-id")
	requireFlag(idOrName, "-id or Name")

	groups, err := v.ListGroups(orgID)
	exitOnErr(err)

	groupID := idOrName
	for _, g := range groups {
		if g.Name == idOrName {
			groupID = g.ID
			break
		}
	}

	err = v.DeleteGroup(orgID, groupID)
	exitOnErr(err)
	fmt.Printf("Deleted Group: %s\n", groupID)
}

func actionCollectionDelete(v *vault.Vault, orgID, collectionID string) {
	requireFlag(orgID, "-org-id")
	requireFlag(collectionID, "-collection-id")
	exitOnErr(v.DeleteCollection(orgID, collectionID))
	fmt.Println("Deleted")
}

func actionSends(v *vault.Vault) {
	sends, err := v.ListSends()
	exitOnErr(err)
	for _, s := range sends {
		typeName := "text"
		if s.Type == vault.SendTypeFile {
			typeName = "file"
		}
		fmt.Printf("%-36s  %-4s  %s\n", s.ID, typeName, s.Name)
	}
}

func actionSendCreate(v *vault.Vault, name, text string) {
	requireFlag(name, "-name")
	requireFlag(text, "-text")
	send, accessURL, err := v.CreateTextSend(name, text, vault.SendOptions{
		DeletionDate: time.Now().Add(7 * 24 * time.Hour),
	})
	exitOnErr(err)
	fmt.Printf("Created: %s\n", send.ID)
	fmt.Printf("Access URL: %s\n", accessURL)
}

func actionSendGet(v *vault.Vault, id string) {
	requireFlag(id, "-id")
	sends, err := v.ListSends()
	exitOnErr(err)
	for _, s := range sends {
		if s.ID == id {
			data, _ := json.MarshalIndent(s, "", "  ")
			fmt.Println(string(data))
			return
		}
	}
	fmt.Fprintf(os.Stderr, "Send not found: %s\n", id)
	os.Exit(1)
}

func actionSendDelete(v *vault.Vault, id string) {
	requireFlag(id, "-id")
	exitOnErr(v.DeleteSend(id))
	fmt.Println("Deleted")
}

func actionEmergencyTrusted(v *vault.Vault) {
	list, err := v.ListTrustedEmergencyAccess()
	exitOnErr(err)
	for _, ea := range list {
		fmt.Printf("%-36s  %-30s  type=%d  status=%d  wait=%dd\n",
			ea.ID, ea.Email, ea.Type, ea.Status, ea.WaitTimeDays)
	}
}

func actionEmergencyGranted(v *vault.Vault) {
	list, err := v.ListGrantedEmergencyAccess()
	exitOnErr(err)
	for _, ea := range list {
		fmt.Printf("%-36s  %-30s  type=%d  status=%d  wait=%dd\n",
			ea.ID, ea.Name, ea.Type, ea.Status, ea.WaitTimeDays)
	}
}

func actionEmergencyInvite(v *vault.Vault, email string, accessType, waitDays int) {
	requireFlag(email, "-invite-email")
	exitOnErr(v.InviteEmergencyAccess(email, accessType, waitDays))
	fmt.Printf("Invited: %s\n", email)
}

func actionEmergencyConfirm(v *vault.Vault, id string) {
	requireFlag(id, "-id")
	exitOnErr(v.ConfirmEmergencyAccess(id))
	fmt.Println("Confirmed")
}

func actionEmergencyInitiate(v *vault.Vault, id string) {
	requireFlag(id, "-id")
	exitOnErr(v.InitiateEmergencyAccess(id))
	fmt.Println("Emergency access initiated")
}

func actionEmergencyApprove(v *vault.Vault, id string) {
	requireFlag(id, "-id")
	exitOnErr(v.ApproveEmergencyAccess(id))
	fmt.Println("Approved")
}

func actionEmergencyReject(v *vault.Vault, id string) {
	requireFlag(id, "-id")
	exitOnErr(v.RejectEmergencyAccess(id))
	fmt.Println("Rejected")
}

func actionEmergencyView(v *vault.Vault, id string) {
	requireFlag(id, "-id")
	ciphers, err := v.ViewEmergencyVault(id)
	exitOnErr(err)
	for _, c := range ciphers {
		fmt.Printf("%-36s  %-8s  %s\n", c.ID(), cipherTypeName(c.Type()), c.Name())
	}
}

func actionEmergencyTakeover(v *vault.Vault, id, newPassword string) {
	requireFlag(id, "-id")
	requireFlag(newPassword, "-new-password")
	exitOnErr(v.TakeoverEmergencyAccess(id, newPassword))
	fmt.Println("Takeover complete — new password set")
}

func cipherTypeName(t int) string {
	switch t {
	case vault.CipherTypeLogin:
		return "login"
	case vault.CipherTypeSecureNote:
		return "note"
	case vault.CipherTypeCard:
		return "card"
	case vault.CipherTypeIdentity:
		return "identity"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}

func requireFlag(val, name string) {
	if val == "" {
		fmt.Fprintf(os.Stderr, "Error: %s is required for this action\n", name)
		os.Exit(1)
	}
}

func exitOnErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
